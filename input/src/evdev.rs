//! Per-device event queue with ring-buffer semantics — the NARF analogue of
//! Linux's evdev character-device layer.
//!
//! # Architecture
//!
//! ```text
//! Driver IRQ handler
//!        │  calls dispatch(DeviceId, EvdevEvent)
//!        ▼
//!   Router (global)
//!        │  fan-out to every Reader attached to that DeviceId
//!        ▼
//!   DeviceNode::ring (per-device, 256-event bounded ring)
//!        │  Reader::poll_event() / wait_event_async()
//!        ▼
//!   Session manager / test harness
//! ```
//!
//! Linux refs:
//!   * `drivers/input/evdev.c` — per-client ring + SYN_DROPPED on overflow.
//!   * `include/uapi/linux/input.h` — `struct input_event` layout.
//!   * `include/uapi/linux/input-event-codes.h` — EV_* / SYN_* constants.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

// ── Wire-format event type ────────────────────────────────────────────────────

/// Linux evdev event type codes.
/// Ref: `include/uapi/linux/input-event-codes.h` lines 39-58.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EventType {
    /// Synchronisation marker (`EV_SYN = 0x00`).
    Syn = 0x00,
    /// Key / button state change (`EV_KEY = 0x01`).
    Key = 0x01,
    /// Relative axis change (`EV_REL = 0x02`).
    Rel = 0x02,
    /// Absolute axis value (`EV_ABS = 0x03`).
    Abs = 0x03,
    /// Miscellaneous event (`EV_MSC = 0x04`).
    Msc = 0x04,
    /// LED state change (`EV_LED = 0x11`).
    Led = 0x11,
    /// Force feedback upload (`EV_FF = 0x15`).
    Ff = 0x15,
}

impl EventType {
    /// Decode a raw u16 event type (from wire or uinput injection).
    /// Returns `None` for unrecognised codes rather than panicking.
    pub const fn from_raw(v: u16) -> Option<Self> {
        Some(match v {
            0x00 => EventType::Syn,
            0x01 => EventType::Key,
            0x02 => EventType::Rel,
            0x03 => EventType::Abs,
            0x04 => EventType::Msc,
            0x11 => EventType::Led,
            0x15 => EventType::Ff,
            _ => return None,
        })
    }
}

/// `EV_SYN` sub-codes.
/// Ref: `include/uapi/linux/input-event-codes.h` lines 58-61.
pub mod syn {
    /// Normal end-of-report marker (`SYN_REPORT = 0`).
    pub const SYN_REPORT: u16 = 0;
    /// Ring overflow — oldest events were lost (`SYN_DROPPED = 3`).
    pub const SYN_DROPPED: u16 = 3;
}

/// `EV_REL` axis codes.
/// Ref: `include/uapi/linux/input-event-codes.h`.
pub mod rel {
    pub const REL_X: u16 = 0x00;
    pub const REL_Y: u16 = 0x01;
    pub const REL_Z: u16 = 0x02;
    pub const REL_RX: u16 = 0x03;
    pub const REL_RY: u16 = 0x04;
    pub const REL_RZ: u16 = 0x05;
    pub const REL_HWHEEL: u16 = 0x06;
    pub const REL_DIAL: u16 = 0x07;
    pub const REL_WHEEL: u16 = 0x08;
    pub const REL_MISC: u16 = 0x09;
}

/// `EV_KEY` button codes for mouse buttons.
/// Ref: `include/uapi/linux/input-event-codes.h`.
pub mod key {
    pub const BTN_LEFT: u16 = 0x110;
    pub const BTN_RIGHT: u16 = 0x111;
    pub const BTN_MIDDLE: u16 = 0x112;
    pub const BTN_SIDE: u16 = 0x113;
    pub const BTN_EXTRA: u16 = 0x114;
    pub const BTN_FORWARD: u16 = 0x115;
    pub const BTN_BACK: u16 = 0x116;
    pub const BTN_TASK: u16 = 0x117;

    /// KEY_A = 30 (matches Linux `include/uapi/linux/input-event-codes.h`).
    pub const KEY_A: u16 = 30;
    pub const KEY_B: u16 = 48;
    pub const KEY_C: u16 = 46;
}

/// Single evdev wire-format event.
///
/// Layout matches Linux `struct input_event` semantics on a 64-bit kernel
/// (`time` as two u64 = sec/usec, then type/code/value packed identically).
/// The `time` field here is a TSC-based `KernelInstant` so NARF doesn't
/// need a wall-clock reference at the driver level.
///
/// Ref: `include/uapi/linux/input.h` `struct input_event`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct EvdevEvent {
    /// Kernel-monotonic timestamp (TSC cycles). Maps to `time` in Linux
    /// `struct input_event`.
    pub time: u64,
    /// Event type — one of the `EventType` discriminants.
    pub type_: EventType,
    /// Per-type code (key scancode, axis id, …).
    pub code: u16,
    /// Signed value. Key: 0=release, 1=press, 2=repeat.
    /// Rel: signed delta. Abs: absolute position. Syn: 0.
    pub value: i32,
}

impl EvdevEvent {
    /// Construct an `EV_SYN SYN_REPORT` end-of-frame marker.
    pub fn syn_report(now: u64) -> Self {
        Self {
            time: now,
            type_: EventType::Syn,
            code: syn::SYN_REPORT,
            value: 0,
        }
    }

    /// Construct an `EV_SYN SYN_DROPPED` overflow marker.
    pub fn syn_dropped(now: u64) -> Self {
        Self {
            time: now,
            type_: EventType::Syn,
            code: syn::SYN_DROPPED,
            value: 0,
        }
    }
}

// Verify the in-memory size is what the ABI expects.
// 8 (time) + 2 (type) + 2 (code) + 4 (value) = 16 bytes.
const _SIZE_CHECK: [u8; 16] = [0u8; core::mem::size_of::<EvdevEvent>()];

// ── Capability bitmap ─────────────────────────────────────────────────────────

/// Maximum evdev code value we track in the capability bitmap.
/// Linux uses 0x1FF (KEY_MAX = 767) but we cover the common range.
/// Matches `KEY_MAX` for keys; independent per type.
const CAP_BITS: usize = 768;

/// Fixed-size bit array covering codes 0..CAP_BITS.
#[derive(Clone, Debug, Default)]
pub struct CapBitmap {
    words: [u64; (CAP_BITS + 63) / 64],
}

impl CapBitmap {
    pub const fn new() -> Self {
        Self {
            words: [0u64; (CAP_BITS + 63) / 64],
        }
    }

    pub fn set(&mut self, code: u16) {
        let c = code as usize;
        if c < CAP_BITS {
            self.words[c / 64] |= 1u64 << (c % 64);
        }
    }

    pub fn get(&self, code: u16) -> bool {
        let c = code as usize;
        if c < CAP_BITS {
            self.words[c / 64] & (1u64 << (c % 64)) != 0
        } else {
            false
        }
    }
}

/// Per-type capability bitmaps for a device.
/// Mirrors `input_dev->keybit`, `->relbit`, `->absbit` in Linux
/// `include/linux/input.h`.
#[derive(Clone, Debug, Default)]
pub struct DeviceCaps {
    /// Supported `EV_KEY` codes.
    pub keybit: CapBitmap,
    /// Supported `EV_REL` axis codes.
    pub relbit: CapBitmap,
    /// Supported `EV_ABS` axis codes.
    pub absbit: CapBitmap,
    /// Bitmask of supported event types (bit = `EventType as u16`).
    pub evbit: u32,
}

impl DeviceCaps {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare support for `EV_KEY` code `c`.
    pub fn add_key(&mut self, c: u16) {
        self.keybit.set(c);
        self.evbit |= 1 << (EventType::Key as u16);
    }

    /// Declare support for `EV_REL` axis `c`.
    pub fn add_rel(&mut self, c: u16) {
        self.relbit.set(c);
        self.evbit |= 1 << (EventType::Rel as u16);
    }

    /// Declare support for `EV_ABS` axis `c`.
    pub fn add_abs(&mut self, c: u16) {
        self.absbit.set(c);
        self.evbit |= 1 << (EventType::Abs as u16);
    }

    /// Return `true` if `(type_, code)` is in the capability set.
    pub fn has(&self, type_: EventType, code: u16) -> bool {
        match type_ {
            EventType::Key => self.keybit.get(code),
            EventType::Rel => self.relbit.get(code),
            EventType::Abs => self.absbit.get(code),
            EventType::Syn => true, // every device supports EV_SYN
            _ => false,
        }
    }
}

// ── DeviceId + DeviceNode ─────────────────────────────────────────────────────

/// Opaque handle that identifies a registered input device.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceId(pub u32);

/// Ring capacity per device node (evdev default `EVDEV_BUF_PACKETS * 64`
/// is typically 512; we use 256 to match the existing per-class rings).
const RING_CAP: usize = 256;

/// Internal mutable state of a device node's reader set + ring.
struct DeviceNodeInner {
    ring: alloc::collections::VecDeque<EvdevEvent>,
    /// One waker slot per reader. The waker is filled when the reader
    /// polls and the ring is empty; cleared once an event arrives.
    wakers: Vec<Option<Waker>>,
}

impl DeviceNodeInner {
    fn new() -> Self {
        Self {
            ring: alloc::collections::VecDeque::with_capacity(RING_CAP),
            wakers: Vec::new(),
        }
    }

    /// Push one event, dropping the oldest and synthesising SYN_DROPPED
    /// on overflow. Ref: `evdev.c` `evdev_pass_values` overflow path.
    fn push(&mut self, ev: EvdevEvent) {
        if self.ring.len() >= RING_CAP {
            // Drop oldest event.
            self.ring.pop_front();
            // Synthesise SYN_DROPPED per Linux evdev.c:152.
            let dropped = EvdevEvent::syn_dropped(ev.time);
            // If ring is still full after the pop, drop one more.
            if self.ring.len() >= RING_CAP {
                self.ring.pop_front();
            }
            self.ring.push_back(dropped);
        }
        self.ring.push_back(ev);
    }

    /// Wake all parked reader wakers.
    fn wake_readers(&mut self) {
        for slot in self.wakers.iter_mut() {
            if let Some(w) = slot.take() {
                // IRQ-safe: use deferred wake so we don't drop Arc
                // in IRQ context. Ref: `narf_lib::deferred_wake`.
                narf_lib::deferred_wake::push_pending(core::iter::once(Some(w)));
            }
        }
    }
}

/// A registered input device node. Shared between the Router (writer)
/// and every Reader (readers).
///
/// Analogous to Linux `struct evdev` (`evdev.c:27`).
pub struct DeviceNode {
    pub id: DeviceId,
    pub caps: DeviceCaps,
    alive: AtomicBool,
    inner: IrqSafeSpinLock<DeviceNodeInner>,
    /// Count of push calls (diagnostic).
    pub push_count: AtomicU32,
    /// Count of dropped events (diagnostic).
    pub drop_count: AtomicU32,
}

impl core::fmt::Debug for DeviceNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceNode")
            .field("id", &self.id)
            .field("alive", &self.alive.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl DeviceNode {
    fn new(id: DeviceId, caps: DeviceCaps) -> Self {
        Self {
            id,
            caps,
            alive: AtomicBool::new(true),
            inner: IrqSafeSpinLock::new(DeviceNodeInner::new()),
            push_count: AtomicU32::new(0),
            drop_count: AtomicU32::new(0),
        }
    }

    /// Dispatch one evdev event to the node's ring and wake all readers.
    /// Called by drivers from IRQ context.
    ///
    /// Returns `false` if the device has been removed (so the caller can
    /// stop dispatching).
    pub fn dispatch(&self, ev: EvdevEvent) -> bool {
        if !self.alive.load(Ordering::Acquire) {
            return false;
        }
        let mut g = self.inner.lock();
        let before = g.ring.len();
        g.push(ev);
        let after = g.ring.len();
        // Detect if we synthesised a SYN_DROPPED (ring len grew by 2 or 1
        // with a SYN_DROPPED at front, i.e. we dropped something).
        if after <= before {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
        }
        self.push_count.fetch_add(1, Ordering::Relaxed);
        g.wake_readers();
        true
    }

    /// Mark the device as removed. Future dispatches become no-ops;
    /// existing readers see a synthesised `SYN_DROPPED` to signal the
    /// stream ended. Mirrors Linux `evdev_cleanup` / `input_unregister_device`.
    pub fn remove(&self) {
        self.alive.store(false, Ordering::Release);
        let now = narf_time::now_cycles();
        let mut g = self.inner.lock();
        g.push(EvdevEvent::syn_dropped(now));
        g.wake_readers();
    }

    /// `true` while the device is registered.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Allocate a waker slot for a new Reader and return its index.
    fn alloc_waker_slot(&self) -> usize {
        let mut g = self.inner.lock();
        let idx = g.wakers.len();
        g.wakers.push(None);
        idx
    }

    /// Pop the oldest event for reader at waker slot `slot_idx`, or
    /// return `Poll::Pending` + register `cx.waker()`.
    fn poll_for_reader(
        &self,
        slot_idx: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Option<EvdevEvent>> {
        let mut g = self.inner.lock();
        if let Some(ev) = g.ring.pop_front() {
            return Poll::Ready(Some(ev));
        }
        // Ring empty — register waker for this slot.
        if slot_idx < g.wakers.len() {
            g.wakers[slot_idx] = Some(cx.waker().clone());
        }
        // If device is gone and ring is empty, signal end-of-stream.
        if !self.alive.load(Ordering::Acquire) {
            return Poll::Ready(None);
        }
        Poll::Pending
    }
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// An evdev reader handle attached to one `DeviceNode`.
///
/// Multiple readers can be attached to the same device; each sees a
/// fan-out of all dispatched events (many-to-one delivery, same ring
/// shared — for simplicity we share a single per-device ring and each
/// reader drains from it; full fan-out with per-reader rings is left
/// as a TODO for when session isolation is needed).
///
/// Analogous to Linux `struct evdev_client` (`evdev.c:36`).
pub struct Reader {
    node: Arc<DeviceNode>,
    waker_slot: usize,
}

impl core::fmt::Debug for Reader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reader")
            .field("device", &self.node.id)
            .field("waker_slot", &self.waker_slot)
            .finish()
    }
}

impl Reader {
    fn new(node: Arc<DeviceNode>) -> Self {
        let waker_slot = node.alloc_waker_slot();
        Self { node, waker_slot }
    }

    /// Non-blocking poll: returns the oldest event or `None` if the ring
    /// is empty. Returns `None` permanently once the device is removed
    /// and the ring is drained.
    pub fn poll_event(&self) -> Option<EvdevEvent> {
        let mut g = self.node.inner.lock();
        g.ring.pop_front()
    }

    /// Non-destructive check: `true` iff the ring has at least one
    /// event pending. Used by `poll_readiness()` to avoid draining the
    /// ring as a side-effect of checking.
    pub fn has_pending(&self) -> bool {
        !self.node.inner.lock().ring.is_empty()
    }

    /// Is the underlying device still alive?
    pub fn is_valid(&self) -> bool {
        self.node.is_alive()
    }

    /// Async blocking wait. Returns the next event as soon as one
    /// arrives, or `None` if the device was removed.
    ///
    /// Ref: Linux `evdev_read` wait_event_interruptible (`evdev.c:441`).
    pub fn wait_event_async(&self) -> WaitEventFuture<'_> {
        WaitEventFuture { reader: self }
    }
}

/// Future that resolves to the next `EvdevEvent` from a `Reader`.
pub struct WaitEventFuture<'a> {
    reader: &'a Reader,
}

impl core::fmt::Debug for WaitEventFuture<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WaitEventFuture").finish_non_exhaustive()
    }
}

impl core::future::Future for WaitEventFuture<'_> {
    type Output = Option<EvdevEvent>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.reader
            .node
            .poll_for_reader(self.reader.waker_slot, cx)
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Event router — owns the table of registered devices.
///
/// Analogous to Linux `input_dev` list in `input.c` + the `input_handle`
/// list per device (`input.c:input_register_handler`).
pub struct Router {
    inner: IrqSafeSpinLock<RouterInner>,
}

struct RouterInner {
    devices: Vec<Arc<DeviceNode>>,
    next_id: u32,
}

impl Router {
    pub const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(RouterInner {
                devices: Vec::new(),
                next_id: 1,
            }),
        }
    }

    /// Register a new input device with the given capability set.
    /// Returns a `(DeviceId, Arc<DeviceNode>)` pair; the caller
    /// (driver) retains the `Arc` and calls `node.dispatch()` from
    /// its IRQ handler.
    pub fn register_device(&self, caps: DeviceCaps) -> (DeviceId, Arc<DeviceNode>) {
        let mut g = self.inner.lock();
        let id = DeviceId(g.next_id);
        g.next_id += 1;
        let node = Arc::new(DeviceNode::new(id, caps));
        g.devices.push(Arc::clone(&node));
        (id, node)
    }

    /// Remove a device by id. Calls `DeviceNode::remove` (synthesises
    /// SYN_DROPPED + wakes readers) and drops the router's reference.
    pub fn unregister_device(&self, id: DeviceId) {
        let mut g = self.inner.lock();
        if let Some(pos) = g.devices.iter().position(|n| n.id == id) {
            let node = g.devices.remove(pos);
            node.remove();
        }
    }

    /// Open a `Reader` on an existing device. Returns `None` if the
    /// device id is not found or is already dead.
    pub fn open_reader(&self, id: DeviceId) -> Option<Reader> {
        let g = self.inner.lock();
        g.devices
            .iter()
            .find(|n| n.id == id && n.is_alive())
            .map(|n| Reader::new(Arc::clone(n)))
    }

    /// Dispatch one event to the node identified by `id`. Silently
    /// ignores unknown ids (device may have been unregistered).
    pub fn dispatch(&self, id: DeviceId, ev: EvdevEvent) {
        let g = self.inner.lock();
        if let Some(node) = g.devices.iter().find(|n| n.id == id) {
            // Release lock before dispatch (dispatch may internally
            // take the node's inner lock).
            let node = Arc::clone(node);
            drop(g);
            node.dispatch(ev);
        }
    }

    /// Return the number of registered (live) devices.
    pub fn device_count(&self) -> usize {
        self.inner.lock().devices.len()
    }

    /// Snapshot the list of currently-registered live device ids.
    /// The returned vec is a point-in-time view; devices may be added
    /// or removed after this call returns. Used by `DevInputDir` to
    /// enumerate `/dev/input/event*` entries.
    pub fn device_ids(&self) -> Vec<DeviceId> {
        self.inner
            .lock()
            .devices
            .iter()
            .filter(|n| n.is_alive())
            .map(|n| n.id)
            .collect()
    }
}

impl core::fmt::Debug for Router {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Router").finish_non_exhaustive()
    }
}

// ── Global router ─────────────────────────────────────────────────────────────

/// Global input event router. Drivers call `ROUTER.dispatch()`;
/// consumers call `ROUTER.open_reader()`.
pub static ROUTER: Router = Router::new();

// ── Re-export abs constants from the existing narf-input namespace ────────────

/// `EV_ABS` axis codes — re-export from the existing `narf_input::abs` module
/// so callers of this module have a single import path.
pub mod abs {
    pub use crate::abs::*;
}

// ── Driver dispatch helpers ───────────────────────────────────────────────────

/// Convenience helper for keyboard drivers: dispatch an `EV_KEY` press or
/// release to the given `DeviceNode`. A `EV_SYN SYN_REPORT` frame end is
/// appended automatically.
///
/// Used by `drivers/input/src/i8042.rs` and test smokes.
pub fn dispatch_key_to_node(node: &DeviceNode, code: u16, pressed: bool) {
    let now = narf_time::now_cycles();
    node.dispatch(EvdevEvent {
        time: now,
        type_: EventType::Key,
        code,
        value: if pressed { 1 } else { 0 },
    });
    node.dispatch(EvdevEvent::syn_report(now));
}

/// Convenience helper for mouse drivers: dispatch `EV_REL REL_X` / `REL_Y`
/// deltas to the given `DeviceNode`, skipping zero axes.  A `EV_SYN
/// SYN_REPORT` frame end is appended.
///
/// Used by `drivers/input/src/i8042_mouse.rs` and test smokes.
pub fn dispatch_rel_to_node(node: &DeviceNode, dx: i32, dy: i32) {
    let now = narf_time::now_cycles();
    if dx != 0 {
        node.dispatch(EvdevEvent {
            time: now,
            type_: EventType::Rel,
            code: rel::REL_X,
            value: dx,
        });
    }
    if dy != 0 {
        node.dispatch(EvdevEvent {
            time: now,
            type_: EventType::Rel,
            code: rel::REL_Y,
            value: dy,
        });
    }
    node.dispatch(EvdevEvent::syn_report(now));
}
