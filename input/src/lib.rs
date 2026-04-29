//! narf-input — shared input event types + per-device event ring.
//!
//! This crate is the contract between input drivers (i8042 PS/2,
//! virtio-input, future USB HID) and consumers (the future TTY,
//! windowing, test harness). Drivers translate their wire format
//! into the `KeyEvent` / `PointerEvent` / `ScrollEvent` shapes
//! defined here and push them through `EventRing`. Consumers pop
//! from the ring through a cap-gated subscriber handle.
//!
//! Wire-level translation tables (scancode-set-1, evdev codes) live
//! in the *drivers* — this crate stays neutral on hardware specifics.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// Tiny local bitflags-style macro — declared early so the
// `bitflags_like!` invocations below can see it.
#[macro_export]
macro_rules! bitflags_like {
    (
        $(#[$outer:meta])*
        pub struct $name:ident: $repr:ty {
            $(const $flag:ident = $value:expr;)*
        }
    ) => {
        $(#[$outer])*
        #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $repr);

        impl $name {
            pub const EMPTY: Self = Self(0);
            $(pub const $flag: Self = Self($value);)*

            #[inline] pub const fn bits(self) -> $repr { self.0 }
            #[inline] pub const fn from_bits_truncate(b: $repr) -> Self { Self(b) }
            #[inline] pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }
            #[inline] pub fn insert(&mut self, other: Self) { self.0 |= other.0; }
            #[inline] pub fn remove(&mut self, other: Self) { self.0 &= !other.0; }
            #[inline] pub fn toggle(&mut self, other: Self) { self.0 ^= other.0; }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({:#b})", stringify!($name), self.0)
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
        }
        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
        }
        impl core::ops::BitAnd for $name {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
        }
    };
}

/// US-QWERTY base key code set. Modeled after Linux input-event-codes
/// `KEY_*` but pruned to a kernel-tractable subset; we add codes as
/// real callers need them. The numeric values are stable so logs +
/// tests can pin against them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum KeyCode {
    Reserved   = 0,
    Escape     = 1,
    Key1       = 2, Key2 = 3, Key3 = 4, Key4 = 5, Key5 = 6,
    Key6       = 7, Key7 = 8, Key8 = 9, Key9 = 10, Key0 = 11,
    Minus      = 12,
    Equal      = 13,
    Backspace  = 14,
    Tab        = 15,
    Q = 16, W = 17, E = 18, R = 19, T = 20, Y = 21, U = 22, I = 23, O = 24, P = 25,
    LeftBrace  = 26,
    RightBrace = 27,
    Enter      = 28,
    LeftCtrl   = 29,
    A = 30, S = 31, D = 32, F = 33, G = 34, H = 35, J = 36, K = 37, L = 38,
    Semicolon  = 39,
    Apostrophe = 40,
    Grave      = 41,
    LeftShift  = 42,
    Backslash  = 43,
    Z = 44, X = 45, C = 46, V = 47, B = 48, N = 49, M = 50,
    Comma      = 51,
    Dot        = 52,
    Slash      = 53,
    RightShift = 54,
    KpAsterisk = 55,
    LeftAlt    = 56,
    Space      = 57,
    CapsLock   = 58,
    F1 = 59, F2 = 60, F3 = 61, F4 = 62, F5 = 63,
    F6 = 64, F7 = 65, F8 = 66, F9 = 67, F10 = 68,
    NumLock    = 69,
    ScrollLock = 70,
    Up         = 103,
    Down       = 108,
    Left       = 105,
    Right      = 106,
    RightCtrl  = 97,
    RightAlt   = 100,
    Unknown    = 0xFFFF,
}

impl KeyCode {
    /// True when this code represents a modifier (shift / ctrl / alt /
    /// caps / num / scroll lock). Useful for consumers that compute
    /// effective modifier state without re-tracking it themselves.
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            KeyCode::LeftShift | KeyCode::RightShift |
            KeyCode::LeftCtrl  | KeyCode::RightCtrl  |
            KeyCode::LeftAlt   | KeyCode::RightAlt   |
            KeyCode::CapsLock  | KeyCode::NumLock    | KeyCode::ScrollLock
        )
    }
}

bitflags_like! {
    /// Modifier-key bitset attached to every `KeyEvent`. Drivers
    /// maintain it across keypress/release pairs and stamp the live
    /// state onto each event so consumers don't need to track it.
    pub struct Modifiers: u16 {
        const SHIFT       = 1 << 0;
        const CTRL        = 1 << 1;
        const ALT         = 1 << 2;
        const CAPS_LOCK   = 1 << 3;
        const NUM_LOCK    = 1 << 4;
        const SCROLL_LOCK = 1 << 5;
    }
}

/// Single key state transition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub code:      KeyCode,
    /// `true` = press / hold-down begin; `false` = release.
    pub pressed:   bool,
    /// Live modifier state at the moment the driver emitted the
    /// event (after applying this event's effect for modifier keys
    /// — e.g. press of LeftShift includes SHIFT).
    pub modifiers: Modifiers,
}

/// Pointer (mouse / touchpad) movement delta. Drivers emit absolute
/// or relative depending on the device class; this struct carries
/// the relative form.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PointerEvent {
    pub dx:      i32,
    pub dy:      i32,
    pub buttons: PointerButtons,
}

bitflags_like! {
    pub struct PointerButtons: u8 {
        const LEFT   = 1 << 0;
        const RIGHT  = 1 << 1;
        const MIDDLE = 1 << 2;
    }
}

/// Vertical / horizontal scroll wheel delta.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScrollEvent {
    pub dx: i32,
    pub dy: i32,
}

/// Tagged-union of every event a driver can emit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InputEvent {
    Key(KeyEvent),
    Pointer(PointerEvent),
    Scroll(ScrollEvent),
}

/// Bounded SPSC ring of input events. Producers (drivers, IRQ
/// context) push; consumers (tasks, tests) pop. Overflow drops the
/// oldest event and bumps `dropped`.
#[derive(Debug)]
pub struct EventRing {
    inner:    IrqSafeSpinLock<VecDeque<InputEvent>>,
    capacity: usize,
    pushed:   AtomicU64,
    dropped:  AtomicU64,
}

impl EventRing {
    /// Construct a ring with `capacity` slots. Capacity 0 is treated
    /// as 1 — empty rings would discard everything.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            inner:    IrqSafeSpinLock::new(VecDeque::with_capacity(cap)),
            capacity: cap,
            pushed:   AtomicU64::new(0),
            dropped:  AtomicU64::new(0),
        }
    }

    pub fn capacity(&self) -> usize { self.capacity }
    pub fn pushed(&self)  -> u64 { self.pushed.load(Ordering::Relaxed) }
    pub fn dropped(&self) -> u64 { self.dropped.load(Ordering::Relaxed) }

    /// Push one event. Drops the oldest event if full and bumps
    /// `dropped`. Returns `true` if no drop happened.
    pub fn push(&self, ev: InputEvent) -> bool {
        let mut q = self.inner.lock();
        let mut clean = true;
        if q.len() >= self.capacity {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
            clean = false;
        }
        q.push_back(ev);
        self.pushed.fetch_add(1, Ordering::Relaxed);
        clean
    }

    /// Pop the oldest event, or `None` if empty.
    pub fn pop(&self) -> Option<InputEvent> {
        self.inner.lock().pop_front()
    }

    /// Number of events queued right now.
    pub fn len(&self) -> usize { self.inner.lock().len() }

    pub fn is_empty(&self) -> bool { self.inner.lock().is_empty() }

    #[doc(hidden)]
    pub fn __reset_for_test(&self) {
        self.inner.lock().clear();
        self.pushed.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
    }
}

/// Process-wide input event ring. Drivers push, consumers pop.
/// Bounded at 256 events — enough for keyboard burst latency, small
/// enough that a runaway producer doesn't eat unbounded heap.
static GLOBAL_RING: IrqSafeSpinLock<Option<EventRing>> =
    IrqSafeSpinLock::new(None);

/// Initialise the global ring. Idempotent on repeat calls — the
/// ring is reset rather than re-constructed so callers that hold
/// `&'static` references stay valid.
pub fn init_global_ring(capacity: usize) {
    let mut g = GLOBAL_RING.lock();
    match g.as_ref() {
        Some(r) => r.__reset_for_test(),
        None    => *g = Some(EventRing::new(capacity)),
    }
}

/// Push to the global ring. Silently drops if `init_global_ring`
/// has not been called.
pub fn push_global(ev: InputEvent) -> bool {
    let g = GLOBAL_RING.lock();
    if let Some(r) = g.as_ref() { r.push(ev) } else { false }
}

/// Pop from the global ring. `None` if empty or uninitialised.
pub fn pop_global() -> Option<InputEvent> {
    GLOBAL_RING.lock().as_ref().and_then(|r| r.pop())
}

/// Snapshot of pushed/dropped counters, useful for smoke tests.
pub fn global_counters() -> (u64, u64) {
    GLOBAL_RING.lock().as_ref()
        .map(|r| (r.pushed(), r.dropped()))
        .unwrap_or((0, 0))
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_global_ring_for_test() {
    if let Some(r) = GLOBAL_RING.lock().as_ref() { r.__reset_for_test(); }
}

/// Stage::Subsys initcall: install the global event ring before
/// any input driver pushes to it. Capacity 256 covers ~1 second
/// of bursty keyboard / mouse input.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "input-event-ring", || {
        init_global_ring(256);
        InitResult::Ok
    });
}

