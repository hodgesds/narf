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
use core::task::Waker;

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
    Reserved = 0,
    Escape = 1,
    Key1 = 2,
    Key2 = 3,
    Key3 = 4,
    Key4 = 5,
    Key5 = 6,
    Key6 = 7,
    Key7 = 8,
    Key8 = 9,
    Key9 = 10,
    Key0 = 11,
    Minus = 12,
    Equal = 13,
    Backspace = 14,
    Tab = 15,
    Q = 16,
    W = 17,
    E = 18,
    R = 19,
    T = 20,
    Y = 21,
    U = 22,
    I = 23,
    O = 24,
    P = 25,
    LeftBrace = 26,
    RightBrace = 27,
    Enter = 28,
    LeftCtrl = 29,
    A = 30,
    S = 31,
    D = 32,
    F = 33,
    G = 34,
    H = 35,
    J = 36,
    K = 37,
    L = 38,
    Semicolon = 39,
    Apostrophe = 40,
    Grave = 41,
    LeftShift = 42,
    Backslash = 43,
    Z = 44,
    X = 45,
    C = 46,
    V = 47,
    B = 48,
    N = 49,
    M = 50,
    Comma = 51,
    Dot = 52,
    Slash = 53,
    RightShift = 54,
    KpAsterisk = 55,
    LeftAlt = 56,
    Space = 57,
    CapsLock = 58,
    F1 = 59,
    F2 = 60,
    F3 = 61,
    F4 = 62,
    F5 = 63,
    F6 = 64,
    F7 = 65,
    F8 = 66,
    F9 = 67,
    F10 = 68,
    NumLock = 69,
    ScrollLock = 70,
    F11 = 87,
    F12 = 88,
    Kp7 = 71,
    Kp8 = 72,
    Kp9 = 73,
    KpMinus = 74,
    Kp4 = 75,
    Kp5 = 76,
    Kp6 = 77,
    KpPlus = 78,
    Kp1 = 79,
    Kp2 = 80,
    Kp3 = 81,
    Kp0 = 82,
    KpDot = 83,
    KpEnter = 96,
    KpSlash = 98,
    SysRq = 99,
    Home = 102,
    PageUp = 104,
    End = 107,
    PageDown = 109,
    Insert = 110,
    Delete = 111,
    Pause = 119,
    LeftMeta = 125,
    RightMeta = 126,
    Menu = 127,
    Up = 103,
    Down = 108,
    Left = 105,
    Right = 106,
    RightCtrl = 97,
    RightAlt = 100,
    // Media / consumer block — Linux evdev values. Used by HID
    // consumer pages, virtio-input keyboards, and ACPI EC laptop
    // hotkey blocks (Fn+F-keys → brightness/volume/airplane).
    Mute = 113,
    VolumeDown = 114,
    VolumeUp = 115,
    Power = 116,
    Stop = 128,
    PreviousSong = 165,
    NextSong = 163,
    PlayPause = 164,
    BrightnessDown = 224,
    BrightnessUp = 225,
    KbdIlluminationToggle = 228,
    KbdIlluminationDown = 229,
    KbdIlluminationUp = 230,
    Sleep = 142,
    WakeUp = 143,
    WLan = 238,
    RfKill = 247,
    TouchpadToggle = 530,
    Unknown = 0xFFFF,
}

impl KeyCode {
    /// True when this code represents a modifier (shift / ctrl / alt /
    /// caps / num / scroll lock). Useful for consumers that compute
    /// effective modifier state without re-tracking it themselves.
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            KeyCode::LeftShift
                | KeyCode::RightShift
                | KeyCode::LeftCtrl
                | KeyCode::RightCtrl
                | KeyCode::LeftAlt
                | KeyCode::RightAlt
                | KeyCode::LeftMeta
                | KeyCode::RightMeta
                | KeyCode::CapsLock
                | KeyCode::NumLock
                | KeyCode::ScrollLock
        )
    }

    /// Decode a Linux evdev `KEY_*` code (the value the kernel hands
    /// userspace and that virtio-input + HID drivers emit on the
    /// wire) into a NARF `KeyCode`. Codes outside the supported set
    /// map to `KeyCode::Unknown` rather than UB-transmuting an
    /// invalid discriminant.
    ///
    /// Reference: include/uapi/linux/input-event-codes.h (Linux UAPI,
    /// public per LICENSES/exceptions/Linux-syscall-note).
    pub const fn from_evdev(code: u16) -> Self {
        match code {
            0 => KeyCode::Reserved,
            1 => KeyCode::Escape,
            2 => KeyCode::Key1,
            3 => KeyCode::Key2,
            4 => KeyCode::Key3,
            5 => KeyCode::Key4,
            6 => KeyCode::Key5,
            7 => KeyCode::Key6,
            8 => KeyCode::Key7,
            9 => KeyCode::Key8,
            10 => KeyCode::Key9,
            11 => KeyCode::Key0,
            12 => KeyCode::Minus,
            13 => KeyCode::Equal,
            14 => KeyCode::Backspace,
            15 => KeyCode::Tab,
            16 => KeyCode::Q,
            17 => KeyCode::W,
            18 => KeyCode::E,
            19 => KeyCode::R,
            20 => KeyCode::T,
            21 => KeyCode::Y,
            22 => KeyCode::U,
            23 => KeyCode::I,
            24 => KeyCode::O,
            25 => KeyCode::P,
            26 => KeyCode::LeftBrace,
            27 => KeyCode::RightBrace,
            28 => KeyCode::Enter,
            29 => KeyCode::LeftCtrl,
            30 => KeyCode::A,
            31 => KeyCode::S,
            32 => KeyCode::D,
            33 => KeyCode::F,
            34 => KeyCode::G,
            35 => KeyCode::H,
            36 => KeyCode::J,
            37 => KeyCode::K,
            38 => KeyCode::L,
            39 => KeyCode::Semicolon,
            40 => KeyCode::Apostrophe,
            41 => KeyCode::Grave,
            42 => KeyCode::LeftShift,
            43 => KeyCode::Backslash,
            44 => KeyCode::Z,
            45 => KeyCode::X,
            46 => KeyCode::C,
            47 => KeyCode::V,
            48 => KeyCode::B,
            49 => KeyCode::N,
            50 => KeyCode::M,
            51 => KeyCode::Comma,
            52 => KeyCode::Dot,
            53 => KeyCode::Slash,
            54 => KeyCode::RightShift,
            55 => KeyCode::KpAsterisk,
            56 => KeyCode::LeftAlt,
            57 => KeyCode::Space,
            58 => KeyCode::CapsLock,
            59 => KeyCode::F1,
            60 => KeyCode::F2,
            61 => KeyCode::F3,
            62 => KeyCode::F4,
            63 => KeyCode::F5,
            64 => KeyCode::F6,
            65 => KeyCode::F7,
            66 => KeyCode::F8,
            67 => KeyCode::F9,
            68 => KeyCode::F10,
            69 => KeyCode::NumLock,
            70 => KeyCode::ScrollLock,
            71 => KeyCode::Kp7,
            72 => KeyCode::Kp8,
            73 => KeyCode::Kp9,
            74 => KeyCode::KpMinus,
            75 => KeyCode::Kp4,
            76 => KeyCode::Kp5,
            77 => KeyCode::Kp6,
            78 => KeyCode::KpPlus,
            79 => KeyCode::Kp1,
            80 => KeyCode::Kp2,
            81 => KeyCode::Kp3,
            82 => KeyCode::Kp0,
            83 => KeyCode::KpDot,
            87 => KeyCode::F11,
            88 => KeyCode::F12,
            96 => KeyCode::KpEnter,
            97 => KeyCode::RightCtrl,
            98 => KeyCode::KpSlash,
            99 => KeyCode::SysRq,
            100 => KeyCode::RightAlt,
            102 => KeyCode::Home,
            103 => KeyCode::Up,
            104 => KeyCode::PageUp,
            105 => KeyCode::Left,
            106 => KeyCode::Right,
            107 => KeyCode::End,
            108 => KeyCode::Down,
            109 => KeyCode::PageDown,
            110 => KeyCode::Insert,
            111 => KeyCode::Delete,
            119 => KeyCode::Pause,
            125 => KeyCode::LeftMeta,
            126 => KeyCode::RightMeta,
            127 => KeyCode::Menu,
            113 => KeyCode::Mute,
            114 => KeyCode::VolumeDown,
            115 => KeyCode::VolumeUp,
            116 => KeyCode::Power,
            128 => KeyCode::Stop,
            163 => KeyCode::NextSong,
            164 => KeyCode::PlayPause,
            165 => KeyCode::PreviousSong,
            224 => KeyCode::BrightnessDown,
            225 => KeyCode::BrightnessUp,
            228 => KeyCode::KbdIlluminationToggle,
            229 => KeyCode::KbdIlluminationDown,
            230 => KeyCode::KbdIlluminationUp,
            142 => KeyCode::Sleep,
            143 => KeyCode::WakeUp,
            238 => KeyCode::WLan,
            247 => KeyCode::RfKill,
            530 => KeyCode::TouchpadToggle,
            _ => KeyCode::Unknown,
        }
    }
}

/// Apply the effect of a press/release of `code` to a modifier
/// bitset and return the post-event state. Shift/Ctrl/Alt/Meta
/// follow press/release directly; CapsLock/NumLock/ScrollLock
/// toggle on press only (release is a no-op). Non-modifier keys
/// pass `mods` through unchanged. Pure — no global state.
pub fn apply_modifiers(code: KeyCode, pressed: bool, mods: Modifiers) -> Modifiers {
    let mut m = mods;
    let bit = match code {
        KeyCode::LeftShift | KeyCode::RightShift => Modifiers::SHIFT,
        KeyCode::LeftCtrl | KeyCode::RightCtrl => Modifiers::CTRL,
        KeyCode::LeftAlt | KeyCode::RightAlt => Modifiers::ALT,
        KeyCode::LeftMeta | KeyCode::RightMeta => Modifiers::META,
        KeyCode::CapsLock if pressed => {
            m.toggle(Modifiers::CAPS_LOCK);
            return m;
        }
        KeyCode::NumLock if pressed => {
            m.toggle(Modifiers::NUM_LOCK);
            return m;
        }
        KeyCode::ScrollLock if pressed => {
            m.toggle(Modifiers::SCROLL_LOCK);
            return m;
        }
        _ => return m,
    };
    if pressed {
        m.insert(bit);
    } else {
        m.remove(bit);
    }
    m
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
        const META        = 1 << 6;
    }
}

/// Single key state transition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub code: KeyCode,
    /// `true` = press / hold-down begin; `false` = release.
    pub pressed: bool,
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
    pub dx: i32,
    pub dy: i32,
    pub buttons: PointerButtons,
}

bitflags_like! {
    /// Mouse-button bitset. Bits 0..=2 are the canonical
    /// three-button mouse; 3..=7 cover gaming-mouse / virtio-mouse
    /// extras emitted as Linux evdev `BTN_SIDE` / `BTN_EXTRA` /
    /// `BTN_FORWARD` / `BTN_BACK` / `BTN_TASK`. Producers that
    /// only know LEFT/RIGHT/MIDDLE leave the high bits clear.
    pub struct PointerButtons: u8 {
        const LEFT    = 1 << 0;
        const RIGHT   = 1 << 1;
        const MIDDLE  = 1 << 2;
        const SIDE    = 1 << 3;
        const EXTRA   = 1 << 4;
        const FORWARD = 1 << 5;
        const BACK    = 1 << 6;
        const TASK    = 1 << 7;
    }
}

/// Vertical / horizontal scroll wheel delta.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScrollEvent {
    pub dx: i32,
    pub dy: i32,
}

/// Absolute-axis sample. Used by digitisers (virtio-tablet, touch
/// pads), styluses, and joysticks where the device reports a
/// position in its own coordinate space rather than a delta.
///
/// `axis` is the raw evdev `ABS_*` code so consumers can address
/// any axis the device exposes, including ones we don't have
/// named constants for yet (vendor-specific axes, second-stick
/// extensions, etc.). The named constants under [`abs`] cover the
/// codes a Stage-1 client most often cares about.
///
/// `value` is the device-reported value. Per Linux evdev semantics
/// it's i32 — most axes are unsigned but tilt / hat / signed-range
/// joystick axes go negative.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AbsoluteEvent {
    pub axis: u16,
    pub value: i32,
}

/// Lifecycle of one multi-touch contact, encoded explicitly so
/// consumers don't have to reconstruct it from `tracking_id`
/// transitions. `Down` = first frame this contact appears in,
/// `Move` = position / pressure update for an already-active
/// contact, `Up` = release. Touchscreens and touchpads on the
/// HID Digitizer page produce all three; the producer is
/// responsible for tracking per-slot state to set this correctly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TouchState {
    Down,
    Move,
    Up,
}

/// One contact slot of a multi-touch frame. Used by both evdev
/// protocol-B touchpads (virtio-input) and HID Digitizer
/// touchscreens (i2c-hid → `digitizer` page 0x0D).
///
/// `slot` is the MT slot id (per `ABS_MT_SLOT` for evdev, or the
/// per-finger collection index for HID Digitizer). `tracking_id`
/// distinguishes generations of the same physical finger — `None`
/// = released (evdev `tracking_id = -1`; HID `Tip Switch` == 0).
/// `id` is the device-reported Contact Identifier from HID
/// Digitizer reports, or the evdev tracking-id cast to u16; the
/// producer sets it to disambiguate fingers across reports.
///
/// `x`, `y`, `pressure` are device-coordinate values. Touchscreen
/// callers can normalise them via [`TouchEvent::normalise_axis`]
/// against the `(min, max)` of the corresponding HID Logical
/// axes, producing a `0..=65535` fixed-point space the windowing
/// layer can consume directly.
///
/// `state` is the explicit lifecycle phase (`Down` / `Move` /
/// `Up`) — derived by the producer from per-slot history so
/// consumers don't have to re-derive it from `tracking_id`
/// changes.
///
/// One `TouchEvent` is emitted per dirty slot at every input
/// frame boundary, so consumers see a self-contained snapshot
/// per touch transition without having to reconstruct slot state
/// themselves.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TouchEvent {
    pub slot: u8,
    pub tracking_id: Option<i32>,
    /// Device-reported Contact Identifier (HID Digitizer usage
    /// 0x51) or evdev tracking-id cast — zero when neither is
    /// known. Stable across frames within one touch lifetime.
    pub id: u16,
    pub x: i32,
    pub y: i32,
    pub pressure: i32,
    pub state: TouchState,
}

impl TouchEvent {
    /// Linearly remap one device-axis sample into the
    /// `0..=65535` fixed-point space the touchscreen public
    /// surface uses. `min` / `max` are the HID `Logical
    /// Minimum` / `Logical Maximum` from the field descriptor
    /// (or the evdev `AxisInfo::{min,max}` for protocol-B
    /// digitisers). Clamps out-of-range values to the endpoints
    /// rather than wrapping — a touchscreen reporting outside
    /// its declared range is a firmware bug, but the rendered
    /// cursor should track the screen edge rather than jumping.
    ///
    /// Returns the input value unchanged when `min == max`
    /// (degenerate axis — keeps the call site safe to invoke
    /// without pre-checking).
    pub fn normalise_axis(value: i32, min: i32, max: i32) -> u16 {
        if max <= min {
            return value.clamp(0, u16::MAX as i32) as u16;
        }
        let v = value.clamp(min, max) as i64;
        let lo = min as i64;
        let hi = max as i64;
        // (v - lo) / (hi - lo) * 65535, computed in i64 to
        // avoid overflow on big logical ranges (touchscreens
        // commonly use 0..=16383 or 0..=32767).
        let num = (v - lo).saturating_mul(u16::MAX as i64);
        let den = hi - lo;
        let scaled = num / den;
        scaled.clamp(0, u16::MAX as i64) as u16
    }

    /// Convenience over [`Self::normalise_axis`] returning both
    /// coordinates as a `(u16, u16)` pair, mapping
    /// `(x, x_min, x_max)` and `(y, y_min, y_max)` into the
    /// shared `0..=65535` space.
    pub fn normalise_xy(
        x: i32,
        y: i32,
        x_min: i32,
        x_max: i32,
        y_min: i32,
        y_max: i32,
    ) -> (u16, u16) {
        (
            Self::normalise_axis(x, x_min, x_max),
            Self::normalise_axis(y, y_min, y_max),
        )
    }
}

/// Generic button event for `BTN_*` codes that aren't keyboard
/// (`KeyCode`) or mouse-button (`PointerButtons`) shaped. Gamepad
/// face buttons (`BTN_SOUTH/EAST/NORTH/WEST`), shoulder buttons
/// (`BTN_TL/TR/TL2/TR2`), thumb-stick clicks, joystick triggers,
/// stylus barrel buttons, digitiser tool-type bits — every input
/// device that emits an EV_KEY outside the keyboard / pointer
/// ranges funnels through this. Consumers compare `code` against
/// constants in [`btn`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ButtonEvent {
    pub code: u16,
    pub pressed: bool,
}

/// Linux evdev `BTN_*` codes — mouse + gamepad + joystick + digitiser.
/// Vendored from `include/uapi/linux/input-event-codes.h`
/// (Linux UAPI, public per `LICENSES/exceptions/Linux-syscall-note`).
pub mod btn {
    // Mouse / pointer buttons (0x110..) — also in `PointerButtons` but
    // surfaced here for drivers that need the raw evdev code (e.g. HID multitouch).
    pub const BTN_LEFT: u16 = 0x110;
    pub const BTN_RIGHT: u16 = 0x111;
    pub const BTN_MIDDLE: u16 = 0x112;
    pub const BTN_SIDE: u16 = 0x113;
    pub const BTN_EXTRA: u16 = 0x114;
    pub const BTN_FORWARD: u16 = 0x115;
    pub const BTN_BACK: u16 = 0x116;
    pub const BTN_TASK: u16 = 0x117;
    // Joystick (0x120..)
    pub const BTN_TRIGGER: u16 = 0x120;
    pub const BTN_THUMB: u16 = 0x121;
    pub const BTN_THUMB2: u16 = 0x122;
    pub const BTN_TOP: u16 = 0x123;
    pub const BTN_TOP2: u16 = 0x124;
    pub const BTN_PINKIE: u16 = 0x125;
    pub const BTN_BASE: u16 = 0x126;
    pub const BTN_BASE2: u16 = 0x127;
    pub const BTN_BASE3: u16 = 0x128;
    pub const BTN_BASE4: u16 = 0x129;
    pub const BTN_BASE5: u16 = 0x12A;
    pub const BTN_BASE6: u16 = 0x12B;
    pub const BTN_DEAD: u16 = 0x12F;
    // Gamepad face buttons (0x130..)
    pub const BTN_SOUTH: u16 = 0x130; // alias: BTN_A
    pub const BTN_EAST: u16 = 0x131; // alias: BTN_B
    pub const BTN_C: u16 = 0x132;
    pub const BTN_NORTH: u16 = 0x133; // alias: BTN_X
    pub const BTN_WEST: u16 = 0x134; // alias: BTN_Y
    pub const BTN_Z: u16 = 0x135;
    pub const BTN_TL: u16 = 0x136;
    pub const BTN_TR: u16 = 0x137;
    pub const BTN_TL2: u16 = 0x138;
    pub const BTN_TR2: u16 = 0x139;
    pub const BTN_SELECT: u16 = 0x13A;
    pub const BTN_START: u16 = 0x13B;
    pub const BTN_MODE: u16 = 0x13C;
    pub const BTN_THUMBL: u16 = 0x13D;
    pub const BTN_THUMBR: u16 = 0x13E;
    // Digitiser (0x140..)
    pub const BTN_TOOL_PEN: u16 = 0x140;
    pub const BTN_TOOL_RUBBER: u16 = 0x141;
    pub const BTN_TOOL_BRUSH: u16 = 0x142;
    pub const BTN_TOOL_PENCIL: u16 = 0x143;
    pub const BTN_TOOL_AIRBRUSH: u16 = 0x144;
    pub const BTN_TOOL_FINGER: u16 = 0x145;
    pub const BTN_TOOL_MOUSE: u16 = 0x146;
    pub const BTN_TOOL_LENS: u16 = 0x147;
    pub const BTN_TOOL_QUINTTAP: u16 = 0x148;
    pub const BTN_STYLUS3: u16 = 0x149;
    // 0x14A = BTN_TOUCH — surfaced through MT slot 0 contact, not
    // through ButtonEvent. Listed here as a reminder.
    pub const BTN_STYLUS: u16 = 0x14B;
    pub const BTN_STYLUS2: u16 = 0x14C;
    pub const BTN_TOOL_DOUBLETAP: u16 = 0x14D;
    pub const BTN_TOOL_TRIPLETAP: u16 = 0x14E;
    pub const BTN_TOOL_QUADTAP: u16 = 0x14F;
    // Gamepad D-pad (0x220..)
    pub const BTN_DPAD_UP: u16 = 0x220;
    pub const BTN_DPAD_DOWN: u16 = 0x221;
    pub const BTN_DPAD_LEFT: u16 = 0x222;
    pub const BTN_DPAD_RIGHT: u16 = 0x223;
}

/// Per-axis bounds + filter parameters. Drivers cache one of these
/// per `ABS_*` axis the device exposes; consumers (tablet cursors,
/// joystick stick mappers) use them to normalise raw
/// `AbsoluteEvent::value` into screen / unit-circle coordinates
/// without baking in device-specific assumptions.
///
/// Mirrors Linux `struct input_absinfo`, with the runtime
/// `value` field intentionally omitted — the latest sample lives
/// in the event stream, not in the bounds record.
///
/// `res` is in axis-units-per-mm (per Linux uapi); `0` means the
/// device didn't advertise a resolution.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct AxisInfo {
    pub min: i32,
    pub max: i32,
    pub fuzz: i32,
    pub flat: i32,
    pub res: i32,
}

impl AxisInfo {
    /// Parse the on-wire `virtio_input_absinfo` (20 bytes, five
    /// little-endian i32 fields in `min/max/fuzz/flat/res` order
    /// per VirtIO 1.2 §5.8.4). Returns `None` if `bytes.len() <
    /// 20` — every well-formed device returns exactly 20.
    pub fn from_virtio_absinfo(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }
        let read = |off: usize| -> i32 {
            i32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
        };
        Some(Self {
            min: read(0),
            max: read(4),
            fuzz: read(8),
            flat: read(12),
            res: read(16),
        })
    }
}

/// Linux evdev `ABS_*` axis codes (subset). Vendored from
/// `include/uapi/linux/input-event-codes.h` (Linux UAPI, public
/// per `LICENSES/exceptions/Linux-syscall-note`). Drivers feed the
/// raw u16; consumers compare against these.
pub mod abs {
    pub const ABS_X: u16 = 0x00;
    pub const ABS_Y: u16 = 0x01;
    pub const ABS_Z: u16 = 0x02;
    pub const ABS_RX: u16 = 0x03;
    pub const ABS_RY: u16 = 0x04;
    pub const ABS_RZ: u16 = 0x05;
    pub const ABS_THROTTLE: u16 = 0x06;
    pub const ABS_RUDDER: u16 = 0x07;
    pub const ABS_WHEEL: u16 = 0x08;
    pub const ABS_GAS: u16 = 0x09;
    pub const ABS_BRAKE: u16 = 0x0a;
    pub const ABS_HAT0X: u16 = 0x10;
    pub const ABS_HAT0Y: u16 = 0x11;
    pub const ABS_HAT1X: u16 = 0x12;
    pub const ABS_HAT1Y: u16 = 0x13;
    pub const ABS_HAT2X: u16 = 0x14;
    pub const ABS_HAT2Y: u16 = 0x15;
    pub const ABS_HAT3X: u16 = 0x16;
    pub const ABS_HAT3Y: u16 = 0x17;
    pub const ABS_PRESSURE: u16 = 0x18;
    pub const ABS_DISTANCE: u16 = 0x19;
    pub const ABS_TILT_X: u16 = 0x1A;
    pub const ABS_TILT_Y: u16 = 0x1B;
    pub const ABS_TOOL_WIDTH: u16 = 0x1C;
    pub const ABS_MT_SLOT: u16 = 0x2F;
    pub const ABS_MT_TOUCH_MAJOR: u16 = 0x30;
    pub const ABS_MT_TOUCH_MINOR: u16 = 0x31;
    pub const ABS_MT_WIDTH_MAJOR: u16 = 0x32;
    pub const ABS_MT_WIDTH_MINOR: u16 = 0x33;
    pub const ABS_MT_ORIENTATION: u16 = 0x34;
    pub const ABS_MT_POSITION_X: u16 = 0x35;
    pub const ABS_MT_POSITION_Y: u16 = 0x36;
    pub const ABS_MT_TOOL_TYPE: u16 = 0x37;
    pub const ABS_MT_BLOB_ID: u16 = 0x38;
    pub const ABS_MT_TRACKING_ID: u16 = 0x39;
    pub const ABS_MT_PRESSURE: u16 = 0x3A;
    pub const ABS_MT_DISTANCE: u16 = 0x3B;
    pub const ABS_MT_TOOL_X: u16 = 0x3C;
    pub const ABS_MT_TOOL_Y: u16 = 0x3D;
    /// Miscellaneous axis — used by some HID drivers as a generic
    /// slot. Ref: `include/uapi/linux/input-event-codes.h ABS_MISC`.
    pub const ABS_MISC: u16 = 0x28;
    pub const ABS_VOLUME: u16 = 0x20;
    pub const ABS_CNT: u16 = 0x40;
}

/// Tagged-union of every event a driver can emit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InputEvent {
    Key(KeyEvent),
    Pointer(PointerEvent),
    Scroll(ScrollEvent),
    Absolute(AbsoluteEvent),
    Touch(TouchEvent),
    Button(ButtonEvent),
    /// Raw ASCII / control byte from a character-oriented source
    /// (UART, virtio-console, ...). Producers that already speak
    /// in terms of bytes (rather than scancodes + modifiers) push
    /// this variant directly. Consumers wanting line-mode input
    /// (TTY, devfs `/dev/console`) deliver the byte verbatim;
    /// scancode-aware consumers (a future windowing system) will
    /// ignore it. Only valid for printable + standard control
    /// codes (Enter/Backspace/Esc); higher-bit / multibyte
    /// sequences are passed through as-is.
    AsciiByte(u8),
}

/// Bounded SPSC ring of input events. Producers (drivers, IRQ
/// context) push; consumers (tasks, tests) pop. Overflow drops the
/// oldest event and bumps `dropped`.
#[derive(Debug)]
pub struct EventRing {
    inner: IrqSafeSpinLock<VecDeque<InputEvent>>,
    capacity: usize,
    pushed: AtomicU64,
    dropped: AtomicU64,
}

impl EventRing {
    /// Construct a ring with `capacity` slots. Capacity 0 is treated
    /// as 1 — empty rings would discard everything.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            inner: IrqSafeSpinLock::new(VecDeque::with_capacity(cap)),
            capacity: cap,
            pushed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn pushed(&self) -> u64 {
        self.pushed.load(Ordering::Relaxed)
    }
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

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
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    #[doc(hidden)]
    pub fn __reset_for_test(&self) {
        self.inner.lock().clear();
        self.pushed.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
    }
}

/// Per-class event rings. Pre-fix every consumer popped from a
/// single shared ring and re-pushed events it didn't care about
/// (cursor pump consumed Pointer + re-pushed Key; /dev/console
/// consumed Key/AsciiByte + re-pushed Pointer/Scroll). The
/// ping-pong worked but interleavings re-ordered keystrokes vs
/// pointer motion across consumers — first character after a
/// click could land out of order.
///
/// One bounded ring per event class. Producer routes by variant;
/// consumer pops the class it cares about. No re-push, no
/// ordering surprises.
///
/// `KEY_RING` and `BYTE_RING` share a logical "console input"
/// stream — `/dev/console` reads from both. Pointer + Scroll are
/// separate because their consumers don't overlap.
static KEY_RING: IrqSafeSpinLock<Option<EventRing>> = IrqSafeSpinLock::new(None);
static POINTER_RING: IrqSafeSpinLock<Option<EventRing>> = IrqSafeSpinLock::new(None);
static SCROLL_RING: IrqSafeSpinLock<Option<EventRing>> = IrqSafeSpinLock::new(None);
static BYTE_RING: IrqSafeSpinLock<Option<EventRing>> = IrqSafeSpinLock::new(None);
static ABSOLUTE_RING: IrqSafeSpinLock<Option<EventRing>> = IrqSafeSpinLock::new(None);
static TOUCH_RING: IrqSafeSpinLock<Option<EventRing>> = IrqSafeSpinLock::new(None);
static BUTTON_RING: IrqSafeSpinLock<Option<EventRing>> = IrqSafeSpinLock::new(None);

/// Single waker slot for the `WaitAsciiByteFuture`. There is at most one
/// console reader blocked on stdin at any time (NARF's shell is single-
/// threaded). If a second waiter ever appears it simply overwrites the
/// first — both will be rescheduled by the next byte anyway.
///
/// The IRQ handler calls `pop_ascii_byte` (which holds the BYTE_RING lock
/// very briefly), so this waker lock must be acquired *after* the ring is
/// released to avoid inversion. `push_global_ascii_and_wake` always takes
/// the ring first, then the waker slot.
static BYTE_RING_WAKER: IrqSafeSpinLock<Option<Waker>> = IrqSafeSpinLock::new(None);

fn ring_for(ev: &InputEvent) -> &'static IrqSafeSpinLock<Option<EventRing>> {
    match ev {
        InputEvent::Key(_) => &KEY_RING,
        InputEvent::Pointer(_) => &POINTER_RING,
        InputEvent::Scroll(_) => &SCROLL_RING,
        InputEvent::Absolute(_) => &ABSOLUTE_RING,
        InputEvent::Touch(_) => &TOUCH_RING,
        InputEvent::Button(_) => &BUTTON_RING,
        InputEvent::AsciiByte(_) => &BYTE_RING,
    }
}

/// All per-class rings, in a stable iteration order.
fn all_rings() -> [&'static IrqSafeSpinLock<Option<EventRing>>; 7] {
    [
        &KEY_RING,
        &POINTER_RING,
        &SCROLL_RING,
        &ABSOLUTE_RING,
        &TOUCH_RING,
        &BUTTON_RING,
        &BYTE_RING,
    ]
}

/// Initialise all per-class rings. Idempotent — re-init resets
/// existing rings rather than reconstructing.
pub fn init_global_ring(capacity: usize) {
    for ring in all_rings() {
        let mut g = ring.lock();
        match g.as_ref() {
            Some(r) => r.__reset_for_test(),
            None => *g = Some(EventRing::new(capacity)),
        }
    }
}

/// Global modifier state tracked across all keyboard producers. A
/// shift held on i8042 stays held when virtio-input fires a letter
/// keypress on the same host (rare, but the correct behaviour). Drivers
/// shouldn't poke this directly — call `push_key` and let the helper
/// advance it.
static MODIFIER_STATE: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);

/// Current modifier bitset, sampled atomically.
pub fn current_modifiers() -> Modifiers {
    Modifiers::from_bits_truncate(MODIFIER_STATE.load(core::sync::atomic::Ordering::Acquire))
}

/// Active scanout pixel dimensions, published by the framebuffer layer so
/// absolute-pointer drivers can map each axis onto its true on-screen extent.
///
/// A tablet/touchscreen reports its position over a *square* device range
/// (QEMU virtio-tablet: 0..0x7FFF on both axes) that covers the whole screen.
/// Scaling both axes to one nominal span stretches the shorter axis — on a
/// 1024×768 output, mapping Y to a 1024-px span runs the pointer 1024/768 ≈
/// 1.33× fast vertically. Mapping each axis onto its real dimension keeps the
/// reconstructed motion 1:1 with the host pointer on both axes. Defaults to
/// 1024×768 (the common mode) until the fb layer publishes the live scanout.
static SCANOUT_W: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1024);
static SCANOUT_H: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(768);

/// Publish the active scanout's pixel dimensions. Called from the fb cursor
/// pump as it resolves the active scanout; zero values are ignored so a
/// half-initialised mode never clobbers a good one.
pub fn set_scanout_dims(w: u32, h: u32) {
    if w != 0 {
        SCANOUT_W.store(w, Ordering::Relaxed);
    }
    if h != 0 {
        SCANOUT_H.store(h, Ordering::Relaxed);
    }
}

/// `(width, height)` of the active scanout in pixels.
pub fn scanout_dims() -> (u32, u32) {
    (
        SCANOUT_W.load(Ordering::Relaxed),
        SCANOUT_H.load(Ordering::Relaxed),
    )
}

/// Absolute cursor position in pixels, published by an absolute-pointer driver
/// (virtio-tablet). `u32::MAX` = unset (no absolute device seen yet → the
/// cursor renderer keeps accumulating relative deltas). An absolute pointer
/// reports a true screen position every frame, so the drawn cursor can sit
/// exactly under the host pointer instead of drifting from an arbitrary origin.
static CURSOR_ABS_X: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static CURSOR_ABS_Y: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

/// Publish the absolute cursor position (scanout pixels). Called by the
/// virtio-tablet driver each input frame.
pub fn set_cursor_abs_px(x: u32, y: u32) {
    CURSOR_ABS_X.store(x, Ordering::Relaxed);
    CURSOR_ABS_Y.store(y, Ordering::Relaxed);
}

/// Latest absolute cursor position in pixels, or `None` if no absolute pointer
/// has reported yet.
pub fn cursor_abs_px() -> Option<(u32, u32)> {
    let x = CURSOR_ABS_X.load(Ordering::Relaxed);
    let y = CURSOR_ABS_Y.load(Ordering::Relaxed);
    if x == u32::MAX {
        None
    } else {
        Some((x, y))
    }
}

/// Advance the global modifier state by the effect of pressing /
/// releasing `code` and return the post-event state. Drivers use
/// this to stamp `KeyEvent::modifiers`. Called automatically by
/// `push_key`.
pub fn update_modifiers(code: KeyCode, pressed: bool) -> Modifiers {
    use core::sync::atomic::Ordering;
    // Single-writer-style CAS loop so a parallel producer doesn't
    // overwrite a concurrent toggle.
    loop {
        let prev_bits = MODIFIER_STATE.load(Ordering::Acquire);
        let prev = Modifiers::from_bits_truncate(prev_bits);
        let next = apply_modifiers(code, pressed, prev);
        match MODIFIER_STATE.compare_exchange(
            prev_bits,
            next.bits(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return next,
            Err(_) => continue,
        }
    }
}

/// Convenience for keyboard drivers: advances the global modifier
/// state, stamps the live modifier bitset onto a fresh `KeyEvent`,
/// and pushes it onto the global Key ring. Returns whether the push
/// landed without drop. Equivalent to:
/// `push_global(InputEvent::Key(KeyEvent { code, pressed,
/// modifiers: update_modifiers(code, pressed) }))`.
pub fn push_key(code: KeyCode, pressed: bool) -> bool {
    let modifiers = update_modifiers(code, pressed);
    push_global(InputEvent::Key(KeyEvent {
        code,
        pressed,
        modifiers,
    }))
}

/// Test-only: reset global modifier state to zero. Smoke tests
/// that exercise modifier transitions call this to avoid bleed
/// from a previous test's residual shift / capslock state.
#[doc(hidden)]
pub fn __reset_modifiers_for_test() {
    MODIFIER_STATE.store(0, core::sync::atomic::Ordering::Release);
}

/// Push an event onto the appropriate per-class ring. Silently
/// drops if `init_global_ring` hasn't been called.
///
/// When the event is `AsciiByte`, any waker registered via
/// `WaitAsciiByteFuture` is picked up and queued through
/// `narf_lib::deferred_wake` so the serial IRQ handler can wake the
/// blocked console reader from IRQ context without dropping an `Arc`
/// under the lock.
pub fn push_global(ev: InputEvent) -> bool {
    let is_key = matches!(ev, InputEvent::Key(_));
    let is_ascii = matches!(ev, InputEvent::AsciiByte(_));
    let ring = ring_for(&ev);
    let g = ring.lock();
    if let Some(r) = g.as_ref() {
        let ok = r.push(ev);
        if ok {
            if is_key {
                KEY_PUSH_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            if is_ascii {
                ASCII_PUSH_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            // Wake a parked console reader for any console-input event —
            // a serial byte OR a keyboard key. The unified line discipline
            // re-pumps both rings on wake, so a key press must wake it too
            // (the old code only woke on AsciiByte and missed the keyboard).
            // Drop the ring lock first so the waker lock is always taken
            // after the ring — this matches `WaitAsciiByteFuture::poll`.
            if is_ascii || is_key {
                drop(g);
                let maybe_waker = BYTE_RING_WAKER.lock().take();
                if let Some(w) = maybe_waker {
                    narf_lib::deferred_wake::push_pending(core::iter::once(Some(w)));
                }
                return ok;
            }
        }
        ok
    } else {
        false
    }
}

/// Pop a Key event. Returns `None` if empty or uninitialised.
pub fn pop_key() -> Option<KeyEvent> {
    let ev = KEY_RING.lock().as_ref().and_then(|r| r.pop())?;
    if let InputEvent::Key(k) = ev {
        KEY_POP_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Some(k)
    } else {
        None
    }
}

/// Pop a Pointer event.
pub fn pop_pointer() -> Option<PointerEvent> {
    let ev = POINTER_RING.lock().as_ref().and_then(|r| r.pop())?;
    if let InputEvent::Pointer(p) = ev {
        Some(p)
    } else {
        None
    }
}

/// Pop a Scroll event.
pub fn pop_scroll() -> Option<ScrollEvent> {
    let ev = SCROLL_RING.lock().as_ref().and_then(|r| r.pop())?;
    if let InputEvent::Scroll(s) = ev {
        Some(s)
    } else {
        None
    }
}

/// Number of ASCII bytes currently queued in the BYTE_RING. Best-
/// effort snapshot; the count can change immediately. Surfaced for
/// FIONREAD: userspace queries "how many bytes can I read without
/// blocking?" and the right answer is what's in the ring right now.
pub fn pending_bytes() -> usize {
    BYTE_RING.lock().as_ref().map(|r| r.len()).unwrap_or(0)
}

/// Total console-input depth: queued serial bytes PLUS queued key
/// events. The unified console line discipline drains both rings, so a
/// parked `sys_read` must re-check both to decide whether new input has
/// arrived. (`pending_bytes` alone misses keyboard input and would leave
/// a keyboard-only reader parked forever.)
pub fn pending_input() -> usize {
    let bytes = BYTE_RING.lock().as_ref().map(|r| r.len()).unwrap_or(0);
    let keys = KEY_RING.lock().as_ref().map(|r| r.len()).unwrap_or(0);
    bytes + keys
}

/// Register `waker` in the `BYTE_RING_WAKER` slot so the next
/// `push_global(AsciiByte(_))` (from the serial/keyboard IRQ via
/// `deferred_wake`) wakes the caller. Unlike `WaitAsciiByteFuture` this
/// does NOT pop — the caller (a parked `sys_read` re-executing on wake)
/// drains the ring itself. The console is single-reader, so the single
/// slot is sufficient. Callers MUST re-check `pending_bytes()` after
/// registering to close the arrive-between-check-and-register race.
pub fn register_byte_waker(waker: &core::task::Waker) {
    *BYTE_RING_WAKER.lock() = Some(waker.clone());
}

/// Pop one raw byte from the AsciiByte stream.
pub fn pop_ascii_byte() -> Option<u8> {
    let ev = BYTE_RING.lock().as_ref().and_then(|r| r.pop())?;
    if let InputEvent::AsciiByte(b) = ev {
        ASCII_POP_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Some(b)
    } else {
        None
    }
}

/// Return a future that resolves to the next byte from the ASCII/serial
/// input ring, blocking the current task until one arrives.
///
/// Uses the `BYTE_RING_WAKER` slot: on the first `Poll::Pending` the
/// future stores `cx.waker()` there. When `push_global(AsciiByte(_))`
/// runs (from the serial IRQ handler via `deferred_wake`) the stored
/// waker is queued for wake-up.
///
/// Raw mode — returns as soon as any single byte is available. Line
/// discipline (echo, backspace processing, newline buffering) is the
/// caller's responsibility; the NARF shell already does this in its own
/// read loop.
pub fn wait_ascii_byte() -> WaitAsciiByteFuture {
    WaitAsciiByteFuture { _priv: () }
}

/// Future returned by [`wait_ascii_byte`].
#[derive(Debug)]
pub struct WaitAsciiByteFuture {
    _priv: (),
}

impl core::future::Future for WaitAsciiByteFuture {
    type Output = u8;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<u8> {
        // Try to pop a byte first — avoids registering a waker if data
        // is already available (common when multiple bytes arrive in a
        // burst before the task is rescheduled).
        if let Some(b) = pop_ascii_byte() {
            return core::task::Poll::Ready(b);
        }
        // No byte yet. Register our waker so the next push wakes us.
        // Lock order: BYTE_RING_WAKER after BYTE_RING pop (already released
        // above) — matches the producer's drop-ring-then-lock-waker order.
        *BYTE_RING_WAKER.lock() = Some(cx.waker().clone());
        // Re-check after registering the waker to close the window where
        // a byte arrives between pop and register.
        if let Some(b) = pop_ascii_byte() {
            // Byte raced in. Clear the waker we just stored (no need to
            // wake ourselves again).
            BYTE_RING_WAKER.lock().take();
            return core::task::Poll::Ready(b);
        }
        core::task::Poll::Pending
    }
}

/// Pop an Absolute (axis sample) event. Returns `None` if empty
/// or the ring is uninitialised.
pub fn pop_absolute() -> Option<AbsoluteEvent> {
    let ev = ABSOLUTE_RING.lock().as_ref().and_then(|r| r.pop())?;
    if let InputEvent::Absolute(a) = ev {
        Some(a)
    } else {
        None
    }
}

/// Pop a Touch (multi-touch slot transition) event.
pub fn pop_touch() -> Option<TouchEvent> {
    let ev = TOUCH_RING.lock().as_ref().and_then(|r| r.pop())?;
    if let InputEvent::Touch(t) = ev {
        Some(t)
    } else {
        None
    }
}

/// Pop a Button (gamepad / joystick / digitiser BTN_*) event.
pub fn pop_button() -> Option<ButtonEvent> {
    let ev = BUTTON_RING.lock().as_ref().and_then(|r| r.pop())?;
    if let InputEvent::Button(b) = ev {
        Some(b)
    } else {
        None
    }
}

/// Generic pop — drains any non-empty ring, no ordering guarantee
/// across classes. Kept for the boot-time diagnostic panel + a
/// small set of tests; new consumers should use the typed
/// variants. Order: Key → Pointer → Scroll → Absolute → Touch →
/// AsciiByte.
pub fn pop_global() -> Option<InputEvent> {
    for ring in all_rings() {
        if let Some(ev) = ring.lock().as_ref().and_then(|r| r.pop()) {
            return Some(ev);
        }
    }
    None
}

/// Snapshot of pushed/dropped counters across all rings, useful
/// for smoke tests + the FB status panel.
pub fn global_counters() -> (u64, u64) {
    let mut pushed = 0u64;
    let mut dropped = 0u64;
    for ring in all_rings() {
        if let Some(r) = ring.lock().as_ref() {
            pushed = pushed.saturating_add(r.pushed());
            dropped = dropped.saturating_add(r.dropped());
        }
    }
    (pushed, dropped)
}

/// Test-only: reset every per-class ring.
#[doc(hidden)]
pub fn __reset_global_ring_for_test() {
    for ring in all_rings() {
        if let Some(r) = ring.lock().as_ref() {
            r.__reset_for_test();
        }
    }
}

/// Diagnostic flag set by the i8042 driver after `install_isa_irq`
/// returns — `true` iff IRQ 1 routed cleanly, `false` if init
/// succeeded but no IRQ vector / IOAPIC line was wired up. The FB
/// status panel renders this so the user can see "kbd-irq=routed"
/// vs "kbd-irq=FAIL" without serial / scrollback. Lives here in
/// the lower `narf-input` crate (vs `narf-input-driver`) to break
/// the dep cycle that would otherwise prevent `narf-fb` from
/// reading it.
pub static I8042_KBD_IRQ_ROUTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
pub static I8042_MOUSE_IRQ_ROUTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// Set by the i8042 driver to `true` once `init()` returns Ok at
/// least once. `false` here + `(no failure)` for IRQ-routed flags
/// means `i8042::init()` never even succeeded — likely no PS/2
/// controller on the system (modern laptops with no legacy KBC).
pub static I8042_KBD_INIT_OK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
pub static I8042_MOUSE_INIT_OK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// True iff the keyboard channel acknowledged `0xF4 ENABLE_SCANNING`.
/// `INIT_OK` says the controller is alive; `SCANNING_OK` says the
/// keyboard itself is wired and now generating scancodes. Phoenix /
/// Renoir EC PS/2 emulation: controller passes self-test instantly
/// (init=ok) but keyboard reset replies take tens of ms — if the
/// driver's init busy-spin is too short, `SCANNING_OK` stays false
/// and the panel shows "scan=FAIL" even when "init=ok irq=routed".
pub static I8042_KBD_SCANNING_OK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// Allocated x86 IDT vector for IRQ 1 (kbd) and IRQ 12 (aux), or
/// `0` if `install_isa_irq` was never called or failed. Surfaced
/// publicly so the FB status panel can read
/// `narf_interrupts::fire_count(vector)` and distinguish "IRQ
/// fired but our handler dropped it" from "EC never raised IRQ
/// after init." Lives in `narf-input` (the lower-level shared
/// crate) so `narf-fb` can read it without a dependency cycle
/// through `narf-input-driver` → `narf-fb` (cursor pump).
pub static I8042_KBD_IRQ_VECTOR: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);
pub static I8042_MOUSE_IRQ_VECTOR: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);
/// IRQ-12 bump count + completed-packet count from
/// `drivers/input/src/i8042_mouse.rs::on_irq12`. Use to
/// diagnose "touchpad isn't moving the cursor": if IRQs stay 0,
/// the controller never fires (re-check AUX init / IRQ routing).
/// If IRQs grow but packets stay 0, packets are getting dropped
/// by the sync-bit guard (re-sync issue).
pub static I8042_MOUSE_IRQ_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
pub static I8042_MOUSE_PACKET_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
/// Per-class ring activity counters — increment on every
/// successful `push_global` so the panel can show whether kbd
/// IRQs are firing without requiring serial. If kbd-pushes stays
/// at 0 across keystroke attempts, IRQ 1 isn't firing.
pub static KEY_PUSH_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Counts pop_key() successes. Distinguishes "DevConsole reads
/// are consuming events" (pop>0) from "no consumer ever ran"
/// (pop=0). Combined with KEY_PUSH_COUNT, tells you whether the
/// blockage is on the producer side (no IRQ, no decode) or the
/// consumer side (shell not reading / read returning nothing).
pub static KEY_POP_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Same shape for `AsciiByte` events (serial / UART RX). 0 means
/// no serial bytes ever reached the input ring — useful when
/// debugging "shell isn't seeing typed input" on QEMU.
pub static ASCII_PUSH_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Counts pop_ascii_byte successes — distinguishes "bytes
/// pushed but never consumed" (push>pop, possible reader bug)
/// from "no bytes ever pushed" (push=0).
pub static ASCII_POP_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Stage::Subsys initcall: install all per-class rings before any
/// input driver pushes. Capacity 256 per ring — enough for
/// keyboard burst latency, small enough that a runaway producer
/// doesn't eat unbounded heap.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "input-event-ring", || {
        init_global_ring(256);
        InitResult::Ok
    });
}

pub mod goodix;
pub mod rmi4;

// ── evdev event-routing layer ─────────────────────────────────────────────────

/// Per-device event queue, capability bitmap, Reader, and Router.
/// The evdev layer sits between drivers (which call `evdev::ROUTER.dispatch`)
/// and consumers (which call `evdev::ROUTER.open_reader`).
pub mod evdev;

/// Userspace synthetic input device (analogous to Linux uinput).
pub mod uinput;

/// `EventSink` is the driver-facing trait.  Drivers that have a
/// `DeviceNode` call `node.dispatch()` directly, but the trait
/// provides a uniform interface for tests and future virtual-device
/// shims that don't need a full `DeviceNode`.
///
/// Linux analogue: `input_dev::event` callback pointer
/// (`include/linux/input.h struct input_dev::event`).
pub trait EventSink: Send + Sync {
    /// Deliver one evdev event. The sink is responsible for any
    /// queueing, fan-out, and waking of blocked readers.
    fn dispatch(&self, ev: evdev::EvdevEvent) -> bool;
}

// Blanket impl so Arc<DeviceNode> can be used as an EventSink.
impl EventSink for alloc::sync::Arc<evdev::DeviceNode> {
    fn dispatch(&self, ev: evdev::EvdevEvent) -> bool {
        evdev::DeviceNode::dispatch(self, ev)
    }
}

// Per-crate smoke tests register against `narf-kernel-test` and
// land in the same `narf.tests` ELF section as the rest of the
// suite.
mod tests;
