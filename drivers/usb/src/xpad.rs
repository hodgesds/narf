// SPDX-License-Identifier: GPL-2.0-or-later
//! Xbox gamepad driver (xpad) — pure packet-decode and event-emit.
//!
//! ## Scope
//!
//! Covers device-ID matching, per-type packet decode, force-feedback
//! rumble encoding, and LED control for Xbox classic / 360 / 360
//! Wireless / Xbox One controllers.  Input events are emitted onto the
//! `narf_input` global ring.
//!
//! This file is deliberately self-contained; it owns no async tasks or
//! USB transfer machinery.  The supervisor in `lib.rs` will feed raw
//! interrupt-IN payloads to [`process_packet`] once hot-plug support
//! lands.  All packet-level logic is exercised today through the unit
//! smoke tests at the bottom of this file.
//!
//! ## References
//!
//! Linux `drivers/input/joystick/xpad.c` (GPL-2.0-or-later), adapted
//! under NARF's GPL-2.0-or-later licence:
//!   - device table:          xpad.c:133–432
//!   - Xbox classic decode:   xpad.c:820–879  (`xpad_process_packet`)
//!   - Xbox 360 decode:       xpad.c:891–979  (`xpad360_process_packet`)
//!   - 360W decode:           xpad.c:1020–1044 (`xpad360w_process_packet`)
//!   - Xbox One decode:       xpad.c:1055–1225 (`xpadone_process_packet`)
//!   - Xbox One init packets: xpad.c:733–748
//!   - Force-feedback:        xpad.c:1550–1633 (`xpad_play_effect`)
//!   - LED control:           xpad.c:1681–1718 (`xpad_send_led_command`)

#![allow(dead_code)]

use narf_input::{abs, btn, push_global, AbsoluteEvent, ButtonEvent, InputEvent};

// ── Mapping flags (xpad.c:80–86) ─────────────────────────────────────

/// Map D-Pad to buttons instead of the default ABS_HAT0X/Y axes.
/// Required for DDR dance pads and arcade sticks.
pub const MAP_DPAD_TO_BUTTONS: u8 = 1 << 0;
/// Map trigger axes (LT/RT) to digital buttons (BTN_TL2/TR2) instead
/// of ABS_Z/RZ.
pub const MAP_TRIGGERS_TO_BUTTONS: u8 = 1 << 1;
/// Do not report stick axes (sticks to null / dance-pad mode).
pub const MAP_STICKS_TO_NULL: u8 = 1 << 2;
/// Device has a Share/Record button (Xbox Series controllers, some
/// third-party).
pub const MAP_SHARE_BUTTON: u8 = 1 << 3;
/// Device has Elite paddle buttons (Elite Series 1 / 2).
pub const MAP_PADDLES: u8 = 1 << 4;
/// Device has a Profile button (Adaptive Controller).
pub const MAP_PROFILE_BUTTON: u8 = 1 << 5;
/// Share button is at a different byte offset in the One report.
pub const MAP_SHARE_OFFSET: u8 = 1 << 6;

/// Convenience aggregate: typical dance-pad mapping flags.
pub const DANCEPAD_MAP_CONFIG: u8 =
    MAP_DPAD_TO_BUTTONS | MAP_TRIGGERS_TO_BUTTONS | MAP_STICKS_TO_NULL;

// ── Controller type (xpad.c:91–95) ───────────────────────────────────

/// Original Xbox controller (analog ABXY + Black/White).
pub const XTYPE_XBOX: u8 = 0;
/// Xbox 360 wired controller.
pub const XTYPE_XBOX360: u8 = 1;
/// Xbox 360 Wireless Receiver (4-slot dongle).
pub const XTYPE_XBOX360W: u8 = 2;
/// Xbox One / Series controller.
pub const XTYPE_XBOXONE: u8 = 3;
/// Unknown / fallback.
pub const XTYPE_UNKNOWN: u8 = 4;

// ── USB interface matching constants ─────────────────────────────────

/// USB class 0xFF — Vendor Specific.  All Xbox controllers use this.
pub const USB_CLASS_VENDOR_SPEC: u8 = 0xFF;
/// Xbox 360 interface subclass (xpad.c:501 comment "93").
pub const XBOX360_INTF_SUBCLASS: u8 = 93;
/// Xbox 360 wired protocol byte (xpad.c:503).
pub const XBOX360_INTF_PROTOCOL_WIRED: u8 = 1;
/// Xbox 360 wireless protocol byte (xpad.c:504, "129").
pub const XBOX360_INTF_PROTOCOL_WIRELESS: u8 = 129;
/// Xbox One interface subclass (xpad.c:508 comment "71").
pub const XBOXONE_INTF_SUBCLASS: u8 = 71;
/// Xbox One interface protocol byte (xpad.c:509, "208").
pub const XBOXONE_INTF_PROTOCOL: u8 = 208;

// ── GIP (Game Input Protocol) command codes (xpad.c:615–624) ─────────

pub const GIP_CMD_ACK: u8 = 0x01;
pub const GIP_CMD_ANNOUNCE: u8 = 0x02;
pub const GIP_CMD_IDENTIFY: u8 = 0x04;
pub const GIP_CMD_POWER: u8 = 0x05;
pub const GIP_CMD_AUTHENTICATE: u8 = 0x06;
pub const GIP_CMD_VIRTUAL_KEY: u8 = 0x07;
pub const GIP_CMD_RUMBLE: u8 = 0x09;
pub const GIP_CMD_LED: u8 = 0x0a;
pub const GIP_CMD_INPUT: u8 = 0x20;

pub const GIP_SEQ0: u8 = 0x00;
pub const GIP_OPT_ACK: u8 = 0x10;
pub const GIP_OPT_INTERNAL: u8 = 0x20;
pub const GIP_PWR_ON: u8 = 0x00;
pub const GIP_LED_ON: u8 = 0x01;
pub const GIP_MOTOR_R: u8 = 1 << 0;
pub const GIP_MOTOR_L: u8 = 1 << 1;
pub const GIP_MOTOR_RT: u8 = 1 << 2;
pub const GIP_MOTOR_LT: u8 = 1 << 3;
pub const GIP_MOTOR_ALL: u8 = GIP_MOTOR_R | GIP_MOTOR_L | GIP_MOTOR_RT | GIP_MOTOR_LT;

// ── Device-ID table ───────────────────────────────────────────────────

/// Per-device metadata: name, mapping flags, controller type.
/// Mirrors Linux `struct xpad_device` (xpad.c:126–133).
#[derive(Copy, Clone, Debug)]
pub struct XpadDevice {
    pub vendor: u16,
    pub product: u16,
    pub name: &'static str,
    pub mapping: u8,
    pub xtype: u8,
}

/// Device table ported from Linux xpad.c:133–432.
/// 100 entries covering Microsoft, Logitech, Mad Catz, Hori, PowerA,
/// PDP, 8BitDo, Razer, SteelSeries, Thrustmaster and many others.
pub static XPAD_DEVICES: &[XpadDevice] = &[
    // ── GPD / CRKD ────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x0079,
        product: 0x18d4,
        name: "GPD Win 2 X-Box Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0351,
        product: 0x1000,
        name: "CRKD LP Blueberry Burst Pro Edition",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0351,
        product: 0x2000,
        name: "CRKD LP Black Tribal Edition",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── Thrustmaster ─────────────────────────────────────────────
    XpadDevice {
        vendor: 0x044f,
        product: 0x0f00,
        name: "Thrustmaster Wheel",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x044f,
        product: 0x0f07,
        name: "Thrustmaster, Inc. Controller",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x044f,
        product: 0xb326,
        name: "Thrustmaster Gamepad GP XID",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── Microsoft Xbox classic ────────────────────────────────────
    XpadDevice {
        vendor: 0x045e,
        product: 0x0202,
        name: "Microsoft X-Box pad v1 (US)",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x0285,
        name: "Microsoft X-Box pad (Japan)",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x0287,
        name: "Microsoft Xbox Controller S",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x0288,
        name: "Microsoft Xbox Controller S v2",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x0289,
        name: "Microsoft X-Box pad v2 (US)",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    // ── Microsoft Xbox 360 ────────────────────────────────────────
    XpadDevice {
        vendor: 0x045e,
        product: 0x028e,
        name: "Microsoft X-Box 360 pad",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x028f,
        name: "Microsoft X-Box 360 pad v2",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── Microsoft Xbox 360 Wireless Receiver ─────────────────────
    XpadDevice {
        vendor: 0x045e,
        product: 0x0291,
        name: "Xbox 360 Wireless Receiver (XBOX)",
        mapping: MAP_DPAD_TO_BUTTONS,
        xtype: XTYPE_XBOX360W,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x02a9,
        name: "Xbox 360 Wireless Receiver (Unofficial)",
        mapping: MAP_DPAD_TO_BUTTONS,
        xtype: XTYPE_XBOX360W,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x0719,
        name: "Xbox 360 Wireless Receiver",
        mapping: MAP_DPAD_TO_BUTTONS,
        xtype: XTYPE_XBOX360W,
    },
    // ── Microsoft Xbox One ────────────────────────────────────────
    XpadDevice {
        vendor: 0x045e,
        product: 0x02d1,
        name: "Microsoft X-Box One pad",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x02dd,
        name: "Microsoft X-Box One pad (FW 2015)",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x02e3,
        name: "Microsoft X-Box One Elite pad",
        mapping: MAP_PADDLES,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x02ea,
        name: "Microsoft X-Box One S pad",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x0b00,
        name: "Microsoft X-Box One Elite 2 pad",
        mapping: MAP_PADDLES,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x0b0a,
        name: "Microsoft X-Box Adaptive Controller",
        mapping: MAP_PROFILE_BUTTON,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x045e,
        product: 0x0b12,
        name: "Microsoft Xbox Series S|X Controller",
        mapping: MAP_SHARE_BUTTON | MAP_SHARE_OFFSET,
        xtype: XTYPE_XBOXONE,
    },
    // ── Logitech ─────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x046d,
        product: 0xc21d,
        name: "Logitech Gamepad F310",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x046d,
        product: 0xc21e,
        name: "Logitech Gamepad F510",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x046d,
        product: 0xc21f,
        name: "Logitech Gamepad F710",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x046d,
        product: 0xc242,
        name: "Logitech Chillstream Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x046d,
        product: 0xca84,
        name: "Logitech Xbox Cordless Controller",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x046d,
        product: 0xca88,
        name: "Logitech Compact Controller for Xbox",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    // ── Mad Catz ─────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x0738,
        product: 0x4503,
        name: "Mad Catz Racing Wheel",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4516,
        name: "Mad Catz Control Pad",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4520,
        name: "Mad Catz Control Pad Pro",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4540,
        name: "Mad Catz Beat Pad",
        mapping: MAP_DPAD_TO_BUTTONS,
        xtype: XTYPE_XBOX,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4716,
        name: "Mad Catz Wired Xbox 360 Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4718,
        name: "Mad Catz Street Fighter IV FightStick SE",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4726,
        name: "Mad Catz Xbox 360 Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4728,
        name: "Mad Catz Street Fighter IV FightPad",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4758,
        name: "Mad Catz Arcade Game Stick",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0x4a01,
        name: "Mad Catz FightStick TE 2",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0xb726,
        name: "Mad Catz Xbox controller - MW2",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0738,
        product: 0xbeef,
        name: "Mad Catz JOYTECH NEO SE Advanced GamePad",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── PDP / Afterglow ──────────────────────────────────────────
    XpadDevice {
        vendor: 0x0e6f,
        product: 0x0113,
        name: "Afterglow AX.1 Gamepad for Xbox 360",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0e6f,
        product: 0x0131,
        name: "PDP EA Sports Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0e6f,
        product: 0x013a,
        name: "PDP Xbox One Controller",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0e6f,
        product: 0x0146,
        name: "Rock Candy Wired Controller for Xbox One",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0e6f,
        product: 0x015c,
        name: "PDP Xbox One Arcade Stick",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0e6f,
        product: 0x0161,
        name: "PDP Xbox One Controller",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0e6f,
        product: 0x02a4,
        name: "PDP Wired Controller for Xbox One - Stealth Series",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0e6f,
        product: 0x02a6,
        name: "PDP Wired Controller for Xbox One - Camo Series",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    // ── Hori ─────────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x0f0d,
        product: 0x000a,
        name: "Hori Co. DOA4 FightStick",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0f0d,
        product: 0x000d,
        name: "Hori Fighting Stick EX2",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0f0d,
        product: 0x0016,
        name: "Hori Real Arcade Pro.EX",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0f0d,
        product: 0x0063,
        name: "Hori Real Arcade Pro Hayabusa (USA) Xbox One",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0f0d,
        product: 0x0067,
        name: "HORIPAD ONE",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x0f0d,
        product: 0x0078,
        name: "Hori Real Arcade Pro V Kai Xbox One",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOXONE,
    },
    // ── SteelSeries ──────────────────────────────────────────────
    XpadDevice {
        vendor: 0x1038,
        product: 0x1430,
        name: "SteelSeries Stratus Duo",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x1038,
        product: 0x1431,
        name: "SteelSeries Stratus Duo",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── Razer ────────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x1532,
        product: 0x0a00,
        name: "Razer Atrox Arcade Stick",
        mapping: MAP_TRIGGERS_TO_BUTTONS,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x1532,
        product: 0x0a03,
        name: "Razer Wildcat",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x1532,
        product: 0x0a29,
        name: "Razer Wolverine V2",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x1689,
        product: 0xfd00,
        name: "Razer Onza Tournament Edition",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x1689,
        product: 0xfd01,
        name: "Razer Onza Classic Edition",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x1689,
        product: 0xfe00,
        name: "Razer Sabertooth",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── PowerA ───────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x20d6,
        product: 0x2001,
        name: "BDA Xbox Series X Wired Controller",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x20d6,
        product: 0x2009,
        name: "PowerA Enhanced Wired Controller for Xbox Series X|S",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x20d6,
        product: 0x2064,
        name: "PowerA Wired Controller for Xbox",
        mapping: MAP_SHARE_BUTTON,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x20d6,
        product: 0x281f,
        name: "PowerA Wired Controller For Xbox 360",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x24c6,
        product: 0x5300,
        name: "PowerA MINI PROEX Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x24c6,
        product: 0x531a,
        name: "PowerA Pro Ex",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x24c6,
        product: 0x541a,
        name: "PowerA Xbox One Mini Wired Controller",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x24c6,
        product: 0x543a,
        name: "PowerA Xbox One wired controller",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x24c6,
        product: 0x551a,
        name: "PowerA FUSION Pro Controller",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    // ── 8BitDo ───────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x2dc8,
        product: 0x2000,
        name: "8BitDo Pro 2 Wired Controller for Xbox",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x2dc8,
        product: 0x200f,
        name: "8BitDo Ultimate 3-mode Controller for Xbox",
        mapping: MAP_SHARE_BUTTON,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x2dc8,
        product: 0x3106,
        name: "8BitDo Ultimate Wireless / Pro 2 Wired Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x2dc8,
        product: 0x6001,
        name: "8BitDo SN30 Pro",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── Snakebyte ────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x294b,
        product: 0x3303,
        name: "Snakebyte GAMEPAD BASE X",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x294b,
        product: 0x3404,
        name: "Snakebyte GAMEPAD RGB X",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    // ── Harmonix (Rock Band) ──────────────────────────────────────
    XpadDevice {
        vendor: 0x1bad,
        product: 0x0002,
        name: "Harmonix Rock Band Guitar",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x1bad,
        product: 0x0003,
        name: "Harmonix Rock Band Drumkit",
        mapping: MAP_DPAD_TO_BUTTONS,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x1bad,
        product: 0xf016,
        name: "Mad Catz Xbox 360 Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x1bad,
        product: 0xf900,
        name: "Harmonix Xbox 360 Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── BigBen / Nacon ───────────────────────────────────────────
    XpadDevice {
        vendor: 0x146b,
        product: 0x0601,
        name: "BigBen Interactive XBOX 360 Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x3285,
        product: 0x0603,
        name: "Nacon Pro Compact controller for Xbox",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x3285,
        product: 0x0607,
        name: "Nacon GC-100",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x3285,
        product: 0x0663,
        name: "Nacon Evol-X",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    // ── Turtle Beach ─────────────────────────────────────────────
    XpadDevice {
        vendor: 0x10f5,
        product: 0x7005,
        name: "Turtle Beach Recon Controller",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x10f5,
        product: 0x7008,
        name: "Turtle Beach Recon Controller",
        mapping: MAP_SHARE_BUTTON,
        xtype: XTYPE_XBOXONE,
    },
    // ── Hyperkin ─────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x2e24,
        product: 0x0652,
        name: "Hyperkin Duke X-Box One pad",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x2e24,
        product: 0x1688,
        name: "Hyperkin X91 X-Box One pad",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    // ── Lenovo / ASUS / Amazon ────────────────────────────────────
    XpadDevice {
        vendor: 0x17ef,
        product: 0x6182,
        name: "Lenovo Legion Controller for Windows",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x0b05,
        product: 0x1a38,
        name: "ASUS ROG RAIKIRI",
        mapping: MAP_SHARE_BUTTON,
        xtype: XTYPE_XBOXONE,
    },
    XpadDevice {
        vendor: 0x1949,
        product: 0x041a,
        name: "Amazon Game Controller",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── GameSir ──────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x3537,
        product: 0x1004,
        name: "GameSir T4 Kaleid",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x3537,
        product: 0x1010,
        name: "GameSir G7 SE",
        mapping: 0,
        xtype: XTYPE_XBOXONE,
    },
    // ── Wooting ──────────────────────────────────────────────────
    XpadDevice {
        vendor: 0x31e3,
        product: 0x1100,
        name: "Wooting One",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    XpadDevice {
        vendor: 0x31e3,
        product: 0x1200,
        name: "Wooting Two",
        mapping: 0,
        xtype: XTYPE_XBOX360,
    },
    // ── Generic fallback ─────────────────────────────────────────
    XpadDevice {
        vendor: 0xffff,
        product: 0xffff,
        name: "Chinese-made Xbox Controller",
        mapping: 0,
        xtype: XTYPE_XBOX,
    },
];

/// Look up a device entry by VID/PID.  Returns the first match or the
/// last fallback entry.
pub fn lookup_device(vendor: u16, product: u16) -> &'static XpadDevice {
    for dev in XPAD_DEVICES {
        if dev.vendor == vendor && dev.product == product {
            return dev;
        }
    }
    // Fallback: last entry is the generic controller.
    &XPAD_DEVICES[XPAD_DEVICES.len() - 1]
}

/// Match an interface descriptor triple to determine the xtype.
/// Returns `None` if the interface is not an Xbox controller.
///
/// Ref: xpad.c:497–515.
pub fn match_interface(class: u8, subclass: u8, protocol: u8) -> Option<u8> {
    if class != USB_CLASS_VENDOR_SPEC {
        return None;
    }
    if subclass == XBOX360_INTF_SUBCLASS
        && (protocol == XBOX360_INTF_PROTOCOL_WIRED || protocol == XBOX360_INTF_PROTOCOL_WIRELESS)
    {
        return Some(if protocol == XBOX360_INTF_PROTOCOL_WIRELESS {
            XTYPE_XBOX360W
        } else {
            XTYPE_XBOX360
        });
    }
    if subclass == XBOXONE_INTF_SUBCLASS && protocol == XBOXONE_INTF_PROTOCOL {
        return Some(XTYPE_XBOXONE);
    }
    None
}

// ── Xbox One init-packet table (xpad.c:733–748) ───────────────────────

/// One entry in the Xbox One start-up sequence.
#[derive(Copy, Clone, Debug)]
pub struct XboxOneInitPacket {
    /// VID filter: 0x0000 = wildcard (send to every device).
    pub vendor: u16,
    /// PID filter: 0x0000 = wildcard.
    pub product: u16,
    /// Raw packet bytes.
    pub data: &'static [u8],
}

// Static payload arrays (xpad.c:657–724).
static XBOXONE_POWER_ON: &[u8] = &[GIP_CMD_POWER, GIP_OPT_INTERNAL, GIP_SEQ0, 0x01, GIP_PWR_ON];
static XBOXONE_S_INIT: &[u8] = &[GIP_CMD_POWER, GIP_OPT_INTERNAL, GIP_SEQ0, 0x0f, 0x06];
static EXTRA_INPUT_PACKET_INIT: &[u8] = &[0x4d, 0x10, 0x01, 0x02, 0x07, 0x00];
static XBOXONE_HORI_ACK_ID: &[u8] = &[
    GIP_CMD_ACK,
    GIP_OPT_INTERNAL,
    GIP_SEQ0,
    0x09,
    0x00,
    GIP_CMD_IDENTIFY,
    GIP_OPT_INTERNAL,
    0x3a,
    0x00,
    0x00,
    0x00,
    0x80,
    0x00,
];
static XBOXONE_LED_ON: &[u8] = &[
    GIP_CMD_LED,
    GIP_OPT_INTERNAL,
    GIP_SEQ0,
    0x03,
    0x00,
    GIP_LED_ON,
    0x14,
];
static XBOXONE_AUTH_DONE: &[u8] = &[
    GIP_CMD_AUTHENTICATE,
    GIP_OPT_INTERNAL,
    GIP_SEQ0,
    0x02,
    0x01,
    0x00,
];
static XBOXONE_RUMBLEBEGIN_INIT: &[u8] = &[
    GIP_CMD_RUMBLE,
    0x00,
    GIP_SEQ0,
    0x09,
    0x00,
    GIP_MOTOR_ALL,
    0x00,
    0x00,
    0x1D,
    0x1D,
    0xFF,
    0x00,
    0x00,
];
static XBOXONE_RUMBLEEND_INIT: &[u8] = &[
    GIP_CMD_RUMBLE,
    0x00,
    GIP_SEQ0,
    0x09,
    0x00,
    GIP_MOTOR_ALL,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
];

/// Ordered init-packet sequence, xpad.c:733–748.
pub static XBOXONE_INIT_PACKETS: &[XboxOneInitPacket] = &[
    XboxOneInitPacket {
        vendor: 0x0e6f,
        product: 0x0165,
        data: XBOXONE_HORI_ACK_ID,
    },
    XboxOneInitPacket {
        vendor: 0x0f0d,
        product: 0x0067,
        data: XBOXONE_HORI_ACK_ID,
    },
    XboxOneInitPacket {
        vendor: 0x0000,
        product: 0x0000,
        data: XBOXONE_POWER_ON,
    },
    XboxOneInitPacket {
        vendor: 0x045e,
        product: 0x02ea,
        data: XBOXONE_S_INIT,
    },
    XboxOneInitPacket {
        vendor: 0x045e,
        product: 0x0b00,
        data: XBOXONE_S_INIT,
    },
    XboxOneInitPacket {
        vendor: 0x045e,
        product: 0x0b00,
        data: EXTRA_INPUT_PACKET_INIT,
    },
    XboxOneInitPacket {
        vendor: 0x0000,
        product: 0x0000,
        data: XBOXONE_LED_ON,
    },
    XboxOneInitPacket {
        vendor: 0x0000,
        product: 0x0000,
        data: XBOXONE_AUTH_DONE,
    },
    XboxOneInitPacket {
        vendor: 0x24c6,
        product: 0x541a,
        data: XBOXONE_RUMBLEBEGIN_INIT,
    },
    XboxOneInitPacket {
        vendor: 0x24c6,
        product: 0x542a,
        data: XBOXONE_RUMBLEBEGIN_INIT,
    },
    XboxOneInitPacket {
        vendor: 0x24c6,
        product: 0x543a,
        data: XBOXONE_RUMBLEBEGIN_INIT,
    },
    XboxOneInitPacket {
        vendor: 0x24c6,
        product: 0x541a,
        data: XBOXONE_RUMBLEEND_INIT,
    },
    XboxOneInitPacket {
        vendor: 0x24c6,
        product: 0x542a,
        data: XBOXONE_RUMBLEEND_INIT,
    },
    XboxOneInitPacket {
        vendor: 0x24c6,
        product: 0x543a,
        data: XBOXONE_RUMBLEEND_INIT,
    },
];

// ── Wireless receiver slot state ──────────────────────────────────────

/// Per-slot connection state for the 4-channel Xbox 360 Wireless
/// Receiver.  Up to 4 controllers can be paired simultaneously.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WirelessSlotState {
    /// No controller associated.
    Absent,
    /// Controller is present and sending data.
    Present,
}

/// Runtime state for one Wireless Receiver dongle.
#[derive(Debug)]
pub struct WirelessReceiver {
    /// Presence flag per slot (slot 0..3).
    pub slots: [WirelessSlotState; 4],
}

impl WirelessReceiver {
    /// Create a new receiver with all slots absent.
    pub const fn new() -> Self {
        Self {
            slots: [WirelessSlotState::Absent; 4],
        }
    }

    /// Update slot presence.  Returns `true` if the state changed.
    pub fn update_presence(&mut self, slot: usize, present: bool) -> bool {
        if slot >= 4 {
            return false;
        }
        let new = if present {
            WirelessSlotState::Present
        } else {
            WirelessSlotState::Absent
        };
        if self.slots[slot] == new {
            return false;
        }
        self.slots[slot] = new;
        true
    }
}

// ── Packet decode ─────────────────────────────────────────────────────

/// Emit a button event onto the global input ring.
#[inline(always)]
fn emit_btn(code: u16, pressed: bool) {
    push_global(InputEvent::Button(ButtonEvent { code, pressed }));
}

/// Emit an absolute-axis event onto the global input ring.
#[inline(always)]
fn emit_abs(axis: u16, value: i32) {
    push_global(InputEvent::Absolute(AbsoluteEvent { axis, value }));
}

/// Read a little-endian i16 from a byte slice at the given offset.
#[inline(always)]
fn read_le_i16(data: &[u8], offset: usize) -> i16 {
    let lo = data[offset] as u16;
    let hi = data[offset + 1] as u16;
    ((hi << 8) | lo) as i16
}

/// Read a little-endian u16 from a byte slice at the given offset.
#[inline(always)]
fn read_le_u16(data: &[u8], offset: usize) -> u16 {
    let lo = data[offset] as u16;
    let hi = data[offset + 1] as u16;
    (hi << 8) | lo
}

/// Decode an original Xbox controller 20-byte report.
///
/// Ref: xpad.c:820–879 (`xpad_process_packet`).
///
/// Report layout (from http://euc.jp/periphs/xbox-controller.ja.html):
/// ```text
///   [0]     message type (ignored)
///   [1]     total length
///   [2]     digital buttons: bit0=DUp,1=DDn,2=DL,3=DR,4=Start,5=Back,6=ThL,7=ThR
///   [3..9]  reserved / type-specific
///   [10]    LT (analog trigger, u8)
///   [11]    RT (analog trigger, u8)
///   [12..13] LX (i16 LE)
///   [14..15] LY (i16 LE, inverted)
///   [16..17] RX (i16 LE)
///   [18..19] RY (i16 LE, inverted)
///   [4] A, [5] B, [6] X, [7] Y (analog 0–255 → treated as digital)
///   [8] Black, [9] White (analog)
/// ```
pub fn xpad_process_packet(data: &[u8], mapping: u8) {
    if data.len() < 20 {
        return;
    }

    // Sticks — xpad.c:826–836
    if mapping & MAP_STICKS_TO_NULL == 0 {
        emit_abs(abs::ABS_X, read_le_i16(data, 12) as i32);
        emit_abs(abs::ABS_Y, !(read_le_i16(data, 14) as i32)); // inverted
        emit_abs(abs::ABS_RX, read_le_i16(data, 16) as i32);
        emit_abs(abs::ABS_RY, !(read_le_i16(data, 18) as i32)); // inverted
    }

    // Triggers — xpad.c:839–845
    if mapping & MAP_TRIGGERS_TO_BUTTONS != 0 {
        emit_btn(btn::BTN_TL2, data[10] != 0);
        emit_btn(btn::BTN_TR2, data[11] != 0);
    } else {
        emit_abs(abs::ABS_Z, data[10] as i32);
        emit_abs(abs::ABS_RZ, data[11] as i32);
    }

    // D-Pad — xpad.c:848–858
    if mapping & MAP_DPAD_TO_BUTTONS != 0 {
        emit_btn(btn::BTN_DPAD_LEFT, data[2] & (1 << 2) != 0);
        emit_btn(btn::BTN_DPAD_RIGHT, data[2] & (1 << 3) != 0);
        emit_btn(btn::BTN_DPAD_UP, data[2] & (1 << 0) != 0);
        emit_btn(btn::BTN_DPAD_DOWN, data[2] & (1 << 1) != 0);
    } else {
        let hat_x = (data[2] & 0x08 != 0) as i32 - (data[2] & 0x04 != 0) as i32;
        let hat_y = (data[2] & 0x02 != 0) as i32 - (data[2] & 0x01 != 0) as i32;
        emit_abs(abs::ABS_HAT0X, hat_x);
        emit_abs(abs::ABS_HAT0Y, hat_y);
    }

    // Start / Back / Thumb — xpad.c:862–865
    emit_btn(btn::BTN_START, data[2] & (1 << 4) != 0);
    emit_btn(btn::BTN_SELECT, data[2] & (1 << 5) != 0);
    emit_btn(btn::BTN_THUMBL, data[2] & (1 << 6) != 0);
    emit_btn(btn::BTN_THUMBR, data[2] & (1 << 7) != 0);

    // A/B/X/Y (analog treated as digital) — xpad.c:868–875
    emit_btn(btn::BTN_SOUTH, data[4] != 0); // A
    emit_btn(btn::BTN_EAST, data[5] != 0); // B
    emit_btn(btn::BTN_NORTH, data[6] != 0); // X
    emit_btn(btn::BTN_WEST, data[7] != 0); // Y

    // Black / White — xpad.c:873–875
    emit_btn(btn::BTN_C, data[8] != 0); // Black
    emit_btn(btn::BTN_Z, data[9] != 0); // White
}

/// Decode an Xbox 360 wired controller 20-byte report.
///
/// Ref: xpad.c:891–979 (`xpad360_process_packet`).
///
/// Report layout (http://www.free60.org/wiki/Gamepad):
/// ```text
///   [0]     message type — must be 0x00; skip if != 0
///   [1]     message length (0x14 = 20)
///   [2]     digital buttons low:  bit0=DUp,1=DDn,2=DL,3=DR,4=Start,5=Back,6=ThL,7=ThR
///   [3]     digital buttons high: bit0=LB,1=RB,2=Guide,3=0,4=A,5=B,6=X,7=Y
///   [4]     LT (trigger, u8)
///   [5]     RT (trigger, u8)
///   [6..7]  LX (i16 LE)
///   [8..9]  LY (i16 LE, inverted)
///   [10..11] RX (i16 LE)
///   [12..13] RY (i16 LE, inverted)
///   [14..19] reserved
/// ```
pub fn xpad360_process_packet(data: &[u8], mapping: u8, is_wireless: bool) {
    if data.len() < 14 {
        return;
    }
    // Valid pad data check — xpad.c:895
    if data[0] != 0x00 {
        return;
    }

    // D-Pad — xpad.c:899–918
    if mapping & MAP_DPAD_TO_BUTTONS != 0 {
        emit_btn(btn::BTN_DPAD_LEFT, data[2] & (1 << 2) != 0);
        emit_btn(btn::BTN_DPAD_RIGHT, data[2] & (1 << 3) != 0);
        emit_btn(btn::BTN_DPAD_UP, data[2] & (1 << 0) != 0);
        emit_btn(btn::BTN_DPAD_DOWN, data[2] & (1 << 1) != 0);
    }
    // Always emit hat for 360W or when not dpad-as-buttons — xpad.c:913–918
    if mapping & MAP_DPAD_TO_BUTTONS == 0 || is_wireless {
        let hat_x = (data[2] & 0x08 != 0) as i32 - (data[2] & 0x04 != 0) as i32;
        let hat_y = (data[2] & 0x02 != 0) as i32 - (data[2] & 0x01 != 0) as i32;
        emit_abs(abs::ABS_HAT0X, hat_x);
        emit_abs(abs::ABS_HAT0Y, hat_y);
    }

    // Start / Back / Thumb — xpad.c:922–927
    emit_btn(btn::BTN_START, data[2] & (1 << 4) != 0);
    emit_btn(btn::BTN_SELECT, data[2] & (1 << 5) != 0);
    emit_btn(btn::BTN_THUMBL, data[2] & (1 << 6) != 0);
    emit_btn(btn::BTN_THUMBR, data[2] & (1 << 7) != 0);

    // A/B/X/Y/LB/RB/Guide — xpad.c:930–936
    emit_btn(btn::BTN_SOUTH, data[3] & (1 << 4) != 0); // A
    emit_btn(btn::BTN_EAST, data[3] & (1 << 5) != 0); // B
    emit_btn(btn::BTN_NORTH, data[3] & (1 << 6) != 0); // X
    emit_btn(btn::BTN_WEST, data[3] & (1 << 7) != 0); // Y
    emit_btn(btn::BTN_TL, data[3] & (1 << 0) != 0); // LB
    emit_btn(btn::BTN_TR, data[3] & (1 << 1) != 0); // RB
    emit_btn(btn::BTN_MODE, data[3] & (1 << 2) != 0); // Guide

    // Sticks — xpad.c:938–950
    if mapping & MAP_STICKS_TO_NULL == 0 {
        emit_abs(abs::ABS_X, read_le_i16(data, 6) as i32);
        emit_abs(abs::ABS_Y, !read_le_i16(data, 8) as i32); // inverted
        emit_abs(abs::ABS_RX, read_le_i16(data, 10) as i32);
        emit_abs(abs::ABS_RY, !read_le_i16(data, 12) as i32); // inverted
    }

    // Triggers — xpad.c:953–959
    if mapping & MAP_TRIGGERS_TO_BUTTONS != 0 {
        emit_btn(btn::BTN_TL2, data[4] != 0);
        emit_btn(btn::BTN_TR2, data[5] != 0);
    } else {
        emit_abs(abs::ABS_Z, data[4] as i32);
        emit_abs(abs::ABS_RZ, data[5] as i32);
    }
}

/// Wireless receiver packet dispatch result.
#[derive(Debug, PartialEq, Eq)]
pub enum WirelessResult {
    /// Presence changed for the given slot.
    PresenceChanged { slot: usize, connected: bool },
    /// Input data decoded (calls `xpad360_process_packet` internally).
    DataDecoded,
    /// Packet was not valid data (pad data byte != 0x01).
    NotData,
}

/// Decode an Xbox 360 Wireless Receiver 32-byte packet.
///
/// The receiver serves 4 controller slots.  Linux dedicates one USB
/// interface per slot, so the slot index comes from the interface
/// number (0–3), not from the packet itself.
///
/// Ref: xpad.c:1006–1044 (`xpad360w_process_packet`).
///
/// Byte map:
/// ```text
///   [0] flags: bit3 = presence change
///   [1] status: bit7 = controller present, bit1 = pad data valid
///   [4..] inner 360-wired payload (passed to xpad360_process_packet)
/// ```
pub fn xpad360w_process_packet(
    receiver: &mut WirelessReceiver,
    slot: usize,
    data: &[u8],
    mapping: u8,
) -> WirelessResult {
    if data.len() < 2 {
        return WirelessResult::NotData;
    }

    // Presence change — xpad.c:1026–1033
    if data[0] & 0x08 != 0 {
        let present = data[1] & 0x80 != 0;
        receiver.update_presence(slot, present);
        return WirelessResult::PresenceChanged {
            slot,
            connected: present,
        };
    }

    // Valid pad data — xpad.c:1036–1043
    if data[1] != 0x01 {
        return WirelessResult::NotData;
    }

    if data.len() >= 4 + 14 {
        xpad360_process_packet(&data[4..], mapping, true);
    }
    WirelessResult::DataDecoded
}

/// Decode an Xbox One controller report.
///
/// Ref: xpad.c:1055–1225 (`xpadone_process_packet`).
///
/// The Xbox One uses the Game Input Protocol (GIP).  The primary input
/// report begins with `GIP_CMD_INPUT` (0x20).  A separate virtual-key
/// report (`GIP_CMD_VIRTUAL_KEY`, 0x07) carries the Guide button.
///
/// Input report layout (payload starting at offset 4):
/// ```text
///   data[4]  menu/view + A/B/X/Y buttons
///   data[5]  D-pad + LB/RB/ThL/ThR
///   data[6..7]  LT (u16 LE)
///   data[8..9]  RT (u16 LE)
///   data[10..11] LX (i16 LE)
///   data[12..13] LY (i16 LE, inverted)
///   data[14..15] RX (i16 LE)
///   data[16..17] RY (i16 LE, inverted)
/// ```
pub fn xpadone_process_packet(data: &[u8], len: usize, mapping: u8) {
    if data.is_empty() {
        return;
    }

    match data[0] {
        GIP_CMD_VIRTUAL_KEY => {
            // Guide button virtual-key report — xpad.c:1062–1073
            if data.len() >= 5 {
                emit_btn(btn::BTN_MODE, data[4] & 0x03 != 0);
            }
        }
        GIP_CMD_INPUT => {
            // Main input report — xpad.c:1103–1221
            if data.len() < 18 {
                return;
            }
            // Menu / View — xpad.c:1105–1106
            emit_btn(btn::BTN_START, data[4] & (1 << 2) != 0);
            emit_btn(btn::BTN_SELECT, data[4] & (1 << 3) != 0);

            // A / B / X / Y — xpad.c:1114–1118
            emit_btn(btn::BTN_SOUTH, data[4] & (1 << 4) != 0); // A
            emit_btn(btn::BTN_EAST, data[4] & (1 << 5) != 0); // B
            emit_btn(btn::BTN_NORTH, data[4] & (1 << 6) != 0); // X
            emit_btn(btn::BTN_WEST, data[4] & (1 << 7) != 0); // Y

            // D-Pad — xpad.c:1121–1132
            if mapping & MAP_DPAD_TO_BUTTONS != 0 {
                emit_btn(btn::BTN_DPAD_LEFT, data[5] & (1 << 2) != 0);
                emit_btn(btn::BTN_DPAD_RIGHT, data[5] & (1 << 3) != 0);
                emit_btn(btn::BTN_DPAD_UP, data[5] & (1 << 0) != 0);
                emit_btn(btn::BTN_DPAD_DOWN, data[5] & (1 << 1) != 0);
            } else {
                let hat_x = (data[5] & 0x08 != 0) as i32 - (data[5] & 0x04 != 0) as i32;
                let hat_y = (data[5] & 0x02 != 0) as i32 - (data[5] & 0x01 != 0) as i32;
                emit_abs(abs::ABS_HAT0X, hat_x);
                emit_abs(abs::ABS_HAT0Y, hat_y);
            }

            // LB / RB / ThL / ThR — xpad.c:1134–1140
            emit_btn(btn::BTN_TL, data[5] & (1 << 4) != 0);
            emit_btn(btn::BTN_TR, data[5] & (1 << 5) != 0);
            emit_btn(btn::BTN_THUMBL, data[5] & (1 << 6) != 0);
            emit_btn(btn::BTN_THUMBR, data[5] & (1 << 7) != 0);

            // Sticks — xpad.c:1142–1154
            if mapping & MAP_STICKS_TO_NULL == 0 {
                emit_abs(abs::ABS_X, read_le_i16(data, 10) as i32);
                emit_abs(abs::ABS_Y, !read_le_i16(data, 12) as i32); // inverted
                emit_abs(abs::ABS_RX, read_le_i16(data, 14) as i32);
                emit_abs(abs::ABS_RY, !read_le_i16(data, 16) as i32); // inverted
            }

            // Triggers — xpad.c:1156–1167
            if mapping & MAP_TRIGGERS_TO_BUTTONS != 0 {
                emit_btn(btn::BTN_TL2, read_le_u16(data, 6) != 0);
                emit_btn(btn::BTN_TR2, read_le_u16(data, 8) != 0);
            } else {
                emit_abs(abs::ABS_Z, read_le_u16(data, 6) as i32);
                emit_abs(abs::ABS_RZ, read_le_u16(data, 8) as i32);
            }

            // Share button (Xbox Series / some third-party) — xpad.c:1107–1112
            if mapping & MAP_SHARE_BUTTON != 0 && len >= 27 {
                let off = if mapping & MAP_SHARE_OFFSET != 0 {
                    len.wrapping_sub(26)
                } else {
                    len.wrapping_sub(18)
                };
                if off < data.len() {
                    // KEY_RECORD = 0x1D3; emit as a button code
                    emit_btn(0x1D3, data[off] & 0x01 != 0);
                }
            }
        }
        _ => {} // Announce/Firmware/Auth handled at probe level
    }
}

/// Route a raw interrupt-IN payload to the correct per-xtype decoder.
///
/// `xtype` comes from the per-device `XpadDevice` entry or interface
/// matching at probe time.
pub fn process_packet(data: &[u8], xtype: u8, mapping: u8, len: usize) {
    match xtype {
        XTYPE_XBOX360 => xpad360_process_packet(data, mapping, false),
        XTYPE_XBOXONE => xpadone_process_packet(data, len, mapping),
        XTYPE_XBOX => xpad_process_packet(data, mapping),
        // XTYPE_XBOX360W is handled at a higher level (wireless demux)
        _ => {}
    }
}

// ── Force-feedback (rumble) encoding ─────────────────────────────────

/// Encoded rumble command ready to write to the interrupt-OUT endpoint.
#[derive(Copy, Clone, Debug)]
pub struct RumblePacket {
    pub data: [u8; 13],
    pub len: usize,
}

/// Encode a rumble command for the given xtype.
///
/// Ref: xpad.c:1550–1633 (`xpad_play_effect`).
///
/// `weak` and `strong` are 0–0xFFFF motor magnitudes (matching Linux
/// `ff_rumble.weak_magnitude` / `strong_magnitude`).  Returns `None`
/// for `XTYPE_UNKNOWN` or unrecognised xtypes.
pub fn encode_rumble(
    xtype: u8,
    strong: u16,
    weak: u16,
    odata_serial: &mut u8,
) -> Option<RumblePacket> {
    let mut pkt = RumblePacket {
        data: [0u8; 13],
        len: 0,
    };
    match xtype {
        XTYPE_XBOX => {
            // xpad.c:1567–1575
            pkt.data[0] = 0x00;
            pkt.data[1] = 0x06;
            pkt.data[2] = 0x00;
            pkt.data[3] = (strong / 256) as u8;
            pkt.data[4] = 0x00;
            pkt.data[5] = (weak / 256) as u8;
            pkt.len = 6;
        }
        XTYPE_XBOX360 => {
            // xpad.c:1577–1587
            pkt.data[0] = 0x00;
            pkt.data[1] = 0x08;
            pkt.data[2] = 0x00;
            pkt.data[3] = (strong / 256) as u8; // left actuator
            pkt.data[4] = (weak / 256) as u8; // right actuator
            pkt.data[5] = 0x00;
            pkt.data[6] = 0x00;
            pkt.data[7] = 0x00;
            pkt.len = 8;
        }
        XTYPE_XBOX360W => {
            // xpad.c:1590–1604
            pkt.data[0] = 0x00;
            pkt.data[1] = 0x01;
            pkt.data[2] = 0x0F;
            pkt.data[3] = 0xC0;
            pkt.data[4] = 0x00;
            pkt.data[5] = (strong / 256) as u8;
            pkt.data[6] = (weak / 256) as u8;
            // bytes 7–11 zero
            pkt.len = 12;
        }
        XTYPE_XBOXONE => {
            // xpad.c:1607–1623
            let seq = *odata_serial;
            *odata_serial = odata_serial.wrapping_add(1);
            pkt.data[0] = GIP_CMD_RUMBLE;
            pkt.data[1] = 0x00;
            pkt.data[2] = seq;
            pkt.data[3] = 0x09; // payload length (LEB128 of 9)
            pkt.data[4] = 0x00;
            pkt.data[5] = GIP_MOTOR_ALL;
            pkt.data[6] = 0x00; // left trigger motor
            pkt.data[7] = 0x00; // right trigger motor
            pkt.data[8] = (strong / 512) as u8; // left actuator
            pkt.data[9] = (weak / 512) as u8; // right actuator
            pkt.data[10] = 0xFF; // on period
            pkt.data[11] = 0x00; // off period
            pkt.data[12] = 0xFF; // repeat count
            pkt.len = 13;
        }
        _ => return None,
    }
    Some(pkt)
}

// ── LED control encoding ──────────────────────────────────────────────

/// Encoded LED command for the guide ring (Xbox 360 / 360W).
#[derive(Copy, Clone, Debug)]
pub struct LedPacket {
    pub data: [u8; 12],
    pub len: usize,
}

/// Encode an LED ring command for Xbox 360 (wired) or 360W (wireless).
///
/// `command` selects the LED pattern (0–15):
/// ```text
///  0 = off
///  2–5 = slot 1–4 blink then on
///  6–9 = slot 1–4 on
///  10  = rotate
/// ```
///
/// Ref: xpad.c:1681–1718 (`xpad_send_led_command`).
///
/// Returns `None` for xtypes that have no LED ring (Xbox classic /
/// Xbox One).
pub fn encode_led(xtype: u8, command: u8) -> Option<LedPacket> {
    let cmd = command % 16;
    let mut pkt = LedPacket {
        data: [0u8; 12],
        len: 0,
    };
    match xtype {
        XTYPE_XBOX360 => {
            // xpad.c:1692–1697
            pkt.data[0] = 0x01;
            pkt.data[1] = 0x03;
            pkt.data[2] = cmd;
            pkt.len = 3;
        }
        XTYPE_XBOX360W => {
            // xpad.c:1699–1713
            pkt.data[0] = 0x00;
            pkt.data[1] = 0x00;
            pkt.data[2] = 0x08;
            pkt.data[3] = 0x40 + cmd;
            // bytes 4–11 zero
            pkt.len = 12;
        }
        _ => return None,
    }
    Some(pkt)
}

// ── Init-packet iterator ──────────────────────────────────────────────

/// Iterate over the Xbox One init packets that apply to a given
/// device, in order.  The caller must send each returned slice to the
/// interrupt-OUT endpoint, inserting the current sequence number at
/// `data[2]` before transmit.
///
/// Ref: xpad.c:1274–1311 (`xpad_prepare_next_init_packet`).
pub fn iter_init_packets(
    vendor: u16,
    product: u16,
) -> impl Iterator<Item = &'static XboxOneInitPacket> {
    XBOXONE_INIT_PACKETS.iter().filter(move |p| {
        (p.vendor == 0x0000 || p.vendor == vendor) && (p.product == 0x0000 || p.product == product)
    })
}

// ── Unit smoke tests ─────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── 1. Device-ID table size ───────────────────────────────────

    fn smoke_xpad_device_table_size() -> TestResult {
        let n = XPAD_DEVICES.len();
        if n < 50 {
            return TestResult::Fail("xpad device table has fewer than 50 entries");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad_device_table_size);

    // ── 2. 360 wired: A button + LT trigger + LX full-left ───────

    fn smoke_xpad360_decode_buttons() -> TestResult {
        // 20-byte 360 report: type=0x00, len=0x14
        // btns_hi: bit4 = A pressed
        // LT = 0x80
        // LX = 0x0000 (actually -32768 full-left is 0x00, 0x80)
        let mut data = [0u8; 20];
        data[0] = 0x00; // valid type
        data[1] = 0x14; // length
        data[3] = 1 << 4; // A button
        data[4] = 0x80; // LT
                        // LX full-left = -32768 = 0x8000 in LE → [0x00, 0x80]
        data[6] = 0x00;
        data[7] = 0x80;

        // Push to a fresh ring and verify counts change
        narf_input::__reset_global_ring_for_test();
        xpad360_process_packet(&data, 0, false);
        // We expect at least one A-button event and one trigger/abs event
        let mut found_a = false;
        let mut found_lt = false;
        let mut found_lx = false;
        loop {
            match narf_input::pop_global() {
                None => break,
                Some(narf_input::InputEvent::Button(b)) => {
                    if b.code == btn::BTN_SOUTH && b.pressed {
                        found_a = true;
                    }
                }
                Some(narf_input::InputEvent::Absolute(a)) => {
                    if a.axis == abs::ABS_Z && a.value == 0x80 {
                        found_lt = true;
                    }
                    // LX full-left: read_le_i16 of [0x00,0x80] = i16::MIN = -32768
                    if a.axis == abs::ABS_X && a.value == -32768 {
                        found_lx = true;
                    }
                }
                Some(_) => {}
            }
        }
        if !found_a {
            return TestResult::Fail("360 decode: A button not found");
        }
        if !found_lt {
            return TestResult::Fail("360 decode: LT=0x80 not found");
        }
        if !found_lx {
            return TestResult::Fail("360 decode: LX full-left not found");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad360_decode_buttons);

    // ── 3. 360 wireless: connect event ───────────────────────────

    fn smoke_xpad360w_connect() -> TestResult {
        let mut rx = WirelessReceiver::new();
        // data[0] bit3 set = presence change; data[1] bit7 = present
        let data = [0x08u8, 0x80, 0, 0, 0, 0];
        let result = xpad360w_process_packet(&mut rx, 0, &data, 0);
        match result {
            WirelessResult::PresenceChanged {
                slot: 0,
                connected: true,
            } => {}
            _ => return TestResult::Fail("360W: expected connect event on slot 0"),
        }
        if rx.slots[0] != WirelessSlotState::Present {
            return TestResult::Fail("360W: slot 0 not marked Present");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad360w_connect);

    // ── 4. 360 wireless: data packet dispatch ────────────────────

    fn smoke_xpad360w_data_packet() -> TestResult {
        let mut rx = WirelessReceiver::new();
        rx.slots[1] = WirelessSlotState::Present;
        // data[0]=0, data[1]=0x01 = valid pad data
        // inner payload at [4..]: type=0x00, A button pressed (data[7] bit4)
        let mut data = [0u8; 32];
        data[1] = 0x01;
        data[4] = 0x00; // inner[0] = type valid
        data[7] = 1 << 4; // inner[3] = A button
        narf_input::__reset_global_ring_for_test();
        let result = xpad360w_process_packet(&mut rx, 1, &data, 0);
        if result != WirelessResult::DataDecoded {
            return TestResult::Fail("360W: expected DataDecoded");
        }
        let mut found_a = false;
        loop {
            match narf_input::pop_global() {
                None => break,
                Some(narf_input::InputEvent::Button(b)) => {
                    if b.code == btn::BTN_SOUTH && b.pressed {
                        found_a = true;
                    }
                }
                Some(_) => {}
            }
        }
        if !found_a {
            return TestResult::Fail("360W data: A button not decoded from inner payload");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad360w_data_packet);

    // ── 5. Xbox One: A button press ──────────────────────────────

    fn smoke_xpadone_a_button() -> TestResult {
        // GIP_CMD_INPUT=0x20 packet, minimal
        // data[4] bit4 = A pressed
        let mut data = [0u8; 18];
        data[0] = GIP_CMD_INPUT;
        data[4] = 1 << 4; // A
        narf_input::__reset_global_ring_for_test();
        xpadone_process_packet(&data, 18, 0);
        let mut found_a = false;
        loop {
            match narf_input::pop_global() {
                None => break,
                Some(narf_input::InputEvent::Button(b)) => {
                    if b.code == btn::BTN_SOUTH && b.pressed {
                        found_a = true;
                    }
                }
                Some(_) => {}
            }
        }
        if !found_a {
            TestResult::Fail("Xbox One: A button not decoded")
        } else {
            TestResult::Pass
        }
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpadone_a_button);

    // ── 6. Xbox One auth-init: first 3 packets ───────────────────

    fn smoke_xpadone_init_sequence() -> TestResult {
        // Verify the first 3 applicable packets for the power_on
        // (wildcard, always applies) match Linux's known payloads.
        // xpad.c:736: XBOXONE_INIT_PKT(0x0000, 0x0000, xboxone_power_on)
        // is the first wildcard entry (index 2).
        let packets: alloc::vec::Vec<_> = iter_init_packets(0x045e, 0x02d1).collect();
        if packets.len() < 3 {
            return TestResult::Fail("Xbox One init: fewer than 3 applicable packets");
        }
        // First applicable packet for a generic One pad should be
        // xboxone_power_on (indices 0+1 are Hori/Titanfall specific).
        let p0 = packets[0];
        if p0.data[0] != GIP_CMD_POWER {
            return TestResult::Fail("Xbox One init[0]: not a power-on packet");
        }
        if p0.data[1] != GIP_OPT_INTERNAL {
            return TestResult::Fail("Xbox One init[0]: GIP_OPT_INTERNAL mismatch");
        }
        // Second wildcard: xboxone_led_on
        let p1 = packets[1];
        if p1.data[0] != GIP_CMD_LED {
            return TestResult::Fail("Xbox One init[1]: not a LED packet");
        }
        // Third wildcard: xboxone_auth_done
        let p2 = packets[2];
        if p2.data[0] != GIP_CMD_AUTHENTICATE {
            return TestResult::Fail("Xbox One init[2]: not an auth packet");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpadone_init_sequence);

    // ── 7. Rumble: 360 encode weak=0x40, strong=0x80 ─────────────

    fn smoke_xpad_rumble_360() -> TestResult {
        let mut serial = 0u8;
        let pkt = match encode_rumble(XTYPE_XBOX360, 0x80 * 256, 0x40 * 256, &mut serial) {
            Some(p) => p,
            None => return TestResult::Fail("360 rumble: encode returned None"),
        };
        if pkt.len != 8 {
            return TestResult::Fail("360 rumble: expected 8-byte packet");
        }
        if pkt.data[0] != 0x00 || pkt.data[1] != 0x08 {
            return TestResult::Fail("360 rumble: wrong header bytes");
        }
        // strong / 256 = 0x80, weak / 256 = 0x40
        if pkt.data[3] != 0x80 {
            return TestResult::Fail("360 rumble: strong motor byte wrong");
        }
        if pkt.data[4] != 0x40 {
            return TestResult::Fail("360 rumble: weak motor byte wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad_rumble_360);

    // ── 8. LED: 360 pattern 6 (top-left on / rotate-ish) ─────────

    fn smoke_xpad_led_360() -> TestResult {
        // Pattern 10 = rotate (xpad.c:1670 "10: rotate")
        let pkt = match encode_led(XTYPE_XBOX360, 10) {
            Some(p) => p,
            None => return TestResult::Fail("360 LED: encode returned None"),
        };
        if pkt.len != 3 {
            return TestResult::Fail("360 LED: expected 3-byte packet");
        }
        if pkt.data[0] != 0x01 || pkt.data[1] != 0x03 {
            return TestResult::Fail("360 LED: wrong header bytes");
        }
        if pkt.data[2] != 10 {
            return TestResult::Fail("360 LED: wrong pattern byte");
        }
        // Specifically test pattern 6 (xpad.c says "6: 1/top-left on")
        let pkt6 = match encode_led(XTYPE_XBOX360, 6) {
            Some(p) => p,
            None => return TestResult::Fail("360 LED pattern 6: encode returned None"),
        };
        if pkt6.data[2] != 6 {
            return TestResult::Fail("360 LED: pattern 6 byte mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad_led_360);

    // ── 9. Button mapping: BTN_SOUTH = 0x130 ─────────────────────

    fn smoke_xpad_btn_south_code() -> TestResult {
        if btn::BTN_SOUTH != 0x130 {
            return TestResult::Fail("BTN_SOUTH != 0x130");
        }
        if btn::BTN_EAST != 0x131 {
            return TestResult::Fail("BTN_EAST != 0x131");
        }
        if btn::BTN_MODE != 0x13C {
            return TestResult::Fail("BTN_MODE != 0x13C");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad_btn_south_code);

    // ── 10. DPad: U/D/L/R → ABS_HAT0Y / ABS_HAT0X ───────────────

    fn smoke_xpad_dpad_hat() -> TestResult {
        // 360 report with D-pad up pressed (data[2] bit0)
        let mut data = [0u8; 20];
        data[0] = 0x00;
        data[2] = 0x01; // DUp bit
        narf_input::__reset_global_ring_for_test();
        xpad360_process_packet(&data, 0, false);
        let mut found_hat_y = false;
        loop {
            match narf_input::pop_global() {
                None => break,
                Some(narf_input::InputEvent::Absolute(a)) => {
                    // DUp → hat0y = -1 (up is negative y per Linux convention)
                    // xpad.c:917: ABS_HAT0Y = !!(data[2]&0x02) - !!(data[2]&0x01)
                    //   = 0 - 1 = -1
                    if a.axis == abs::ABS_HAT0Y && a.value == -1 {
                        found_hat_y = true;
                    }
                }
                Some(_) => {}
            }
        }
        if !found_hat_y {
            return TestResult::Fail("DPad up did not emit ABS_HAT0Y = -1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad_dpad_hat);

    // ── 11. Wireless receiver 4-slot demux ───────────────────────

    fn smoke_xpad360w_4slot_demux() -> TestResult {
        let mut rx = WirelessReceiver::new();
        // Connect all 4 slots in sequence
        for slot in 0..4usize {
            let data = [0x08u8, 0x80, 0, 0, 0, 0];
            let result = xpad360w_process_packet(&mut rx, slot, &data, 0);
            match result {
                WirelessResult::PresenceChanged {
                    slot: s,
                    connected: true,
                } if s == slot => {}
                _ => return TestResult::Fail("4-slot: connect not dispatched correctly"),
            }
        }
        for slot in 0..4usize {
            if rx.slots[slot] != WirelessSlotState::Present {
                return TestResult::Fail("4-slot: not all slots marked Present");
            }
        }
        // Disconnect slot 2
        let disc = [0x08u8, 0x00, 0, 0, 0, 0];
        let result = xpad360w_process_packet(&mut rx, 2, &disc, 0);
        match result {
            WirelessResult::PresenceChanged {
                slot: 2,
                connected: false,
            } => {}
            _ => return TestResult::Fail("4-slot: disconnect not dispatched correctly"),
        }
        if rx.slots[2] != WirelessSlotState::Absent {
            return TestResult::Fail("4-slot: slot 2 not marked Absent after disconnect");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/xpad", smoke_xpad360w_4slot_demux);
}
