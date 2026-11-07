//! PS/2 pointing-device protocol extensions.
//!
//! The device behind the i8042 AUX channel is usually more than a
//! bare 3-byte mouse. This module owns the protocol knowledge for
//! everything above the 3-byte baseline:
//!
//! * IntelliMouse (wheel) and IntelliMouse Explorer (wheel + 4th/5th
//!   buttons + tilt wheel) — sample-rate knock sequences and 4-byte
//!   packet decode, following Linux `drivers/input/mouse/psmouse-base.c`
//!   (`intellimouse_detect`, `im_explorer_detect`, `psmouse_process_byte`).
//! * Synaptics / ALPS touchpad *detection* — the magic knocks from
//!   Linux `synaptics_detect` (`drivers/input/mouse/synaptics.c`) and
//!   `Documentation/input/alps.txt` ("E6 report" / "E7 report").
//!   A detected pad keeps working in relative mode (all three vendors
//!   emulate a standard PS/2 mouse until told otherwise); absolute-mode
//!   enablement is a follow-up lane, not attempted here.
//! * Synaptics absolute-packet *decoders* (NEWABS / OLDABS, from Linux
//!   `synaptics_parse_hw_state` + `synaptics_validate_byte`) as pure
//!   functions with spec fixtures. They are not wired to the IRQ path
//!   yet — enabling absolute mode needs the Synaptics query/mode
//!   constants (`SYN_QUE_*`, `SYN_PS_SET_MODE2`, `SYN_BIT_*` from
//!   `synaptics.h`), which were not verifiable in-session.
//!
//! Elantech detection is deliberately NOT implemented here: the
//! firmware-version signature check that keeps Linux from mis-detecting
//! standard/Logitech mice as Elantech (`elantech_detect`) was not
//! verifiable in-session, and a bare "FW version query succeeded"
//! check false-positives on standard mice (their `GETINFO` reply
//! parses as a plausible version triple). See the remainder issue.
//!
//! Probe order follows Linux `psmouse_extensions()`: Synaptics, then
//! ALPS, then a full reset to defaults (the vendor probes can confuse
//! a plain mouse), then Explorer (whose knock includes the IntelliMouse
//! knock as a prefix), then IntelliMouse, then bare PS/2 fallback.
//!
//! References:
//! * Adam Chapweske, "The PS/2 Mouse Interface" — IntelliMouse /
//!   Explorer knocks (200/100/80 → ID 0x03; 200/200/80 → ID 0x04),
//!   4-byte packet, Z wheel as 4-bit two's complement (-8..+7).
//! * Linux `drivers/input/mouse/psmouse-base.c` (ti-linux-6.12.y-cicd
//!   mirror) — `intellimouse_detect`, `im_explorer_detect` (incl. the
//!   200/80/40 Explorer 4.0 tilt enable), `psmouse_process_byte`
//!   (wheel = `-(signed char)packet[3]` for IMPS; the `packet[3] & 0xC0`
//!   switch for IMEX), `psmouse_extensions` probe order,
//!   `psmouse_initialize` (sample rate restored to 100 after probing).
//! * Linux `drivers/input/mouse/synaptics.c` — `synaptics_detect`
//!   (4x `SETRES(0)` + `GETINFO`, 2nd response byte `0x47`),
//!   `synaptics_parse_hw_state`, `synaptics_validate_byte`,
//!   `synaptics_invert_y`.
//! * Linux `Documentation/input/alps.txt` — "E6 report"
//!   (`E8-E6-E6-E6-E9` → `00-00-0A` or `00-00-64`) and "E7 report"
//!   (`E8-E7-E7-E7-E9` → model signature, `0x73...` for v3/v4).

extern crate alloc;

use core::fmt::Write;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_console::Writer;

// ── PS/2 device commands (sent behind the i8042 0xD4 prefix) ─────────────

/// Set sample rate (0xF3) — takes one rate byte (10/20/40/60/80/100/200).
pub const CMD_SET_RATE: u8 = 0xF3;
/// Get device ID (0xF2) — one reply byte (0x00 standard, 0x03 IMPS, 0x04 IMEX).
pub const CMD_GET_ID: u8 = 0xF2;
/// Get info / status (0xE9) — three reply bytes.
pub const CMD_GET_INFO: u8 = 0xE9;
/// Set resolution (0xE8) — takes one resolution byte.
pub const CMD_SET_RES: u8 = 0xE8;
/// Set scaling 1:1 (0xE6).
pub const CMD_SET_SCALE11: u8 = 0xE6;
/// Set scaling 2:1 (0xE7).
pub const CMD_SET_SCALE21: u8 = 0xE7;
/// Disable data reporting (0xF5).
pub const CMD_DISABLE: u8 = 0xF5;
/// Enable data reporting (0xF4).
pub const CMD_ENABLE: u8 = 0xF4;
/// Set defaults (0xF6).
pub const CMD_SET_DEFAULTS: u8 = 0xF6;
/// Reset (0xFF) — replies ACK, BAT (0xAA), device-id byte.
pub const CMD_RESET: u8 = 0xFF;

/// ACK byte (0xFA) sent after every accepted command byte.
pub const ACK: u8 = 0xFA;
/// BAT-ok byte (0xAA) sent after a reset.
pub const BAT_OK: u8 = 0xAA;

/// Device ID of a bare standard PS/2 mouse.
pub const ID_STANDARD: u8 = 0x00;
/// Device ID of an IntelliMouse (wheel) after the 200/100/80 knock.
pub const ID_INTELLI: u8 = 0x03;
/// Device ID of an IntelliMouse Explorer after the 200/200/80 knock.
pub const ID_EXPLORER: u8 = 0x04;

/// IntelliMouse knock: set sample rate 200, 100, 80, then `GETID`.
pub const INTELLI_RATES: [u8; 3] = [200, 100, 80];
/// Explorer knock (sent after the IntelliMouse knock): 200, 200, 80.
pub const EXPLORER_RATES: [u8; 3] = [200, 200, 80];
/// Explorer 4.0 tilt-wheel enable (sent after ID 0x04): 200, 80, 40.
pub const EXPLORER4_RATES: [u8; 3] = [200, 80, 40];

/// Sample rate restored after probing (Linux `psmouse_initialize`
/// re-applies the configured rate, default 100, once the protocol
/// is settled — the knocks leave it at 80, or 40 after the tilt knock).
pub const RESTORE_RATE: u8 = 100;

/// Second byte of the `GETINFO` reply from a Synaptics pad
/// (Linux `synaptics_detect`: `param[1] != 0x47` → not Synaptics).
pub const SYNAPTICS_ID_BYTE: u8 = 0x47;

/// First byte of an ALPS "E7 report" model signature (v3/v4 pads
/// answer `73-02-64`; newer pads `73-03-50` / `73-03-0A`).
pub const ALPS_SIGNATURE_PREFIX: u8 = 0x73;

// ── Detected hardware / active protocol ───────────────────────────────────

/// What the vendor probes found behind the AUX channel. Distinct
/// from [`PsmouseProtocol`]: a Synaptics pad can still run the
/// IntelliMouse packet protocol in relative mode (Linux keeps a
/// `synaptics_hardware` flag alongside `psmouse->type`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PsmouseHardware {
    /// No vendor protocol detected (plain mouse or unknown pad).
    Generic = 0,
    /// Synaptics pad (`synaptics_detect` matched).
    Synaptics = 1,
    /// ALPS pad ("E6 report" + "E7 report" matched).
    Alps = 2,
}

impl PsmouseHardware {
    pub fn as_str(self) -> &'static str {
        match self {
            PsmouseHardware::Generic => "generic",
            PsmouseHardware::Synaptics => "Synaptics",
            PsmouseHardware::Alps => "ALPS",
        }
    }
}

/// Active packet protocol negotiated on the AUX channel.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PsmouseProtocol {
    /// Bare 3-byte PS/2 packets.
    Standard = 0,
    /// IntelliMouse: 4-byte packets, wheel in byte 3.
    IntelliMouse = 3,
    /// IntelliMouse Explorer: 4-byte packets, wheel + 4th/5th buttons.
    Explorer = 4,
    /// Explorer with the 4.0 tilt-wheel enable: byte 3 can also carry
    /// horizontal scroll (Linux `im_explorer_detect` sends the extra
    /// 200/80/40 knock after ID 0x04).
    ExplorerTilt = 5,
}

impl PsmouseProtocol {
    /// Movement-packet length in bytes for this protocol.
    pub fn packet_len(self) -> usize {
        match self {
            PsmouseProtocol::Standard => 3,
            PsmouseProtocol::IntelliMouse
            | PsmouseProtocol::Explorer
            | PsmouseProtocol::ExplorerTilt => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PsmouseProtocol::Standard => "PS/2",
            PsmouseProtocol::IntelliMouse => "ImPS/2",
            PsmouseProtocol::Explorer => "ImExPS/2",
            PsmouseProtocol::ExplorerTilt => "ImExPS/2-4.0",
        }
    }
}

/// Hardware found by the vendor probes (write-once at init, before
/// IRQ 12 is armed; read-only afterwards).
static HARDWARE: AtomicU8 = AtomicU8::new(PsmouseHardware::Generic as u8);
/// Active packet protocol (same lifetime as `HARDWARE`).
static PROTOCOL: AtomicU8 = AtomicU8::new(PsmouseProtocol::Standard as u8);

pub fn hardware() -> PsmouseHardware {
    match HARDWARE.load(Ordering::Acquire) {
        1 => PsmouseHardware::Synaptics,
        2 => PsmouseHardware::Alps,
        _ => PsmouseHardware::Generic,
    }
}

pub fn protocol() -> PsmouseProtocol {
    match PROTOCOL.load(Ordering::Acquire) {
        3 => PsmouseProtocol::IntelliMouse,
        4 => PsmouseProtocol::Explorer,
        5 => PsmouseProtocol::ExplorerTilt,
        _ => PsmouseProtocol::Standard,
    }
}

/// Packet length for the active protocol (3 or 4 bytes).
pub fn packet_len() -> usize {
    protocol().packet_len()
}

/// Record the negotiation result. Called once from
/// `i8042_mouse::init`, before IRQ 12 is armed.
pub fn set_detected(hw: PsmouseHardware, proto: PsmouseProtocol) {
    HARDWARE.store(hw as u8, Ordering::Release);
    PROTOCOL.store(proto as u8, Ordering::Release);
}

/// Test-only: force a protocol (lets packet fixtures feed 4-byte
/// packets without a device). `__reset_for_test` in `i8042_mouse`
/// restores `Standard`.
pub fn set_protocol_for_test(proto: PsmouseProtocol) {
    PROTOCOL.store(proto as u8, Ordering::Release);
}

// ── Transport ─────────────────────────────────────────────────────────────

/// Byte transport to the PS/2 device. The real implementation lives
/// in `i8042_mouse` (0xD4-prefixed port I/O); tests use a fake that
/// records sends and replays canned replies, so the knock sequences
/// are fixture-pinned byte-for-byte instead of trusted from the impl.
pub trait Ps2Transport {
    /// Send one byte to the device. Returns `true` if the device ACKed
    /// (`0xFA`). Detection ignores ACK failures (Linux ignores the
    /// `SET RATE` results too — only the reply bytes decide).
    fn send(&mut self, byte: u8) -> bool;

    /// Read one reply byte, if one arrives within the transport's timeout.
    fn recv(&mut self) -> Option<u8>;

    /// Send a command byte followed by one parameter byte.
    fn send_param(&mut self, cmd: u8, param: u8) -> bool {
        self.send(cmd) && self.send(param)
    }

    /// Read exactly `buf.len()` reply bytes.
    fn recv_exact(&mut self, buf: &mut [u8]) -> bool {
        for b in buf.iter_mut() {
            match self.recv() {
                Some(v) => *b = v,
                None => return false,
            }
        }
        true
    }

    /// Full device reset: `0xFF`, expect ACK (consumed by `send`),
    /// then BAT (`0xAA`), then the device-id byte. Restores power-on
    /// defaults (3-byte packets, rate 100, reporting disabled).
    /// Transports with a slow BAT (real hardware: up to ~500 ms)
    /// override this to wait longer for the BAT byte.
    fn reset(&mut self) -> bool {
        if !self.send(CMD_RESET) {
            return false;
        }
        if self.recv() != Some(BAT_OK) {
            return false;
        }
        self.recv().is_some()
    }

    /// Sliced command (Linux `psmouse_sliced_command`): `0xE6`,
    /// then `0xE8` + each 2-bit slice of `command`, most significant
    /// first — wire bytes `E6 E8 rr E8 ss E8 tt E8 uu` where
    /// `(rr*64)+(ss*16)+(tt*4)+uu` is the command. Used by the
    /// Synaptics/Elantech query mechanism.
    fn sliced_command(&mut self, command: u8) -> bool {
        if !self.send(CMD_SET_SCALE11) {
            return false;
        }
        for shift in [6, 4, 2, 0] {
            let slice = (command >> shift) & 0x03;
            if !self.send_param(CMD_SET_RES, slice) {
                return false;
            }
        }
        true
    }
}

// ── Detection ─────────────────────────────────────────────────────────────

/// Synaptics detect (Linux `synaptics_detect`): four `SETRES(0)`
/// commands, then `GETINFO`; a Synaptics pad answers with `0x47`
/// in the *second* reply byte.
///
/// Note the old stub in this file claimed the knock was four
/// `Disable (0xF5)` commands checked against the *first* reply
/// byte — that was wrong on both counts; the Linux source says
/// `SETRES` and `param[1]`.
fn detect_synaptics<T: Ps2Transport>(t: &mut T) -> bool {
    for _ in 0..4 {
        let _ = t.send_param(CMD_SET_RES, 0);
    }
    if !t.send(CMD_GET_INFO) {
        return false;
    }
    let mut resp = [0u8; 3];
    if !t.recv_exact(&mut resp) {
        return false;
    }
    resp[1] == SYNAPTICS_ID_BYTE
}

/// ALPS "E6 report" (Linux `Documentation/input/alps.txt`): wire
/// bytes `E8-E6-E6-E6-E9`, i.e. `SETRES(0xE6)`, `SETSCALE11`,
/// `SETSCALE11`, `GETINFO`. An ALPS pad answers `00-00-0A` or
/// `00-00-64` (bits 0-2 of the first byte are 1 when buttons are
/// pressed, so only the top five bits must be zero).
fn alps_e6_report<T: Ps2Transport>(t: &mut T) -> bool {
    let _ = t.send_param(CMD_SET_RES, 0xE6);
    let _ = t.send(CMD_SET_SCALE11);
    let _ = t.send(CMD_SET_SCALE11);
    if !t.send(CMD_GET_INFO) {
        return false;
    }
    let mut resp = [0u8; 3];
    if !t.recv_exact(&mut resp) {
        return false;
    }
    resp[0] & 0xF8 == 0 && resp[1] == 0x00 && (resp[2] == 0x0A || resp[2] == 0x64)
}

/// ALPS "E7 report" (`alps.txt`): wire bytes `E8-E7-E7-E7-E9`,
/// i.e. `SETRES(0xE7)`, `SETSCALE21`, `SETSCALE21`, `GETINFO`.
/// The reply is the model signature; v3/v4 pads answer `73-02-64`,
/// newer pads `73-03-50` / `73-03-0A` — all start with `0x73`.
fn alps_e7_report<T: Ps2Transport>(t: &mut T) -> bool {
    let _ = t.send_param(CMD_SET_RES, 0xE7);
    let _ = t.send(CMD_SET_SCALE21);
    let _ = t.send(CMD_SET_SCALE21);
    if !t.send(CMD_GET_INFO) {
        return false;
    }
    let mut resp = [0u8; 3];
    if !t.recv_exact(&mut resp) {
        return false;
    }
    resp[0] == ALPS_SIGNATURE_PREFIX
}

fn detect_alps<T: Ps2Transport>(t: &mut T) -> bool {
    alps_e6_report(t) && alps_e7_report(t)
}

/// Send a sample-rate knock sequence and read the device ID
/// afterwards (Linux `intellimouse_detect` / `im_explorer_detect`).
/// Rate-set ACKs are ignored — only the ID byte decides.
fn knock_get_id<T: Ps2Transport>(t: &mut T, rates: &[u8]) -> Option<u8> {
    for &rate in rates {
        let _ = t.send_param(CMD_SET_RATE, rate);
    }
    if !t.send(CMD_GET_ID) {
        return None;
    }
    t.recv()
}

/// Negotiate the active protocol, in Linux `psmouse_extensions()`
/// order: Synaptics detect, ALPS detect, full reset to defaults,
/// Explorer attempt (IntelliMouse knock as its prefix, then the
/// Explorer knock; ID must be `0x04`, then the 4.0 tilt knock),
/// IntelliMouse attempt (ID must be `0x03`), bare PS/2 fallback.
///
/// The vendor probes run before the wheel knocks because some
/// Synaptics pads emulate the IntelliMouse protocol — probing them
/// first is what lets Linux tell a real wheel mouse from a pad in
/// relative mode. The post-probe reset is Linux's "reset to defaults
/// in case the device got confused by extended protocol probes".
pub fn negotiate_protocol<T: Ps2Transport>(t: &mut T) -> (PsmouseHardware, PsmouseProtocol) {
    let mut hw = PsmouseHardware::Generic;
    if detect_synaptics(t) {
        hw = PsmouseHardware::Synaptics;
    } else if detect_alps(t) {
        hw = PsmouseHardware::Alps;
    }
    // Elantech is NOT probed here: see the module docs — the
    // signature check that avoids mis-detecting standard mice was
    // not verifiable in-session (remainder issue).

    // Reset to defaults before the wheel knocks.
    let _ = t.reset();

    // Explorer attempt (Linux `im_explorer_detect`).
    let _ = knock_get_id(t, &INTELLI_RATES);
    if knock_get_id(t, &EXPLORER_RATES) == Some(ID_EXPLORER) {
        // Explorer 4.0 tilt-wheel enable (Linux: 200, 80, 40).
        for &rate in &EXPLORER4_RATES {
            let _ = t.send_param(CMD_SET_RATE, rate);
        }
        return (hw, PsmouseProtocol::ExplorerTilt);
    }
    // IntelliMouse attempt (Linux `intellimouse_detect`).
    if knock_get_id(t, &INTELLI_RATES) == Some(ID_INTELLI) {
        return (hw, PsmouseProtocol::IntelliMouse);
    }
    (hw, PsmouseProtocol::Standard)
}

// ── Wheel decode (IntelliMouse / Explorer 4-byte packets) ──────────────────

/// IntelliMouse wheel delta (Linux `psmouse_process_byte` for
/// `PSMOUSE_IMPS`: `REL_WHEEL = -(signed char)packet[3]`).
/// The whole 4th byte is the Z movement: 4-bit two's complement
/// (-8..+7) sign-extended into the full byte.
pub fn decode_imps_wheel(b3: u8) -> i32 {
    -(b3 as i8) as i32
}

/// Explorer 4th-byte decode (Linux `psmouse_process_byte` for
/// `PSMOUSE_IMEX`, `packet[3] & 0xC0` switch, verbatim):
/// * `0x80` — Explorer 4.0 vertical scroll: 6-bit value
///   `(b3 & 32) - (b3 & 31)` on `REL_WHEEL`.
/// * `0x40` — Explorer 4.0 horizontal scroll: same value on `REL_HWHEEL`.
/// * `0x00` / `0xC0` — wheel in the low nibble
///   (`(b3 & 8) - (b3 & 7)`), 4th button in bit 4 (`BTN_SIDE`),
///   5th button in bit 5 (`BTN_EXTRA`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ImexWheel {
    /// Vertical wheel delta (`REL_WHEEL`).
    pub wheel: i32,
    /// Horizontal wheel delta (`REL_HWHEEL`, Explorer 4.0 tilt only).
    pub hwheel: i32,
    /// 4th button pressed (`BTN_SIDE`).
    pub side: bool,
    /// 5th button pressed (`BTN_EXTRA`).
    pub extra: bool,
}

pub fn decode_imex(b3: u8) -> ImexWheel {
    match b3 & 0xC0 {
        0x80 => ImexWheel {
            wheel: (b3 & 32) as i32 - (b3 & 31) as i32,
            hwheel: 0,
            side: false,
            extra: false,
        },
        0x40 => ImexWheel {
            wheel: 0,
            hwheel: (b3 & 32) as i32 - (b3 & 31) as i32,
            side: false,
            extra: false,
        },
        _ => ImexWheel {
            wheel: (b3 & 8) as i32 - (b3 & 7) as i32,
            hwheel: 0,
            side: (b3 >> 4) & 1 != 0,
            extra: (b3 >> 5) & 1 != 0,
        },
    }
}

// ── Synaptics absolute-packet decoders (pure; not yet wired) ───────────────
//
// From Linux `synaptics_parse_hw_state` (`drivers/input/mouse/synaptics.c`).
// 6-byte absolute packets, two layouts selected by model
// (`SYN_MODEL_NEWABS`): NEWABS on current pads, OLDABS on old ones.
// Both share the wrap-around rule (values above the positive limit
// are negative values truncated to the 13-bit reporting range) and
// the Y inversion (`synaptics_invert_y`: the pad reports Y bottom
// to top, userspace expects top to bottom).

/// Synaptics absolute-mode coordinate limits (Interfacing Guide §2.3.2).
pub const SYN_X_MAX: i32 = 6143;
pub const SYN_Y_MAX: i32 = 6143;
/// Nominal (unqueried) edges, used by the Y inversion.
pub const SYN_X_MIN_NOMINAL: i32 = 1472;
pub const SYN_X_MAX_NOMINAL: i32 = 5472;
pub const SYN_Y_MIN_NOMINAL: i32 = 1408;
pub const SYN_Y_MAX_NOMINAL: i32 = 4448;
/// Wrap-around limit: `((1 << 13) + 6143) / 2 = 7167`.
pub const SYN_MAX_POSITIVE: i32 = ((1 << 13) + 6143) / 2;
/// Absolute position is 13 bits wide.
pub const SYN_ABS_POS_BITS: u32 = 13;

/// One decoded Synaptics absolute packet (single-finger fields;
/// the AGM / multi-finger state machine is a follow-up lane).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SynapticsHwState {
    /// Absolute X (0..6143 nominal, before Y-style inversion — X is not inverted).
    pub x: i32,
    /// Absolute Y, raw pad orientation (bottom-to-top); use
    /// [`synaptics_invert_y`] before reporting.
    pub y: i32,
    /// Finger pressure (Z, 0..255).
    pub z: u8,
    /// Finger width (W; 0 = one finger, 1 = two fingers on
    /// multifinger pads — see `synaptics_process_packet`).
    pub w: u8,
    pub left: bool,
    pub right: bool,
}

fn synaptics_wrap(value: i32) -> i32 {
    if value > SYN_MAX_POSITIVE {
        value - (1 << SYN_ABS_POS_BITS)
    } else {
        value
    }
}

/// Invert Y to userspace orientation (Linux `synaptics_invert_y`:
/// `YMAX_NOMINAL + YMIN_NOMINAL - y`).
pub fn synaptics_invert_y(y: i32) -> i32 {
    SYN_Y_MAX_NOMINAL + SYN_Y_MIN_NOMINAL - y
}

/// NEWABS 6-byte packet (Linux `synaptics_parse_hw_state`,
/// `SYN_MODEL_NEWABS` branch):
/// `x = ((b3 & 0x10) << 8) | ((b1 & 0x0f) << 8) | b4`,
/// `y = ((b3 & 0x20) << 7) | ((b1 & 0xf0) << 4) | b5`,
/// `z = b2`,
/// `w = ((b0 & 0x30) >> 2) | ((b0 & 0x04) >> 1) | ((b3 & 0x04) >> 2)`,
/// left = `b0 & 0x01`, right = `b0 & 0x02`.
pub fn decode_synaptics_newabs(buf: &[u8; 6]) -> SynapticsHwState {
    let w = (((buf[0] & 0x30) >> 2) | ((buf[0] & 0x04) >> 1) | ((buf[3] & 0x04) >> 2)) as u8;
    let x = synaptics_wrap(
        ((buf[3] as i32 & 0x10) << 8) | ((buf[1] as i32 & 0x0f) << 8) | buf[4] as i32,
    );
    let y = synaptics_wrap(
        ((buf[3] as i32 & 0x20) << 7) | ((buf[1] as i32 & 0xf0) << 4) | buf[5] as i32,
    );
    SynapticsHwState {
        x,
        y,
        z: buf[2],
        w,
        left: buf[0] & 0x01 != 0,
        right: buf[0] & 0x02 != 0,
    }
}

/// OLDABS 6-byte packet (Linux `synaptics_parse_hw_state`, else branch):
/// `x = ((b1 & 0x1f) << 8) | b2`, `y = ((b4 & 0x1f) << 8) | b5`,
/// `z = ((b0 & 0x30) << 2) | (b3 & 0x3F)`,
/// `w = ((b1 & 0x80) >> 4) | ((b0 & 0x04) >> 1)`,
/// left = `b0 & 0x01`, right = `b0 & 0x02`.
pub fn decode_synaptics_oldabs(buf: &[u8; 6]) -> SynapticsHwState {
    let w = (((buf[1] & 0x80) >> 4) | ((buf[0] & 0x04) >> 1)) as u8;
    let x = synaptics_wrap(((buf[1] as i32 & 0x1f) << 8) | buf[2] as i32);
    let y = synaptics_wrap(((buf[4] as i32 & 0x1f) << 8) | buf[5] as i32);
    SynapticsHwState {
        x,
        y,
        z: (((buf[0] as i32 & 0x30) << 2) | (buf[3] as i32 & 0x3F)) as u8,
        w,
        left: buf[0] & 0x01 != 0,
        right: buf[0] & 0x02 != 0,
    }
}

/// Synaptics absolute packet flavour, for byte validation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SynapticsPktType {
    NewAbs,
    NewAbsStrict,
    NewAbsRelaxed,
    OldAbs,
}

/// Per-byte validation (Linux `synaptics_validate_byte`).
/// Only bytes 0..=4 are validated (the 6th byte completes the
/// packet); `idx` outside that range is invalid.
/// Masks/results, verbatim from Linux:
/// * NEWABS strict: mask `{0xC8,0,0,0xC8,0}`, result `{0x80,0,0,0xC0,0}`
/// * NEWABS relaxed: mask `{0xC0,0,0,0xC0,0}`, result `{0x80,0,0,0xC0,0}`
/// * OLDABS: mask `{0xC0,0x60,0,0xC0,0x60}`, result `{0xC0,0,0,0x80,0}`
pub fn synaptics_validate_byte(buf: &[u8; 6], idx: usize, pkt_type: SynapticsPktType) -> bool {
    if idx > 4 {
        return false;
    }
    let (mask, rslt): ([u8; 5], [u8; 5]) = match pkt_type {
        SynapticsPktType::NewAbs | SynapticsPktType::NewAbsStrict => (
            [0xC8, 0x00, 0x00, 0xC8, 0x00],
            [0x80, 0x00, 0x00, 0xC0, 0x00],
        ),
        SynapticsPktType::NewAbsRelaxed => (
            [0xC0, 0x00, 0x00, 0xC0, 0x00],
            [0x80, 0x00, 0x00, 0xC0, 0x00],
        ),
        SynapticsPktType::OldAbs => (
            [0xC0, 0x60, 0x00, 0xC0, 0x60],
            [0xC0, 0x00, 0x00, 0x80, 0x00],
        ),
    };
    (buf[idx] & mask[idx]) == rslt[idx]
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "psmouse", || {
        // Negotiation already ran inside `i8042_mouse::init`
        // (it must precede the 0xF4 enable); report the result.
        let _ = writeln!(
            Writer,
            "  psmouse: hardware={} protocol={} ({}-byte packets)",
            hardware().as_str(),
            protocol().as_str(),
            packet_len(),
        );
        InitResult::Ok
    });
}
