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
//!   A detected pad keeps working in relative mode (both vendors
//!   emulate a standard PS/2 mouse until told otherwise); absolute-mode
//!   enablement is a follow-up lane, not attempted here.
//! * Elantech touchpad *detection* + absolute mode (v1–v4) —
//!   the magic knock from Linux `elantech_detect`
//!   (`drivers/input/mouse/elantech.c`): `RESET_DIS`, `DISABLE`,
//!   3x `SETSCALE11`, `GETINFO` must answer `0x3C, 0x03, 0xC8|0x00`,
//!   then the firmware-version query (`ETP_FW_VERSION_QUERY = 0x01`)
//!   must pass `elantech_is_signature_valid` — the check that keeps
//!   Linux from mis-detecting standard/Logitech mice (their `GETINFO`
//!   reply parses as a plausible version triple, e.g. `00.02.64`,
//!   and fails the signature: `param[0] == 0` is invalid, and a
//!   `param[2]` that is a sample rate is invalid). Absolute-mode
//!   packet decoders for v1 (4-byte) and v2/v3/v4 (6-byte) follow
//!   `elantech_report_absolute_v1/v2/v3/v4` + the per-version
//!   packet checks, verbatim from the same file.
//! * Synaptics absolute-packet *decoders* (NEWABS / OLDABS, from Linux
//!   `synaptics_parse_hw_state` + `synaptics_validate_byte`) as pure
//!   functions with spec fixtures. They are not wired to the IRQ path
//!   yet — enabling absolute mode needs the Synaptics query/mode
//!   constants (`SYN_QUE_*`, `SYN_PS_SET_MODE2`, `SYN_BIT_*` from
//!   `synaptics.h`), which were not verifiable in-session.
//!
//! Probe order follows Linux `psmouse_extensions()`: Synaptics, then
//! ALPS, then Elantech, then a full reset to defaults (the vendor probes
//! can confuse a plain mouse), then Explorer (whose knock includes the
//! IntelliMouse knock as a prefix), then IntelliMouse, then bare PS/2
//! fallback. An Elantech match claims the device outright — absolute
//! mode is already enabled, so the wheel knocks must not run after it.
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

// ── Elantech (Linux `drivers/input/mouse/elantech.h` / `elantech.c`) ───────

/// Synaptics-style sliced query commands.
pub const ETP_FW_ID_QUERY: u8 = 0x00;
pub const ETP_FW_VERSION_QUERY: u8 = 0x01;
pub const ETP_CAPABILITIES_QUERY: u8 = 0x02;
pub const ETP_SAMPLE_QUERY: u8 = 0x03;
/// Elantech custom PS/2 command prefix (0xF8) for register access (hw v2+).
pub const ETP_PS2_CUSTOM_COMMAND: u8 = 0xF8;
/// Register read/write command values (sliced for v1, after 0xF8 for v2+).
pub const ETP_REGISTER_READ: u8 = 0x10;
pub const ETP_REGISTER_WRITE: u8 = 0x11;
pub const ETP_REGISTER_READWRITE: u8 = 0x00;
/// Register 0x10 bit: absolute mode (hw v1).
pub const ETP_R10_ABSOLUTE_MODE: u8 = 0x04;
/// Magic-knock reply (Linux `elantech_detect`): after `RESET_DIS`,
/// `DISABLE`, 3x `SETSCALE11`, `GETINFO` must answer these bytes
/// (`param[2]` is `0xC8` or `0x00`).
pub const ELANTECH_MAGIC_0: u8 = 0x3C;
pub const ELANTECH_MAGIC_1: u8 = 0x03;
/// Retries per register byte (Linux `ETP_PS2_COMMAND_TRIES`).
pub const ETP_PS2_COMMAND_TRIES: u32 = 3;
/// Read-back attempts for register 0x10 after the mode set
/// (Linux `ETP_READ_BACK_TRIES`).
pub const ETP_READ_BACK_TRIES: u32 = 5;

/// Hardware version 1 axis ranges (Linux `elantech.h`:
/// 0..576 / 0..384 minus the 32-unit edge fuzz).
pub const ETP_XMAX_V1: u32 = 576 - 32;
pub const ETP_YMAX_V1: u32 = 384 - 32;
/// Hardware version 2 axis ranges for the known firmwares
/// (`0x020800` / `0x020B00` / `0x020030`).
pub const ETP_XMAX_V2: u32 = 1152;
pub const ETP_YMAX_V2: u32 = 768;

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
    /// Elantech pad (`elantech_detect` magic knock + firmware
    /// signature matched; absolute mode already enabled).
    Elantech = 3,
}

impl PsmouseHardware {
    pub fn as_str(self) -> &'static str {
        match self {
            PsmouseHardware::Generic => "generic",
            PsmouseHardware::Synaptics => "Synaptics",
            PsmouseHardware::Alps => "ALPS",
            PsmouseHardware::Elantech => "Elantech",
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
    /// Elantech hardware version 1: 4-byte absolute packets
    /// (Linux `elantech_setup_ps2`: `pktsize = hw_version > 1 ? 6 : 4`).
    ElantechV1 = 6,
    /// Elantech hardware versions 2–4: 6-byte absolute packets.
    Elantech = 7,
}

impl PsmouseProtocol {
    /// Movement-packet length in bytes for this protocol.
    pub fn packet_len(self) -> usize {
        match self {
            PsmouseProtocol::Standard => 3,
            PsmouseProtocol::IntelliMouse
            | PsmouseProtocol::Explorer
            | PsmouseProtocol::ExplorerTilt
            | PsmouseProtocol::ElantechV1 => 4,
            PsmouseProtocol::Elantech => 6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PsmouseProtocol::Standard => "PS/2",
            PsmouseProtocol::IntelliMouse => "ImPS/2",
            PsmouseProtocol::Explorer => "ImExPS/2",
            PsmouseProtocol::ExplorerTilt => "ImExPS/2-4.0",
            PsmouseProtocol::ElantechV1 => "ETPS/2-v1",
            PsmouseProtocol::Elantech => "ETPS/2",
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
        3 => PsmouseHardware::Elantech,
        _ => PsmouseHardware::Generic,
    }
}

pub fn protocol() -> PsmouseProtocol {
    match PROTOCOL.load(Ordering::Acquire) {
        3 => PsmouseProtocol::IntelliMouse,
        4 => PsmouseProtocol::Explorer,
        5 => PsmouseProtocol::ExplorerTilt,
        6 => PsmouseProtocol::ElantechV1,
        7 => PsmouseProtocol::Elantech,
        _ => PsmouseProtocol::Standard,
    }
}

/// Packet length for the active protocol (3 or 4 bytes).
pub fn packet_len() -> usize {
    protocol().packet_len()
}

/// Record the negotiation result. Called once from
/// `i8042_mouse::init`, before IRQ 12 is armed. Clears the
/// Elantech info unless the negotiated hardware is Elantech, so
/// "info present" always implies "Elantech active".
pub fn set_detected(hw: PsmouseHardware, proto: PsmouseProtocol) {
    HARDWARE.store(hw as u8, Ordering::Release);
    PROTOCOL.store(proto as u8, Ordering::Release);
    if hw != PsmouseHardware::Elantech {
        clear_elantech_info();
    }
}

/// Test-only: force a protocol (lets packet fixtures feed 4-byte
/// packets without a device). `__reset_for_test` in `i8042_mouse`
/// restores `Standard`.
pub fn set_protocol_for_test(proto: PsmouseProtocol) {
    PROTOCOL.store(proto as u8, Ordering::Release);
}

// ── Elantech negotiated info ──────────────────────────────────────────────

/// What `detect_elantech` learned about the pad: the firmware
/// version triple as one `u32` (`param[0]<<16 | param[1]<<8 |
/// param[2]`), the derived hardware version, the axis ranges the
/// decoders invert Y against, and the flags the packet checks and
/// the evdev caps need. All of it comes from Linux
/// `elantech_query_info` + `elantech_set_properties`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ElantechInfo {
    /// Hardware version 1–4 (`elantech_set_properties`).
    pub hw_version: u8,
    /// Firmware version (`ETP_FW_VERSION_QUERY` reply as one word).
    pub fw_version: u32,
    /// IC-body version (`(fw_version & 0x0f0000) >> 16`).
    pub ic_version: u8,
    /// Absolute X maximum (device units; min is 0, except v1's
    /// 32-unit edge fuzz which the decoders do not subtract —
    /// Linux reports the fuzzed range via `ETP_XMIN_V1` but the
    /// packets themselves span 0..`x_max`).
    pub x_max: u32,
    /// Absolute Y maximum; decoders report `y_max - raw_y`.
    pub y_max: u32,
    /// v4 touch-major scale `x_max / (traces - 1)`; 0 for hw < 4.
    pub width: u32,
    /// Firmware reports pressure/width (hw > 1 and fw >= 0x020800).
    pub reports_pressure: bool,
    /// Packet signatures use the CRC form (`fw_version & 0x4000`).
    pub crc_enabled: bool,
    /// Clickpad: both buttons map to `BTN_LEFT` (fw bit 12).
    pub buttonpad: bool,
    /// Trackpoint present (capabilities byte 0 bit 7). Trackpoint
    /// packets are classified but not reported — NARF has no
    /// second evdev node for the stick yet (remainder).
    pub has_trackpoint: bool,
    /// Second byte of the SAMPLE query (v4 packet sanity check
    /// needs it for IC version 7).
    pub samples_1: u8,
    /// Firmware misreports coordinates at touch start (fw
    /// `0x020022` / `0x020600`): the first two single-finger
    /// reports are discarded (Linux `jumpy_cursor`).
    pub jumpy_cursor: bool,
}

use core::sync::atomic::AtomicU32;

static ELANTECH_HW_VERSION: AtomicU8 = AtomicU8::new(0);
static ELANTECH_FW_VERSION: AtomicU32 = AtomicU32::new(0);
static ELANTECH_X_MAX: AtomicU32 = AtomicU32::new(0);
static ELANTECH_Y_MAX: AtomicU32 = AtomicU32::new(0);
static ELANTECH_WIDTH: AtomicU32 = AtomicU32::new(0);
static ELANTECH_SAMPLES_1: AtomicU8 = AtomicU8::new(0);
/// Bit 0 reports_pressure, bit 1 crc_enabled, bit 2 buttonpad,
/// bit 3 has_trackpoint, bit 4 jumpy_cursor.
static ELANTECH_FLAGS: AtomicU8 = AtomicU8::new(0);

/// Snapshot of the negotiated Elantech info, or `None` when no
/// Elantech pad was detected (see `set_detected`).
pub fn elantech_info() -> Option<ElantechInfo> {
    let hw_version = ELANTECH_HW_VERSION.load(Ordering::Acquire);
    if hw_version == 0 {
        return None;
    }
    let fw_version = ELANTECH_FW_VERSION.load(Ordering::Acquire);
    let flags = ELANTECH_FLAGS.load(Ordering::Acquire);
    Some(ElantechInfo {
        hw_version,
        fw_version,
        ic_version: ((fw_version & 0x0f0000) >> 16) as u8,
        x_max: ELANTECH_X_MAX.load(Ordering::Acquire),
        y_max: ELANTECH_Y_MAX.load(Ordering::Acquire),
        width: ELANTECH_WIDTH.load(Ordering::Acquire),
        reports_pressure: flags & 0x01 != 0,
        crc_enabled: flags & 0x02 != 0,
        buttonpad: flags & 0x04 != 0,
        has_trackpoint: flags & 0x08 != 0,
        samples_1: ELANTECH_SAMPLES_1.load(Ordering::Acquire),
        jumpy_cursor: flags & 0x10 != 0,
    })
}

pub fn set_elantech_info(info: &ElantechInfo) {
    ELANTECH_HW_VERSION.store(info.hw_version, Ordering::Release);
    ELANTECH_FW_VERSION.store(info.fw_version, Ordering::Release);
    ELANTECH_X_MAX.store(info.x_max, Ordering::Release);
    ELANTECH_Y_MAX.store(info.y_max, Ordering::Release);
    ELANTECH_WIDTH.store(info.width, Ordering::Release);
    ELANTECH_SAMPLES_1.store(info.samples_1, Ordering::Release);
    let mut flags = 0u8;
    if info.reports_pressure {
        flags |= 0x01;
    }
    if info.crc_enabled {
        flags |= 0x02;
    }
    if info.buttonpad {
        flags |= 0x04;
    }
    if info.has_trackpoint {
        flags |= 0x08;
    }
    if info.jumpy_cursor {
        flags |= 0x10;
    }
    ELANTECH_FLAGS.store(flags, Ordering::Release);
}

/// Test-only: install Elantech info directly (lets packet fixtures
/// feed absolute packets without a device). Cleared by
/// `set_detected` with non-Elantech hardware.
pub fn set_elantech_info_for_test(info: &ElantechInfo) {
    set_elantech_info(info);
}

fn clear_elantech_info() {
    ELANTECH_HW_VERSION.store(0, Ordering::Release);
    ELANTECH_FW_VERSION.store(0, Ordering::Release);
    ELANTECH_X_MAX.store(0, Ordering::Release);
    ELANTECH_Y_MAX.store(0, Ordering::Release);
    ELANTECH_WIDTH.store(0, Ordering::Release);
    ELANTECH_SAMPLES_1.store(0, Ordering::Release);
    ELANTECH_FLAGS.store(0, Ordering::Release);
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

// ── Elantech detection ────────────────────────────────────────────────────

/// Firmware-version signature check (Linux
/// `elantech_is_signature_valid`, verbatim). This is the whole
/// anti-mis-detection story, and why a bare "FW version query
/// succeeded" check is wrong:
/// * `param[0] == 0` — a standard mouse's `GETINFO` reply (e.g.
///   `00.02.64`) parses as a version triple with a zero major, so
///   it is rejected here;
/// * `param[1] == 0` — a real Elantech firmware (e.g. `02.00.22`);
/// * hw >= 4 firmwares with a revision above 20 (`param[2]` may be
///   10 or 20, not a sample rate) are accepted by the carve-out;
/// * `param[2]` equal to a sample rate (200/100/80/60/40/20/10)
///   means the "version" is just the mouse echoing rates — a
///   Logitech mouse answering the magic knock is rejected here.
pub fn elantech_is_signature_valid(param: &[u8; 3]) -> bool {
    if param[0] == 0 {
        return false;
    }
    if param[1] == 0 {
        return true;
    }
    // Some hw_version >= 4 models have a revision higher than 20.
    // Meaning that param[2] may be 10 or 20, skip the rates check
    // for these.
    if (param[0] & 0x0f) >= 0x06 && (param[1] & 0xaf) == 0x0f && param[2] < 40 {
        return true;
    }
    const RATES: [u8; 7] = [200, 100, 80, 60, 40, 20, 10];
    if RATES.contains(&param[2]) {
        return false;
    }
    true
}

/// Hardware version from the firmware version (Linux
/// `elantech_set_properties`): early firmwares are v1; otherwise
/// the IC-body version (`(fw & 0x0f0000) >> 16`) selects v2 (2/4),
/// v3 (5) or v4 (6..=15). `None` is an unknown IC — Linux aborts
/// init, and so do we.
pub fn elantech_hw_version(fw_version: u32) -> Option<u8> {
    let ic_version = ((fw_version & 0x0f0000) >> 16) as u8;
    // Early version of Elan touchpads doesn't obey the rule.
    if fw_version < 0x020030 || fw_version == 0x020600 {
        return Some(1);
    }
    match ic_version {
        2 | 4 => Some(2),
        5 => Some(3),
        6..=15 => Some(4),
        _ => None,
    }
}

/// One Elantech query (Linux `elantech_device_info::send_cmd`):
/// hw v3+ uses the fast command (`0xF8`, cmd, `GETINFO`); hw v1/v2
/// use the Synaptics sliced command. The reply is the 3-byte
/// `GETINFO` payload.
fn elantech_query<T: Ps2Transport>(t: &mut T, hw_version: u8, cmd: u8, out: &mut [u8; 3]) -> bool {
    if hw_version >= 3 {
        // elantech_send_cmd: F8, cmd, GETINFO (single attempt).
        if !t.send(ETP_PS2_CUSTOM_COMMAND) || !t.send(cmd) || !t.send(CMD_GET_INFO) {
            return false;
        }
    } else if !t.sliced_command(cmd) || !t.send(CMD_GET_INFO) {
        return false;
    }
    t.recv_exact(out)
}

/// Send one byte with up to 3 attempts (Linux
/// `elantech_ps2_command`: `ETP_PS2_COMMAND_TRIES` = 3; no delay
/// between tries here — the transport owns its timeout).
fn send_retry<T: Ps2Transport>(t: &mut T, byte: u8) -> bool {
    for _ in 0..ETP_PS2_COMMAND_TRIES {
        if t.send(byte) {
            return true;
        }
    }
    false
}

/// Write one register byte (Linux `elantech_write_reg`).
/// Registers live at 0x07..=0x26 excluding 0x12..=0x1F; the wire
/// form depends on the hardware version (sliced commands for v1,
/// `0xF8`-prefixed sequences for v2/v3/v4, with the v4 form
/// repeating the `0x00` (READWRITE) step before the value).
fn elantech_write_reg<T: Ps2Transport>(t: &mut T, hw_version: u8, reg: u8, val: u8) -> bool {
    if reg < 0x07 || reg > 0x26 || (0x12..0x20).contains(&reg) {
        return false;
    }
    match hw_version {
        1 => {
            t.sliced_command(ETP_REGISTER_WRITE)
                && t.sliced_command(reg)
                && t.sliced_command(val)
                && t.send(CMD_SET_SCALE11)
        }
        2 => {
            send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, ETP_REGISTER_WRITE)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, reg)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, val)
                && send_retry(t, CMD_SET_SCALE11)
        }
        3 => {
            send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, ETP_REGISTER_READWRITE)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, reg)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, val)
                && send_retry(t, CMD_SET_SCALE11)
        }
        4 => {
            send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, ETP_REGISTER_READWRITE)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, reg)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, ETP_REGISTER_READWRITE)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, val)
                && send_retry(t, CMD_SET_SCALE11)
        }
        _ => false,
    }
}

/// Read one register byte (Linux `elantech_read_reg`). The value
/// is `param[0]` of the `GETINFO` reply, except on hw v4 where it
/// is `param[1]`.
fn elantech_read_reg<T: Ps2Transport>(t: &mut T, hw_version: u8, reg: u8) -> Option<u8> {
    if reg < 0x07 || reg > 0x26 || (0x12..0x20).contains(&reg) {
        return None;
    }
    let mut param = [0u8; 3];
    let ok = match hw_version {
        1 => {
            t.sliced_command(ETP_REGISTER_READ)
                && t.sliced_command(reg)
                && t.send(CMD_GET_INFO)
                && t.recv_exact(&mut param)
        }
        2 => {
            send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, ETP_REGISTER_READ)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, reg)
                && send_retry(t, CMD_GET_INFO)
                && t.recv_exact(&mut param)
        }
        3 | 4 => {
            send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, ETP_REGISTER_READWRITE)
                && send_retry(t, ETP_PS2_CUSTOM_COMMAND)
                && send_retry(t, reg)
                && send_retry(t, CMD_GET_INFO)
                && t.recv_exact(&mut param)
        }
        _ => false,
    };
    if !ok {
        return None;
    }
    Some(if hw_version == 4 { param[1] } else { param[0] })
}

/// Put the pad into absolute mode (Linux
/// `elantech_set_absolute_mode`): the per-version register values,
/// then a read-back of register 0x10 (up to 5 attempts; v4 has no
/// reg 0x10 to read). For hw v1 the read-back must show the
/// absolute-mode bit, or the pad refused the mode switch.
fn set_elantech_absolute_mode<T: Ps2Transport>(t: &mut T, info: &ElantechInfo) -> bool {
    let ok = match info.hw_version {
        1 => elantech_write_reg(t, 1, 0x10, 0x16) && elantech_write_reg(t, 1, 0x11, 0x8f),
        2 => {
            // Windows driver values (Linux comment verbatim).
            elantech_write_reg(t, 2, 0x10, 0x54)
                && elantech_write_reg(t, 2, 0x11, 0x88)
                && elantech_write_reg(t, 2, 0x21, 0x60)
        }
        // set_hw_resolution is always on here (no DMI blacklist in
        // NARF), so reg 0x10 is 0x0b, not 0x01.
        3 => elantech_write_reg(t, 3, 0x10, 0x0b),
        4 => elantech_write_reg(t, 4, 0x07, 0x01),
        _ => return false,
    };
    if !ok {
        return false;
    }
    // v4 has no reg 0x10 to read back.
    if info.hw_version == 4 {
        return true;
    }
    for _ in 0..ETP_READ_BACK_TRIES {
        match elantech_read_reg(t, info.hw_version, 0x10) {
            Some(val) => {
                if info.hw_version == 1 && val & ETP_R10_ABSOLUTE_MODE == 0 {
                    return false;
                }
                return true;
            }
            None => continue,
        }
    }
    false
}

/// Query capabilities / samples / firmware id and derive the axis
/// ranges (Linux `elantech_query_info`, PS/2-relevant subset — the
/// SMBus companion setup, IC-body query and resolution query are
/// not applicable here). Any query failure aborts: Linux returns
/// `-EINVAL` and falls back to standard PS/2, and so do we.
fn query_elantech_info<T: Ps2Transport>(
    t: &mut T,
    hw_version: u8,
    fw_version: u32,
) -> Option<ElantechInfo> {
    let mut caps = [0u8; 3];
    if !elantech_query(t, hw_version, ETP_CAPABILITIES_QUERY, &mut caps) {
        return None;
    }
    let mut samples = [0u8; 3];
    if hw_version != 1 && !elantech_query(t, hw_version, ETP_SAMPLE_QUERY, &mut samples) {
        return None;
    }
    if hw_version == 3 && samples[1] == 0x74 {
        // This module has a bug which makes absolute mode unusable,
        // so let's abort so we'll be using standard PS/2 protocol.
        return None;
    }
    let (x_max, y_max, width) = match hw_version {
        1 => (ETP_XMAX_V1, ETP_YMAX_V1, 0),
        2 => {
            if fw_version == 0x020800 || fw_version == 0x020b00 || fw_version == 0x020030 {
                (ETP_XMAX_V2, ETP_YMAX_V2, 0)
            } else {
                let i: u32 = if fw_version > 0x020800 && fw_version < 0x020900 {
                    1
                } else {
                    2
                };
                let mut id = [0u8; 3];
                if !elantech_query(t, hw_version, ETP_FW_ID_QUERY, &mut id) {
                    return None;
                }
                let fixed_dpi = id[1] & 0x10 != 0;
                if (fw_version >> 16) == 0x14 && fixed_dpi {
                    let mut s = [0u8; 3];
                    if !elantech_query(t, hw_version, ETP_SAMPLE_QUERY, &mut s) {
                        return None;
                    }
                    (
                        (caps[1] as u32).saturating_sub(i) * s[1] as u32 / 2,
                        (caps[2] as u32).saturating_sub(i) * s[2] as u32 / 2,
                        0,
                    )
                } else if fw_version == 0x040216 {
                    (819, 405, 0)
                } else if fw_version == 0x040219 || fw_version == 0x040215 {
                    (900, 500, 0)
                } else {
                    (
                        (caps[1] as u32).saturating_sub(i) * 64,
                        (caps[2] as u32).saturating_sub(i) * 64,
                        0,
                    )
                }
            }
        }
        3 | 4 => {
            let mut id = [0u8; 3];
            if !elantech_query(t, hw_version, ETP_FW_ID_QUERY, &mut id) {
                return None;
            }
            let x_max = (((id[0] & 0x0f) as u32) << 8) | id[1] as u32;
            let y_max = (((id[0] & 0xf0) as u32) << 4) | id[2] as u32;
            if hw_version == 4 {
                let traces = caps[1] as u32;
                if traces < 2 || traces > x_max {
                    return None;
                }
                (x_max, y_max, x_max / (traces - 1))
            } else {
                (x_max, y_max, 0)
            }
        }
        _ => return None,
    };
    Some(ElantechInfo {
        hw_version,
        fw_version,
        ic_version: ((fw_version & 0x0f0000) >> 16) as u8,
        x_max,
        y_max,
        width,
        // Firmware >= 0x020800 on hw > 1 reports pressure/width
        // (Linux `elantech_set_properties`).
        reports_pressure: hw_version > 1 && fw_version >= 0x020800,
        // The signatures of v3 and v4 packets change depending on
        // the value of this hardware flag.
        crc_enabled: fw_version & 0x4000 == 0x4000,
        buttonpad: fw_version & 0x001000 != 0,
        // The MSB indicates the presence of the trackpoint.
        has_trackpoint: caps[0] & 0x80 != 0,
        samples_1: samples[1],
        jumpy_cursor: fw_version == 0x020022 || fw_version == 0x020600,
    })
}

/// Elantech detect (Linux `elantech_detect` + `elantech_query_info`
/// + `elantech_set_absolute_mode`): the magic knock, the firmware
/// version query with its signature check, the capability/range
/// queries, and the absolute-mode register writes. `None` on any
/// failure — the caller falls through to the reset + wheel knocks,
/// exactly as Linux falls back to standard PS/2.
fn detect_elantech<T: Ps2Transport>(t: &mut T) -> Option<ElantechInfo> {
    // Use magic knock to detect Elantech touchpad. RESET_DIS is
    // 0xF6 (`CMD_SET_DEFAULTS`).
    let _ = t.send(CMD_SET_DEFAULTS);
    let _ = t.send(CMD_DISABLE);
    let _ = t.send(CMD_SET_SCALE11);
    let _ = t.send(CMD_SET_SCALE11);
    let _ = t.send(CMD_SET_SCALE11);
    if !t.send(CMD_GET_INFO) {
        return None;
    }
    let mut param = [0u8; 3];
    if !t.recv_exact(&mut param) {
        return None;
    }
    if param[0] != ELANTECH_MAGIC_0
        || param[1] != ELANTECH_MAGIC_1
        || (param[2] != 0xC8 && param[2] != 0x00)
    {
        return None;
    }
    // Query touchpad's firmware version and see if it reports known
    // value to avoid mis-detection. Logitech mice are known to
    // respond to Elantech magic knock and there might be more.
    if !t.sliced_command(ETP_FW_VERSION_QUERY) || !t.send(CMD_GET_INFO) {
        return None;
    }
    let mut fw = [0u8; 3];
    if !t.recv_exact(&mut fw) {
        return None;
    }
    if !elantech_is_signature_valid(&fw) {
        return None;
    }
    let fw_version = ((fw[0] as u32) << 16) | ((fw[1] as u32) << 8) | fw[2] as u32;
    let hw_version = elantech_hw_version(fw_version)?;
    let info = query_elantech_info(t, hw_version, fw_version)?;
    if !set_elantech_absolute_mode(t, &info) {
        return None;
    }
    Some(info)
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
/// order: Synaptics detect, ALPS detect, Elantech detect (magic
/// knock + firmware signature + absolute-mode enablement — a match
/// claims the device outright and returns immediately, before any
/// reset or wheel knock), full reset to defaults, Explorer attempt
/// (IntelliMouse knock as its prefix, then the Explorer knock; ID
/// must be `0x04`, then the 4.0 tilt knock), IntelliMouse attempt
/// (ID must be `0x03`), bare PS/2 fallback.
///
/// The vendor probes run before the wheel knocks because some
/// Synaptics pads emulate the IntelliMouse protocol — probing them
/// first is what lets Linux tell a real wheel mouse from a pad in
/// relative mode. The post-probe reset is Linux's "reset to defaults
/// in case the device got confused by extended protocol probes".
pub fn negotiate_protocol<T: Ps2Transport>(t: &mut T) -> (PsmouseHardware, PsmouseProtocol) {
    // Negotiation owns the Elantech info: it is set if and only
    // if this call returns Elantech, so a failed probe can never
    // leave a stale info behind for the IRQ path (or a later test)
    // to read.
    clear_elantech_info();
    let mut hw = PsmouseHardware::Generic;
    if detect_synaptics(t) {
        hw = PsmouseHardware::Synaptics;
    } else if detect_alps(t) {
        hw = PsmouseHardware::Alps;
    }
    // Elantech, in Linux order (after Synaptics/ALPS, before the
    // reset + wheel knocks). A match wins over an earlier vendor
    // match: a device answering the Elantech magic knock *and* the
    // firmware signature is Elantech, whatever the earlier probes
    // thought. Absolute mode is already enabled on return, so the
    // wheel knocks must not run afterwards.
    if let Some(info) = detect_elantech(t) {
        set_elantech_info(&info);
        let proto = if info.hw_version == 1 {
            PsmouseProtocol::ElantechV1
        } else {
            PsmouseProtocol::Elantech
        };
        return (PsmouseHardware::Elantech, proto);
    }

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

// ── Elantech absolute-packet decode (pure; wired in `i8042_mouse`) ────────
//
// From Linux `drivers/input/mouse/elantech.c`. All coordinates are
// reported Y-inverted (`y_max - raw_y`: the pad reports Y bottom
// to top, userspace expects top to bottom), in device units
// (0..`x_max` / 0..`y_max` from [`ElantechInfo`]).

/// Packet class for hw v3/v4 (Linux `elantech_packet_check_v3/v4`).
/// `Debounce` packets are ignored whole; `Unknown` packets are
/// dropped (`PSMOUSE_BAD_DATA`); `Trackpoint` packets are
/// classified but not reported — NARF has no second evdev node
/// for the stick yet (remainder).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElantechPacket {
    Unknown,
    Debounce,
    V3Head,
    V3Tail,
    V4Head,
    V4Motion,
    V4Status,
    Trackpoint,
}

/// One contact slot of a decoded Elantech frame. `width` is the
/// Linux `ABS_TOOL_WIDTH` value (v2/v3 decoded width; v4 trace
/// count scaled by `ElantechInfo::width`); `pressure` is the Linux
/// `ABS_PRESSURE` / `ABS_MT_PRESSURE` value (0 when the firmware
/// does not report pressure).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ElantechSlot {
    pub active: bool,
    pub x: u32,
    pub y: u32,
    pub pressure: u16,
    pub width: u16,
}

impl ElantechSlot {
    pub const fn new() -> Self {
        Self {
            active: false,
            x: 0,
            y: 0,
            pressure: 0,
            width: 0,
        }
    }
}

/// One decoded Elantech absolute packet, as the IRQ path reports
/// it: up to 5 slots (v4) — v1/v2/v3 fill slots 0..=1 at most —
/// plus the primary-finger pressure/width and the physical
/// buttons. `fingers` is the hardware finger count (0..=5); for
/// v2/v3 a 3- or 4-finger touch reports one position with
/// `fingers` 3/4 (Linux's semi-MT second slot at (0,0) is not
/// replicated — a phantom (0,0) contact is worse than a missing
/// second contact, and the count still rides in `fingers`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ElantechFrame {
    pub slots: [ElantechSlot; 5],
    pub fingers: u8,
    pub left: bool,
    pub right: bool,
    pub pressure: u16,
    pub width: u16,
}

/// Decode state that survives across packets: v4 finger slots
/// (motion packets are deltas against the last head position),
/// the v3 two-finger head stash, and the v1 jumpy-cursor counter.
/// Owned by the IRQ/test feed path in `i8042_mouse`.
#[derive(Copy, Clone, Debug)]
pub struct ElantechState {
    /// Last known per-slot positions (v4 motion base; also the
    /// last reported frame for v1/v2/v3).
    pub slots: [ElantechSlot; 5],
    /// Bit per slot currently down.
    pub active_mask: u8,
    /// v3 two-finger head position, awaiting its tail packet.
    pub v3_head: (u32, u32),
    /// A v3 head packet was stashed (`v3_head` is live).
    pub v3_head_pending: bool,
    /// v1 jumpy-cursor workaround: single-finger reports seen
    /// since the last multi-finger report.
    pub single_finger_reports: u32,
}

impl ElantechState {
    pub const fn new() -> Self {
        Self {
            slots: [ElantechSlot::new(); 5],
            active_mask: 0,
            v3_head: (0, 0),
            v3_head_pending: false,
            single_finger_reports: 0,
        }
    }
}

impl Default for ElantechState {
    fn default() -> Self {
        Self::new()
    }
}

/// v1 parity bit (Linux `elantech_data::parity` table:
/// `parity[0] = 1`, `parity[i] = parity[i & (i - 1)] ^ 1` —
/// i.e. 1 when the byte has an even popcount).
pub fn elantech_parity(byte: u8) -> u8 {
    if byte.count_ones() % 2 == 0 {
        1
    } else {
        0
    }
}

/// v1 packet check (Linux `elantech_packet_check_v1`): the three
/// parity bits ride in byte 0, placed differently before/after
/// firmware 0x020000.
pub fn elantech_packet_check_v1(packet: &[u8; 4], fw_version: u32) -> bool {
    // Parity bits are placed differently.
    let (p1, p2) = if fw_version < 0x020000 {
        // byte 0:  D   U  p1  p2   1  p3   R   L
        ((packet[0] & 0x20) >> 5, (packet[0] & 0x10) >> 4)
    } else {
        // byte 0: n1  n0  p2  p1   1  p3   R   L
        ((packet[0] & 0x10) >> 4, (packet[0] & 0x20) >> 5)
    };
    let p3 = (packet[0] & 0x04) >> 2;
    elantech_parity(packet[1]) == p1
        && elantech_parity(packet[2]) == p2
        && elantech_parity(packet[3]) == p3
}

/// v2 debounce packet (Linux `elantech_debounce_check_v2`): when
/// the hardware is in debounce status the whole packet is ignored.
pub fn elantech_is_debounce_v2(packet: &[u8; 6]) -> bool {
    packet == &[0x84, 0xff, 0xff, 0x02, 0xff, 0xff]
}

/// v2 packet check (Linux `elantech_packet_check_v2`): constant
/// bits, which differ between pressure-reporting firmware and the
/// older flavours (1/3-finger vs 2-finger layouts).
pub fn elantech_packet_check_v2(packet: &[u8; 6], reports_pressure: bool) -> bool {
    if reports_pressure {
        return (packet[0] & 0x0c) == 0x04 && (packet[3] & 0x0f) == 0x02;
    }
    if (packet[0] & 0xc0) == 0x80 {
        return (packet[0] & 0x0c) == 0x0c && (packet[3] & 0x0e) == 0x08;
    }
    (packet[0] & 0x3c) == 0x3c
        && (packet[1] & 0xf0) == 0x00
        && (packet[3] & 0x3e) == 0x38
        && (packet[4] & 0xf0) == 0x00
}

/// v3 packet classification (Linux `elantech_packet_check_v3`).
/// The debounce packet is checked first — it shares byte 0 / byte
/// 3 signatures with `V3Head`. With CRC enabled the head/tail
/// signatures change.
pub fn elantech_packet_check_v3(packet: &[u8; 6], crc_enabled: bool) -> ElantechPacket {
    const DEBOUNCE: [u8; 6] = [0xc4, 0xff, 0xff, 0x02, 0xff, 0xff];
    if packet == &DEBOUNCE {
        return ElantechPacket::Debounce;
    }
    if crc_enabled {
        if (packet[3] & 0x09) == 0x08 {
            return ElantechPacket::V3Head;
        }
        if (packet[3] & 0x09) == 0x09 {
            return ElantechPacket::V3Tail;
        }
    } else {
        if (packet[0] & 0x0c) == 0x04 && (packet[3] & 0xcf) == 0x02 {
            return ElantechPacket::V3Head;
        }
        if (packet[0] & 0x0c) == 0x0c && (packet[3] & 0xce) == 0x0c {
            return ElantechPacket::V3Tail;
        }
        if (packet[3] & 0x0f) == 0x06 {
            return ElantechPacket::Trackpoint;
        }
    }
    ElantechPacket::Unknown
}

/// v4 packet classification (Linux `elantech_packet_check_v4`).
/// The trackpoint signature needs a trackpoint device to exist;
/// without one the packet falls through to the sanity check.
/// `samples_1` is the second byte of the SAMPLE query.
pub fn elantech_packet_check_v4(
    packet: &[u8; 6],
    crc_enabled: bool,
    fw_version: u32,
    samples_1: u8,
    has_trackpoint: bool,
) -> ElantechPacket {
    if has_trackpoint && (packet[3] & 0x0f) == 0x06 {
        return ElantechPacket::Trackpoint;
    }
    // This represents the version of IC body.
    let ic_version = ((fw_version & 0x0f0000) >> 16) as u8;
    // Sanity check based on the constant bits of a packet. The
    // constant bits change depending on the value of the hardware
    // flag 'crc_enabled' and the version of the IC body, but are
    // the same for every packet, regardless of the type.
    let sanity = if crc_enabled {
        (packet[3] & 0x08) == 0x00
    } else if ic_version == 7 && samples_1 == 0x2A {
        (packet[3] & 0x1c) == 0x10
    } else {
        (packet[0] & 0x08) == 0x00 && (packet[3] & 0x1c) == 0x10
    };
    if !sanity {
        return ElantechPacket::Unknown;
    }
    match packet[3] & 0x03 {
        0 => ElantechPacket::V4Status,
        1 => ElantechPacket::V4Head,
        2 => ElantechPacket::V4Motion,
        _ => ElantechPacket::Unknown,
    }
}

/// Decode a v1 4-byte packet (Linux
/// `elantech_report_absolute_v1`). Returns `None` for the
/// jumpy-cursor discards (first two single-finger reports on fw
/// `0x020022` / `0x020600`). Byte 0 bit 2 is the p3 parity bit,
/// not a middle button — Linux's generic button reporter aliases
/// it into `BTN_MIDDLE`; we do not.
pub fn decode_elantech_v1(
    state: &mut ElantechState,
    packet: &[u8; 4],
    fw_version: u32,
    y_max: u32,
    jumpy_cursor: bool,
) -> Option<ElantechFrame> {
    let fingers = if fw_version < 0x020000 {
        // byte 0:  D   U  p1  p2   1  p3   R   L
        // byte 1:  f   0  th  tw  x9  x8  y9  y8
        (((packet[1] & 0x80) >> 7) + ((packet[1] & 0x30) >> 4)) as u8
    } else {
        // byte 0: n1  n0  p2  p1   1  p3   R   L
        // byte 1:  0   0   0   0  x9  x8  y9  y8
        ((packet[0] & 0xc0) >> 6) as u8
    };
    if jumpy_cursor {
        if fingers != 1 {
            state.single_finger_reports = 0;
        } else if state.single_finger_reports < 2 {
            // Discard first 2 reports of one finger, bogus.
            state.single_finger_reports += 1;
            return None;
        }
    }
    let mut frame = ElantechFrame::default();
    frame.fingers = fingers;
    if fingers != 0 {
        // byte 2: x7..x0; byte 3: y7..y0.
        let x = (((packet[1] & 0x0c) as u32) << 6) | packet[2] as u32;
        let raw_y = (((packet[1] & 0x03) as u32) << 8) | packet[3] as u32;
        frame.slots[0] = ElantechSlot {
            active: true,
            x,
            y: y_max.saturating_sub(raw_y),
            pressure: 0,
            width: 0,
        };
    }
    frame.left = packet[0] & 0x01 != 0;
    frame.right = packet[0] & 0x02 != 0;
    state.slots = frame.slots;
    state.active_mask = if fingers != 0 { 1 } else { 0 };
    Some(frame)
}

/// Decode a v2 6-byte packet (Linux
/// `elantech_report_absolute_v2`). `fingers` 3 with bit 7 of byte
/// 3 set means 4 fingers (same 1-finger layout otherwise); 2
/// fingers report both contacts at half resolution.
pub fn decode_elantech_v2(
    state: &mut ElantechState,
    packet: &[u8; 6],
    y_max: u32,
) -> ElantechFrame {
    // byte 0: n1  n0   .   .   .   .   R   L
    let mut fingers = ((packet[0] & 0xc0) >> 6) as u8;
    if fingers == 3 && packet[3] & 0x80 != 0 {
        fingers = 4;
    }
    let mut frame = ElantechFrame::default();
    frame.fingers = fingers;
    let (mut x1, mut y1, mut x2, mut y2) = (0u32, 0u32, 0u32, 0u32);
    let (mut pres, mut width) = (0u16, 0u16);
    match fingers {
        1 | 3 | 4 => {
            // byte 1:  .   .   .   .  x11 x10 x9  x8
            // byte 2: x7..x0
            x1 = (((packet[1] & 0x0f) as u32) << 8) | packet[2] as u32;
            // byte 4:  .   .   .   .  y11 y10 y9  y8
            // byte 5: y7..y0
            y1 = y_max.saturating_sub((((packet[4] & 0x0f) as u32) << 8) | packet[5] as u32);
            pres = ((packet[1] & 0xf0) | ((packet[4] & 0xf0) >> 4)) as u16;
            width = (((packet[0] & 0x30) >> 2) | ((packet[3] & 0x30) >> 4)) as u16;
        }
        2 => {
            // The coordinate of each finger is reported separately
            // with a lower resolution for two finger touches.
            x1 = ((((packet[0] & 0x10) as u32) << 4) | packet[1] as u32) << 2;
            y1 = y_max.saturating_sub(((((packet[0] & 0x20) as u32) << 3) | packet[2] as u32) << 2);
            x2 = ((((packet[3] & 0x10) as u32) << 4) | packet[4] as u32) << 2;
            y2 = y_max.saturating_sub(((((packet[3] & 0x20) as u32) << 3) | packet[5] as u32) << 2);
            // Unknown so just report sensible values.
            pres = 127;
            width = 7;
        }
        _ => {}
    }
    if fingers != 0 {
        frame.slots[0] = ElantechSlot {
            active: true,
            x: x1,
            y: y1,
            pressure: pres,
            width,
        };
        if fingers == 2 {
            frame.slots[1] = ElantechSlot {
                active: true,
                x: x2,
                y: y2,
                pressure: pres,
                width,
            };
        }
    }
    frame.pressure = pres;
    frame.width = width;
    frame.left = packet[0] & 0x01 != 0;
    frame.right = packet[0] & 0x02 != 0;
    state.slots = frame.slots;
    state.active_mask = match fingers {
        0 => 0,
        2 => 0b11,
        _ => 0b01,
    };
    frame
}

/// Decode a v3 6-byte packet (Linux
/// `elantech_report_absolute_v3`). A two-finger head packet only
/// stashes finger A and returns `None` — the frame is reported
/// when its tail packet arrives (12 bytes per two-finger report).
pub fn decode_elantech_v3(
    state: &mut ElantechState,
    packet: &[u8; 6],
    packet_type: ElantechPacket,
    y_max: u32,
    buttonpad: bool,
) -> Option<ElantechFrame> {
    let fingers = ((packet[0] & 0xc0) >> 6) as u8;
    let (mut x1, mut y1, mut x2, mut y2) = (0u32, 0u32, 0u32, 0u32);
    match fingers {
        1 | 3 => {
            x1 = (((packet[1] & 0x0f) as u32) << 8) | packet[2] as u32;
            y1 = y_max.saturating_sub((((packet[4] & 0x0f) as u32) << 8) | packet[5] as u32);
        }
        2 => {
            if packet_type == ElantechPacket::V3Head {
                state.v3_head = (
                    (((packet[1] & 0x0f) as u32) << 8) | packet[2] as u32,
                    y_max.saturating_sub((((packet[4] & 0x0f) as u32) << 8) | packet[5] as u32),
                );
                state.v3_head_pending = true;
                // Wait for next packet.
                return None;
            }
            // packet_type == PACKET_V3_TAIL
            x1 = state.v3_head.0;
            y1 = state.v3_head.1;
            x2 = (((packet[1] & 0x0f) as u32) << 8) | packet[2] as u32;
            y2 = y_max.saturating_sub((((packet[4] & 0x0f) as u32) << 8) | packet[5] as u32);
            state.v3_head_pending = false;
        }
        _ => {}
    }
    let pres = ((packet[1] & 0xf0) | ((packet[4] & 0xf0) >> 4)) as u16;
    let width = (((packet[0] & 0x30) >> 2) | ((packet[3] & 0x30) >> 4)) as u16;
    let mut frame = ElantechFrame::default();
    frame.fingers = fingers;
    if fingers != 0 {
        frame.slots[0] = ElantechSlot {
            active: true,
            x: x1,
            y: y1,
            pressure: pres,
            width,
        };
        if fingers == 2 {
            frame.slots[1] = ElantechSlot {
                active: true,
                x: x2,
                y: y2,
                pressure: pres,
                width,
            };
        }
    }
    frame.pressure = pres;
    frame.width = width;
    // For clickpads map both buttons to BTN_LEFT.
    if buttonpad {
        frame.left = packet[0] & 0x03 != 0;
        frame.right = false;
    } else {
        frame.left = packet[0] & 0x01 != 0;
        frame.right = packet[0] & 0x02 != 0;
    }
    state.slots = frame.slots;
    state.active_mask = match fingers {
        0 => 0,
        2 => 0b11,
        _ => 0b01,
    };
    Some(frame)
}

/// Decode a v4 6-byte packet (Linux
/// `elantech_report_absolute_v4`): status packets release fingers,
/// head packets place one finger, motion packets move one or two
/// fingers by signed deltas. The returned frame is the whole
/// current slot state after applying the packet. Delta
/// application clamps at 0 instead of wrapping like Linux's
/// unsigned arithmetic — a wrap would teleport the cursor to
/// ~4 billion on a single underflowing delta.
pub fn decode_elantech_v4(
    state: &mut ElantechState,
    packet: &[u8; 6],
    packet_type: ElantechPacket,
    y_max: u32,
    width: u32,
    buttonpad: bool,
) -> Option<ElantechFrame> {
    match packet_type {
        ElantechPacket::V4Status => {
            // Notify finger state change.
            let fingers = packet[1] & 0x1f;
            for i in 0..5 {
                if fingers & (1 << i) == 0 {
                    state.slots[i].active = false;
                    state.active_mask &= !(1 << i);
                }
            }
        }
        ElantechPacket::V4Head => {
            let id = (((packet[3] & 0xe0) >> 5) as i32) - 1;
            if !(0..5).contains(&id) {
                return None;
            }
            let id = id as usize;
            let x = (((packet[1] & 0x0f) as u32) << 8) | packet[2] as u32;
            let y = y_max.saturating_sub((((packet[4] & 0x0f) as u32) << 8) | packet[5] as u32);
            let pres = ((packet[1] & 0xf0) | ((packet[4] & 0xf0) >> 4)) as u16;
            let traces = ((packet[0] & 0xf0) >> 4) as u32;
            state.slots[id] = ElantechSlot {
                active: true,
                x,
                y,
                pressure: pres,
                width: (traces * width) as u16,
            };
            state.active_mask |= 1 << id;
        }
        ElantechPacket::V4Motion => {
            let id = (((packet[0] & 0xe0) >> 5) as i32) - 1;
            if !(0..5).contains(&id) {
                return None;
            }
            let id = id as usize;
            let sid = (((packet[3] & 0xe0) >> 5) as i32) - 1;
            let weight: i32 = if packet[0] & 0x10 != 0 { 5 } else { 1 };
            // Motion packets give us the delta of x, y values of
            // specific fingers, but in two's complement.
            let dx1 = packet[1] as i8 as i32;
            let dy1 = packet[2] as i8 as i32;
            let dx2 = packet[4] as i8 as i32;
            let dy2 = packet[5] as i8 as i32;
            state.slots[id].x = (state.slots[id].x as i32 + dx1 * weight).max(0) as u32;
            state.slots[id].y = (state.slots[id].y as i32 - dy1 * weight).max(0) as u32;
            if (0..5).contains(&sid) {
                let sid = sid as usize;
                state.slots[sid].x = (state.slots[sid].x as i32 + dx2 * weight).max(0) as u32;
                state.slots[sid].y = (state.slots[sid].y as i32 - dy2 * weight).max(0) as u32;
            }
        }
        _ => return None,
    }
    let mut frame = ElantechFrame::default();
    frame.slots = state.slots;
    frame.fingers = state.active_mask.count_ones() as u8;
    // For clickpads map both buttons to BTN_LEFT.
    if buttonpad {
        frame.left = packet[0] & 0x03 != 0;
        frame.right = false;
    } else {
        frame.left = packet[0] & 0x01 != 0;
        frame.right = packet[0] & 0x02 != 0;
    }
    for s in state.slots {
        if s.active {
            frame.pressure = s.pressure;
            frame.width = s.width;
            break;
        }
    }
    Some(frame)
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
