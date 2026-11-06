//! PS/2 pointing-device protocol extensions — Synaptics absolute mode.
//!
//! The device behind the i8042 AUX channel is usually more than a
//! bare 3-byte mouse. This module owns the Synaptics half of the
//! protocol knowledge above the 3-byte baseline:
//!
//! * Synaptics *detection* — the magic knock from Linux
//!   `synaptics_detect` (`drivers/input/mouse/synaptics.c`): four
//!   `SETRES(0)` + `GETINFO`, second response byte `0x47`.
//! * Synaptics *query + mode set* — the hardware queries from Linux
//!   `synaptics_query_hardware` (`__synaptics_init` order: identify
//!   → model → firmware → board → capability → resolution) and the
//!   mode byte from Linux `synaptics_set_mode`, sent with
//!   `synaptics_mode_cmd` (sliced mode byte + `SETRATE(0x14)`).
//!   The query/mode constants (`SYN_QUE_*`, `SYN_PS_SET_MODE2`,
//!   `SYN_BIT_*`) are from Linux `drivers/input/mouse/synaptics.h`,
//!   cross-checked against the Synaptics TouchPad Interfacing Guide
//!   (2nd ed., §2.4/§2.5/§3.5/§3.6).
//! * Synaptics absolute-packet *decoders* (NEWABS / OLDABS, from
//!   Linux `synaptics_parse_hw_state` + `synaptics_validate_byte`)
//!   as pure functions with spec fixtures, wired to the IRQ path in
//!   `i8042_mouse` — a negotiated Synaptics pad runs 6-byte packets
//!   reporting `ABS_X` / `ABS_Y` / `ABS_PRESSURE` + `BTN_TOUCH`.
//!
//! Out of scope here (separate lanes / follow-ons):
//! * IntelliMouse / Explorer wheel knocks and 4-byte packets —
//!   open PR #1676 (`claude/ps2-wheel-767`, issue #767). This file
//!   overlaps that PR's `psmouse.rs` (transport trait, Synaptics
//!   detect, decoders): whichever lands second rebases and unions
//!   the two — see the PR body for the ordering. Shared symbols
//!   intentionally keep #1676's names (`Ps2Transport`,
//!   `PsmouseHardware`, `PsmouseProtocol`, `set_detected`,
//!   `decode_synaptics_newabs` / `decode_synaptics_oldabs`,
//!   `synaptics_validate_byte`, `synaptics_invert_y`) so the union
//!   is mechanical.
//! * ALPS absolute mode — issue #1674 (separate lane).
//! * Elantech — issue #1673 (separate lane).
//! * MT / AGM (multi-finger / advanced gesture mode) — follow-on
//!   within #1675: `w == 2` AGM packets are not decoded and the
//!   AGM mode set (`synaptics_set_advanced_gesture_mode`) is not
//!   sent; single-finger (SGM) packets only.
//!
//! References:
//! * Linux `drivers/input/mouse/synaptics.h` — `SYN_QUE_*`,
//!   `SYN_BIT_*`, `SYN_MODEL_*`, `SYN_CAP_*`, `SYN_ID_*`,
//!   `SYN_PS_SET_MODE2 = 0x14`.
//! * Linux `drivers/input/mouse/synaptics.c` — `synaptics_detect`,
//!   `synaptics_send_cmd`, `synaptics_query_hardware`,
//!   `synaptics_set_mode`, `synaptics_mode_cmd`,
//!   `synaptics_parse_hw_state`, `synaptics_validate_byte`,
//!   `synaptics_process_packet` (BTN_TOUCH hysteresis `z > 30` /
//!   `z < 25`, X/Y reported only when `z > 0 && x > 1`),
//!   `synaptics_invert_y`, `__synaptics_init`.
//! * Linux `drivers/input/mouse/psmouse-base.c` —
//!   `psmouse_sliced_command` (`0xE6`, then `0xE8` + each 2-bit
//!   slice, most significant first).
//! * Synaptics TouchPad Interfacing Guide, 2nd ed. — §2.3 absolute
//!   packet contents, §2.4 queries, §2.5 mode byte (Fig 2-14/2-15),
//!   §3.5.1 information queries, §3.5.2 mode setting sequence
//!   (`$F3, $14` commit, e.g. `$C1` = Absolute + high rate + W),
//!   §3.6.2 absolute packet format (Fig 3-18 NEWABS, Fig 3-20
//!   OLDABS).

extern crate alloc;

use core::fmt::Write;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_console::Writer;

// ── PS/2 device commands (sent behind the i8042 0xD4 prefix) ─────────────

/// Set sample rate (0xF3) — takes one rate byte (10/20/40/60/80/100/200).
pub const CMD_SET_RATE: u8 = 0xF3;
/// Get info / status (0xE9) — three reply bytes.
pub const CMD_GET_INFO: u8 = 0xE9;
/// Set resolution (0xE8) — takes one resolution byte.
pub const CMD_SET_RES: u8 = 0xE8;
/// Set scaling 1:1 (0xE6) — first byte of a sliced command.
pub const CMD_SET_SCALE11: u8 = 0xE6;
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

// ── Synaptics queries (Linux `synaptics.h`) ───────────────────────────────
//
// Query numbers are the 8-bit argument encoded as a sliced command
// (§3.5.1 of the Interfacing Guide: $00 Identify, $01 Read Modes,
// $02 Read Capabilities, $03 Read Model ID, $08 Read Resolutions;
// Linux added $06/$07 serial, $09 ext caps, $0a firmware ID,
// $0c ext caps 0x0c, $0d/$0f max/min coords).

/// Identify TouchPad.
pub const SYN_QUE_IDENTIFY: u8 = 0x00;
/// Read TouchPad modes (board ID rides in this response).
pub const SYN_QUE_MODES: u8 = 0x01;
/// Read capability bits.
pub const SYN_QUE_CAPABILITIES: u8 = 0x02;
/// Read model ID.
pub const SYN_QUE_MODEL: u8 = 0x03;
/// Read serial number prefix.
pub const SYN_QUE_SERIAL_NUMBER_PREFIX: u8 = 0x06;
/// Read serial number suffix.
pub const SYN_QUE_SERIAL_NUMBER_SUFFIX: u8 = 0x07;
/// Read X/Y resolutions (units/mm).
pub const SYN_QUE_RESOLUTION: u8 = 0x08;
/// Read extended capabilities.
pub const SYN_QUE_EXT_CAPAB: u8 = 0x09;
/// Read firmware ID.
pub const SYN_QUE_FIRMWARE_ID: u8 = 0x0a;
/// Read extended capabilities 0x0c (clickpad / AGM / image sensor).
pub const SYN_QUE_EXT_CAPAB_0C: u8 = 0x0c;
/// Read maximum reported coordinates.
pub const SYN_QUE_EXT_MAX_COORDS: u8 = 0x0d;
/// Read minimum reported coordinates.
pub const SYN_QUE_EXT_MIN_COORDS: u8 = 0x0f;

// ── Synaptics mode byte bits (Linux `synaptics.h` / Guide Fig 2-14) ───────

/// Absolute mode (bit 7).
pub const SYN_BIT_ABSOLUTE_MODE: u8 = 0x80;
/// High packet rate, ~80/s instead of ~40/s (bit 6).
pub const SYN_BIT_HIGH_RATE: u8 = 0x40;
/// Sleep mode (bit 3; PS/2 only, relative mode only).
pub const SYN_BIT_SLEEP_MODE: u8 = 0x08;
/// Disable tap/drag gesture detection (bit 2; major version >= 4).
pub const SYN_BIT_DISABLE_GESTURE: u8 = 0x04;
/// Four-byte pass-through client (bit 1).
pub const SYN_BIT_FOUR_BYTE_CLIENT: u8 = 0x02;
/// W mode: enhanced absolute packets carrying the W value (bit 0).
pub const SYN_BIT_W_MODE: u8 = 0x01;

// ── Synaptics special commands (Linux `synaptics.h`) ──────────────────────

/// `SETRATE` argument that commits a sliced mode byte
/// (Guide §3.5.2: `Set Sample Rate 20 ($F3, $14)`).
pub const SYN_PS_SET_MODE2: u8 = 0x14;
/// `SETRATE` argument for the pass-through port.
pub const SYN_PS_CLIENT_CMD: u8 = 0x28;

/// Second byte of the `GETINFO` reply from a Synaptics pad
/// (Linux `synaptics_detect`: `param[1] != 0x47` → not Synaptics).
pub const SYNAPTICS_ID_BYTE: u8 = 0x47;

/// Sample rate the pad runs at after reset (PS/2 default); the
/// mode byte takes `HIGH_RATE` when the rate is >= 80 (Linux
/// `synaptics_set_mode` / `synaptics_set_rate`).
pub const SYNAPTICS_RATE: u32 = 100;

// ── Synaptics limits (Linux `synaptics.c` / Guide §2.3.2) ─────────────────

/// Synaptics absolute-mode coordinate limits (Guide §2.3.2).
pub const SYN_X_MAX: i32 = 6143;
pub const SYN_Y_MAX: i32 = 6143;
/// Nominal (unqueried) edges, used by the Y inversion and by the
/// evdev `ABS_X`/`ABS_Y` ranges.
pub const SYN_X_MIN_NOMINAL: i32 = 1472;
pub const SYN_X_MAX_NOMINAL: i32 = 5472;
pub const SYN_Y_MIN_NOMINAL: i32 = 1408;
pub const SYN_Y_MAX_NOMINAL: i32 = 4448;
/// Wrap-around limit (Linux `X_MAX_POSITIVE` / `Y_MAX_POSITIVE`):
/// values above this are negative values truncated to the 13-bit
/// reporting range, and a value exactly equal to it means the
/// finger is at the edge whose precise position cannot be
/// determined, so it clamps to the axis maximum (6143).
///
/// NOTE: open PR #1676 uses a 7167 midpoint rule here
/// (`((1 << 13) + 6143) / 2`); that deviates from Linux, which
/// uses 8176 with the `== 8176 → XMAX` clamp. This lane follows
/// Linux; the rebase must keep 8176.
pub const SYN_MAX_POSITIVE: i32 = 8176;
/// Absolute position is 13 bits wide.
pub const SYN_ABS_POS_BITS: u32 = 13;
/// BTN_TOUCH hysteresis (Linux `synaptics_process_packet`):
/// touch asserts when `z > 30`, releases when `z < 25`.
pub const SYN_TOUCH_ON_Z: u8 = 30;
pub const SYN_TOUCH_OFF_Z: u8 = 25;

// ── Synaptics identity / model / capability decodes ────────────────────────

/// `SYN_MODEL_NEWABS(m)`: model-ID bit 7 — new absolute packet format.
pub const fn syn_model_newabs(model_id: u32) -> bool {
    model_id & (1 << 7) != 0
}

/// `SYN_MODEL_PEN(m)`: model-ID bit 6 — pen sensing.
pub const fn syn_model_pen(model_id: u32) -> bool {
    model_id & (1 << 6) != 0
}

/// `SYN_CAP_EXTENDED(c)`: capability bit 23 — extended capability
/// bits present, which also means W mode is supported.
pub const fn syn_cap_extended(capabilities: u32) -> bool {
    capabilities & (1 << 23) != 0
}

/// `SYN_CAP_SUBMODEL_ID(c)`: capability bits 15–8.
pub const fn syn_cap_submodel_id(capabilities: u32) -> u32 {
    (capabilities & 0x00ff00) >> 8
}

/// `SYN_EXT_CAP_REQUESTS(c)`: capability bits 22–20 — how many
/// extended-capability queries the pad answers.
pub const fn syn_ext_cap_requests(capabilities: u32) -> u32 {
    (capabilities & 0x700000) >> 20
}

/// `SYN_CAP_MULTI_BUTTON_NO(ec)`: extended-capability bits 15–12.
pub const fn syn_cap_multi_button_no(ext_cap: u32) -> u32 {
    (ext_cap & 0x00f000) >> 12
}

/// `SYN_CAP_MAX_DIMENSIONS(ex0c)`: ext-cap-0x0c bit 17 — the pad
/// answers the max-coordinates query (0x0d).
pub const fn syn_cap_max_dimensions(ext_cap_0c: u32) -> bool {
    ext_cap_0c & 0x020000 != 0
}

/// `SYN_CAP_MIN_DIMENSIONS(ex0c)`: ext-cap-0x0c bit 13 — the pad
/// answers the min-coordinates query (0x0f).
pub const fn syn_cap_min_dimensions(ext_cap_0c: u32) -> bool {
    ext_cap_0c & 0x002000 != 0
}

/// `SYN_CAP_ADV_GESTURE(ex0c)`: ext-cap-0x0c bit 19.
pub const fn syn_cap_adv_gesture(ext_cap_0c: u32) -> bool {
    ext_cap_0c & 0x080000 != 0
}

/// `SYN_CAP_IMAGE_SENSOR(ex0c)`: ext-cap-0x0c bit 11.
pub const fn syn_cap_image_sensor(ext_cap_0c: u32) -> bool {
    ext_cap_0c & 0x000800 != 0
}

/// `SYN_ID_MAJOR(i)`: identify low nibble of the third byte.
pub const fn syn_id_major(identity: u32) -> u32 {
    identity & 0x0f
}

/// `SYN_ID_MINOR(i)`: identify first byte.
pub const fn syn_id_minor(identity: u32) -> u32 {
    (identity >> 16) & 0xff
}

/// `SYN_ID_FULL(i)`: `(major << 8) | minor`.
pub const fn syn_id_full(identity: u32) -> u32 {
    (syn_id_major(identity) << 8) | syn_id_minor(identity)
}

/// `SYN_ID_IS_SYNAPTICS(i)`: identify middle byte is `0x47`.
pub const fn syn_id_is_synaptics(identity: u32) -> bool {
    ((identity >> 8) & 0xff) == 0x47
}

/// `SYN_ID_DISGEST_SUPPORTED(i)`: major version >= 4.
pub const fn syn_id_disgest_supported(identity: u32) -> bool {
    syn_id_major(identity) >= 4
}

// ── Detected hardware / active protocol ───────────────────────────────────

/// What the vendor probes found behind the AUX channel. Distinct
/// from [`PsmouseProtocol`]: a Synaptics pad can still run the
/// standard relative protocol until absolute mode is enabled.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PsmouseHardware {
    /// No vendor protocol detected (plain mouse or unknown pad).
    Generic = 0,
    /// Synaptics pad (`synaptics_detect` matched).
    Synaptics = 1,
}

impl PsmouseHardware {
    pub fn as_str(self) -> &'static str {
        match self {
            PsmouseHardware::Generic => "generic",
            PsmouseHardware::Synaptics => "Synaptics",
        }
    }
}

/// Active packet protocol negotiated on the AUX channel.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PsmouseProtocol {
    /// Bare 3-byte PS/2 packets.
    Standard = 0,
    /// Synaptics absolute mode: 6-byte packets.
    SynapticsAbsolute = 6,
}

impl PsmouseProtocol {
    /// Movement-packet length in bytes for this protocol.
    pub fn packet_len(self) -> usize {
        match self {
            PsmouseProtocol::Standard => 3,
            PsmouseProtocol::SynapticsAbsolute => 6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PsmouseProtocol::Standard => "PS/2",
            PsmouseProtocol::SynapticsAbsolute => "SynPS/2",
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
        _ => PsmouseHardware::Generic,
    }
}

pub fn protocol() -> PsmouseProtocol {
    match PROTOCOL.load(Ordering::Acquire) {
        6 => PsmouseProtocol::SynapticsAbsolute,
        _ => PsmouseProtocol::Standard,
    }
}

/// Packet length for the active protocol (3 or 6 bytes).
pub fn packet_len() -> usize {
    protocol().packet_len()
}

/// Record the negotiation result. Called once from
/// `i8042_mouse::init`, before IRQ 12 is armed.
pub fn set_detected(hw: PsmouseHardware, proto: PsmouseProtocol) {
    HARDWARE.store(hw as u8, Ordering::Release);
    PROTOCOL.store(proto as u8, Ordering::Release);
}

/// Test-only: force a protocol (lets packet fixtures feed 6-byte
/// packets without a device). `__reset_for_test` in `i8042_mouse`
/// restores `Standard`.
pub fn set_protocol_for_test(proto: PsmouseProtocol) {
    PROTOCOL.store(proto as u8, Ordering::Release);
}

// ── Transport ─────────────────────────────────────────────────────────────

/// Byte transport to the PS/2 device. The real implementation lives
/// in `i8042_mouse` (0xD4-prefixed port I/O); tests use a fake that
/// records sends and replays canned replies, so the query/mode
/// sequences are fixture-pinned byte-for-byte instead of trusted
/// from the impl.
pub trait Ps2Transport {
    /// Send one byte to the device. Returns `true` if the device ACKed
    /// (`0xFA`).
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
    /// Synaptics query / mode-set mechanism.
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

// ── Query + mode set ───────────────────────────────────────────────────────

/// Hardware identity read back by [`synaptics_query_hardware`]
/// (Linux `struct synaptics_data` fields this lane uses). Zero
/// means "unqueried / unsupported" for the optional fields
/// (`x_res`/`y_res`, `x_min`/`x_max`/`y_min`/`y_max`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SynapticsHw {
    /// Identify triple as one 24-bit value.
    pub identity: u32,
    /// Model-ID triple as one 24-bit value.
    pub model_id: u32,
    /// Firmware-ID triple as one 24-bit value.
    pub firmware_id: u32,
    /// Board ID (from the QUERY MODES response).
    pub board_id: u32,
    /// Capability triple as one 24-bit value.
    pub capabilities: u32,
    /// Extended capabilities (0x09 query) as one 24-bit value.
    pub ext_cap: u32,
    /// Extended capabilities 0x0c as one 24-bit value.
    pub ext_cap_0c: u32,
    /// X resolution in units/mm (0 if the pad does not answer).
    pub x_res: u32,
    /// Y resolution in units/mm (0 if the pad does not answer).
    pub y_res: u32,
    /// Queried minimum X (0 if unqueried — use the nominal edge).
    pub x_min: u32,
    /// Queried maximum X (0 if unqueried — use the nominal edge).
    pub x_max: u32,
    /// Queried minimum Y (0 if unqueried — use the nominal edge).
    pub y_min: u32,
    /// Queried maximum Y (0 if unqueried — use the nominal edge).
    pub y_max: u32,
    /// Packet flavour selected by `SYN_MODEL_NEWABS(model_id)`.
    pub newabs: bool,
    /// Mode byte actually programmed (Linux `priv->mode`).
    pub mode: u8,
}

/// Why absolute-mode enablement failed. Any failure leaves the pad
/// in relative mode (the caller keeps the 3-byte protocol); only
/// `ModeSet` needs the best-effort re-assert of mode 0, which
/// [`synaptics_enable_absolute`] performs before returning.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SynapticsEnableError {
    /// The Synaptics knock did not match (not a Synaptics pad).
    Detect,
    /// A hardware query failed or answered inconsistently.
    Query,
    /// The mode-set sequence was not accepted.
    ModeSet,
}

/// One Synaptics query (Linux `synaptics_send_cmd`): the query
/// number as a sliced command, then `GETINFO`, which returns the
/// 3-byte response.
pub fn synaptics_send_cmd<T: Ps2Transport>(t: &mut T, query: u8, resp: &mut [u8; 3]) -> bool {
    if !t.sliced_command(query) {
        return false;
    }
    if !t.send(CMD_GET_INFO) {
        return false;
    }
    t.recv_exact(resp)
}

/// Read the touchpad hardware (Linux `synaptics_query_hardware`,
/// in `__synaptics_init` order): identify → model → firmware →
/// board → capability → resolution. The identify/model/firmware/
/// board/capability queries are fatal on failure; the resolution
/// and extended-coordinate queries are best-effort, exactly as in
/// Linux (a pad that does not answer them simply reports 0).
pub fn synaptics_query_hardware<T: Ps2Transport>(
    t: &mut T,
) -> Result<SynapticsHw, SynapticsEnableError> {
    let mut hw = SynapticsHw::default();
    let mut r = [0u8; 3];

    // Identify.
    if !synaptics_send_cmd(t, SYN_QUE_IDENTIFY, &mut r) {
        return Err(SynapticsEnableError::Query);
    }
    hw.identity = ((r[0] as u32) << 16) | ((r[1] as u32) << 8) | r[2] as u32;
    if !syn_id_is_synaptics(hw.identity) {
        return Err(SynapticsEnableError::Query);
    }

    // Model ID.
    if !synaptics_send_cmd(t, SYN_QUE_MODEL, &mut r) {
        return Err(SynapticsEnableError::Query);
    }
    hw.model_id = ((r[0] as u32) << 16) | ((r[1] as u32) << 8) | r[2] as u32;
    hw.newabs = syn_model_newabs(hw.model_id);

    // Firmware ID.
    if !synaptics_send_cmd(t, SYN_QUE_FIRMWARE_ID, &mut r) {
        return Err(SynapticsEnableError::Query);
    }
    hw.firmware_id = ((r[0] as u32) << 16) | ((r[1] as u32) << 8) | r[2] as u32;

    // Board ID (encoded in the QUERY MODES response).
    if !synaptics_send_cmd(t, SYN_QUE_MODES, &mut r) {
        return Err(SynapticsEnableError::Query);
    }
    hw.board_id = (((r[0] & 0xfc) as u32) << 6) | r[1] as u32;

    // Capabilities.
    if !synaptics_send_cmd(t, SYN_QUE_CAPABILITIES, &mut r) {
        return Err(SynapticsEnableError::Query);
    }
    hw.capabilities = ((r[0] as u32) << 16) | ((r[1] as u32) << 8) | r[2] as u32;
    // Older firmwares had submodel ID fixed to 0x47.
    if syn_id_full(hw.identity) < 0x705 && syn_cap_submodel_id(hw.capabilities) != 0x47 {
        return Err(SynapticsEnableError::Query);
    }
    // Unless capExtended is set the rest of the flags should be ignored.
    if !syn_cap_extended(hw.capabilities) {
        hw.capabilities = 0;
    }
    if syn_ext_cap_requests(hw.capabilities) >= 1 {
        // A pad that claims extended capabilities but does not
        // answer only loses the extended bits (Linux warns and
        // continues).
        if synaptics_send_cmd(t, SYN_QUE_EXT_CAPAB, &mut r) {
            hw.ext_cap = ((r[0] as u32) << 16) | ((r[1] as u32) << 8) | r[2] as u32;
            // If nExtBtn is greater than 8 it should be considered
            // invalid and treated as 0.
            if syn_cap_multi_button_no(hw.ext_cap) > 8 {
                hw.ext_cap &= 0xff0fff;
            }
        }
    }
    if syn_ext_cap_requests(hw.capabilities) >= 4 {
        if synaptics_send_cmd(t, SYN_QUE_EXT_CAPAB_0C, &mut r) {
            hw.ext_cap_0c = ((r[0] as u32) << 16) | ((r[1] as u32) << 8) | r[2] as u32;
        }
    }

    // Resolution and reported coordinate limits (major >= 4 only).
    if syn_id_major(hw.identity) >= 4 {
        if synaptics_send_cmd(t, SYN_QUE_RESOLUTION, &mut r) {
            if r[0] != 0 && (r[1] & 0x80) != 0 && r[2] != 0 {
                hw.x_res = r[0] as u32;
                hw.y_res = r[2] as u32;
            }
        }
        if syn_ext_cap_requests(hw.capabilities) >= 5
            && syn_cap_max_dimensions(hw.ext_cap_0c)
            && synaptics_send_cmd(t, SYN_QUE_EXT_MAX_COORDS, &mut r)
        {
            hw.x_max = ((r[0] as u32) << 5) | (((r[1] & 0x0f) as u32) << 1);
            hw.y_max = ((r[2] as u32) << 5) | (((r[1] & 0xf0) as u32) >> 3);
        }
        if syn_ext_cap_requests(hw.capabilities) >= 7
            && syn_cap_min_dimensions(hw.ext_cap_0c)
            && synaptics_send_cmd(t, SYN_QUE_EXT_MIN_COORDS, &mut r)
        {
            hw.x_min = ((r[0] as u32) << 5) | (((r[1] & 0x0f) as u32) << 1);
            hw.y_min = ((r[2] as u32) << 5) | (((r[1] & 0xf0) as u32) >> 3);
        }
    }

    Ok(hw)
}

/// Set the touchpad mode byte by special commands (Linux
/// `synaptics_mode_cmd`): the mode byte as a sliced command, then
/// `SETRATE(SYN_PS_SET_MODE2)` commits it.
pub fn synaptics_mode_cmd<T: Ps2Transport>(t: &mut T, mode: u8) -> bool {
    if !t.sliced_command(mode) {
        return false;
    }
    t.send_param(CMD_SET_RATE, SYN_PS_SET_MODE2)
}

/// Compose the absolute-mode byte (Linux `synaptics_set_mode`):
/// `ABSOLUTE`, plus `HIGH_RATE` when the report rate is >= 80,
/// plus `W_MODE` when the pad reports extended capabilities, plus
/// `DISABLE_GESTURE` when the identity major version is >= 4
/// (Linux sets `disable_gesture` for those pads in
/// `__synaptics_init`). Typical modern pad at rate 100:
/// `0x80 | 0x40 | 0x01 | 0x04 = 0xC5` (Guide Fig 2-15 `$C1`
/// plus the Linux gesture bit).
pub fn synaptics_mode_byte(hw: &SynapticsHw, rate: u32) -> u8 {
    let mut mode = SYN_BIT_ABSOLUTE_MODE;
    if syn_id_disgest_supported(hw.identity) {
        mode |= SYN_BIT_DISABLE_GESTURE;
    }
    if rate >= 80 {
        mode |= SYN_BIT_HIGH_RATE;
    }
    if syn_cap_extended(hw.capabilities) {
        mode |= SYN_BIT_W_MODE;
    }
    mode
}

/// Full absolute-mode enablement (Linux `__synaptics_init` minus
/// the reset, which the caller already performed): detect → query
/// hardware → set the absolute mode byte.
///
/// Precondition: the device was reset and set to defaults, and
/// data reporting is still disabled (the Guide requires the pad
/// to be disabled before the mode-set sequence; the caller sends
/// Enable `0xF4` afterwards to start the 6-byte packet stream).
/// On any error the pad stays in relative mode and the caller
/// keeps the 3-byte protocol.
pub fn synaptics_enable_absolute<T: Ps2Transport>(
    t: &mut T,
    rate: u32,
) -> Result<SynapticsHw, SynapticsEnableError> {
    if !detect_synaptics(t) {
        return Err(SynapticsEnableError::Detect);
    }
    let mut hw = synaptics_query_hardware(t)?;
    let mode = synaptics_mode_byte(&hw, rate);
    if !synaptics_mode_cmd(t, mode) {
        // Best-effort: force the pad back to relative mode so a
        // half-committed mode byte cannot leave the IRQ path
        // parsing 3-byte packets from an absolute-mode pad.
        let _ = synaptics_mode_cmd(t, 0);
        return Err(SynapticsEnableError::ModeSet);
    }
    hw.mode = mode;
    Ok(hw)
}

// ── Synaptics absolute-packet decoders (pure) ──────────────────────────────
//
// From Linux `synaptics_parse_hw_state` (`drivers/input/mouse/synaptics.c`).
// 6-byte absolute packets, two layouts selected by model
// (`SYN_MODEL_NEWABS`): NEWABS on current pads, OLDABS on old ones.
// Both share the wrap-around rule (values above the positive limit
// are negative values truncated to the 13-bit reporting range;
// a value exactly at the limit clamps to the axis maximum) and the
// Y inversion (`synaptics_invert_y`: the pad reports Y bottom to
// top, userspace expects top to bottom).

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

/// Wrap-around conversion (Linux `synaptics_parse_hw_state` tail):
/// above `SYN_MAX_POSITIVE` the value is a truncated negative;
/// exactly at the limit it is the edge-indeterminate maximum.
fn synaptics_wrap_axis(value: i32) -> i32 {
    if value > SYN_MAX_POSITIVE {
        value - (1 << SYN_ABS_POS_BITS)
    } else if value == SYN_MAX_POSITIVE {
        SYN_X_MAX
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
    let x = synaptics_wrap_axis(
        ((buf[3] as i32 & 0x10) << 8) | ((buf[1] as i32 & 0x0f) << 8) | buf[4] as i32,
    );
    let y = synaptics_wrap_axis(
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
    let x = synaptics_wrap_axis(((buf[1] as i32 & 0x1f) << 8) | buf[2] as i32);
    let y = synaptics_wrap_axis(((buf[4] as i32 & 0x1f) << 8) | buf[5] as i32);
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
#[repr(u8)]
pub enum SynapticsPktType {
    /// NEWABS, not yet classified strict/relaxed (validates with
    /// the relaxed masks, as Linux does for `SYN_NEWABS`).
    NewAbs = 0,
    /// NEWABS, strict masks.
    NewAbsStrict = 1,
    /// NEWABS, relaxed masks.
    NewAbsRelaxed = 2,
    /// OLDABS.
    OldAbs = 3,
}

impl SynapticsPktType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => SynapticsPktType::NewAbsStrict,
            2 => SynapticsPktType::NewAbsRelaxed,
            3 => SynapticsPktType::OldAbs,
            _ => SynapticsPktType::NewAbs,
        }
    }

    /// Initial streaming packet type for a pad (Linux
    /// `__synaptics_init`: `SYN_MODEL_NEWABS(model_id) ?
    /// SYN_NEWABS : SYN_OLDABS`).
    pub fn initial(newabs: bool) -> Self {
        if newabs {
            SynapticsPktType::NewAbs
        } else {
            SynapticsPktType::OldAbs
        }
    }
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

/// Classify a NEWABS pad as strict or relaxed from its first
/// full packet (Linux `synaptics_detect_pkt_type`): strict when
/// all five validated bytes pass the strict masks.
pub fn synaptics_detect_pkt_type(buf: &[u8; 6]) -> SynapticsPktType {
    for i in 0..5 {
        if !synaptics_validate_byte(buf, i, SynapticsPktType::NewAbsStrict) {
            return SynapticsPktType::NewAbsRelaxed;
        }
    }
    SynapticsPktType::NewAbsStrict
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
