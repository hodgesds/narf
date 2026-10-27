//! AMD Sensor Fusion Hub (SFH / MP2) HID transport.
//!
//! Stage-5 AMD laptops (Renoir / Lucienne, Phoenix) expose their
//! motion / light / presence sensors through the MP2 coprocessor's
//! Sensor Fusion Hub function. This module is the transport that was
//! missing from the input stack: it probes the MP2 PCI function,
//! speaks the SFH mailbox protocol, and feeds HID input reports into
//! the shared decode layer in [`crate::hid_sensor`], which publishes
//! `SensorEvent`s on the sensor ring for consumers (issue #773 owns
//! the userspace surface on top of that ring).
//!
//! ## Hardware contract
//!
//! Grounded in AMD's SFH design as implemented by Linux's
//! `drivers/hid/amd-sfh-hid` (GPL-2.0; register layouts, command
//! encodings and the base-info structures are AMD's published
//! interface, restated here):
//!
//! | PCI ID        | Generation | SoCs              | Data path            |
//! |---------------|------------|-------------------|----------------------|
//! | 1022:15E4     | MP2 1.0    | Renoir / Cezanne  | mailbox + DMA report |
//! |               |            |                   | buffers              |
//! | 1022:164A     | MP2 1.1    | Van Gogh / Phoenix| mailbox + firmware   |
//! |               |            |                   | shared-memory window |
//!
//! BAR2 is the register window (must be ≥ 128 KiB; the highest
//! register used is 0x10958). The mailbox is a pair of 32-bit
//! register banks: C2P (CPU→processor) at 0x10500 + 4n and P2C at
//! 0x10680 + 4n.
//!
//! ### MP2 1.0 discovery and commands
//!
//! `P2C_MSG(3)` is the ACS register. Its low nibble selects the
//! command layout: `2` ⇒ the V2 layout, anything else ⇒ the legacy
//! V1 layout. The remaining bits are the sensor-presence mask:
//! sensor *n* is present iff bit `4 + n` is set. Sensor indices on
//! 1.0: accel 0, gyro 1, mag 2, tablet-mode (OP) 15, human-presence
//! (HPD) 16, ALS 19, colour (ACS) 22. Commands (both layouts):
//! NO_OP 0, ENABLE_SENSOR 1, DISABLE_SENSOR 2, STOP_ALL_SENSORS 8;
//! firmware answers on `P2C_MSG(0)` with SENSOR_ENABLED (4) /
//! SENSOR_DISABLED (5) on V2 (V1 start/stop are fire-and-forget).
//!
//! On V2, an enabled sensor's firmware writes HID input reports
//! into the DMA buffer whose address the driver passed at ENABLE.
//! (Linux programs ALS with `USE_C2P_REG` delivery on V2 instead of
//! a DRAM buffer; this driver requests DRAM delivery for every
//! sensor — see "Known gaps" below.)
//!
//! ### MP2 1.1 discovery and commands
//!
//! The data window is firmware-owned: its physical base is
//! `readl(C2P_MSG(22)) << 21`, 128 KiB. At offset 0 sits
//! `sfh_base_info` (96 bytes): platform info @0, firmware version
//! @4 (must become non-zero once firmware has configured), the
//! sensor-presence mask (u16) @8, and per-sensor properties @16.
//! Sensor indices on 1.1: accel 0, gyro 1, mag 2, SRA 3, ALS 4,
//! HPD 5. Per-sensor data lives at `1024 + idx * 256`, starting
//! with `sfh_common_data` { timestamp u64, intr_cnt u32, state
//! word u32 } followed by the payload: three IEEE-754 f32 axis
//! values for accel/gyro/mag, an f32-bits lux for ALS. HPD state
//! on 1.1 (pre-1.2) is read from `C2P_MSG(4)` (presence is the
//! 2-bit field at bits [25:24]). Commands pack into one word:
//! sensor_id [3:0], cmd_id [7:4], sub_cmd_id [15:8],
//! sub_cmd_value [27:16], intr_disable [31]; ENABLE carries
//! sub_cmd_value 1. Responses land on `P2C_MSG(0)`:
//! response [7:0] (0 = success), sensor_id [11:8], cmd_id [15:12].
//!
//! ### HID presentation
//!
//! Like Linux, the driver synthesises one HID device per sensor:
//! the static descriptors below describe exactly the report format
//! the transport produces/consumes — report ID, sensor-state byte,
//! sensor-event byte, then the data fields — plus a Feature report
//! carrying the standard REPORT_INTERVAL property (usage 0x030E),
//! which is also the firmware mailbox `period` programmed at
//! ENABLE time. The descriptors are parsed by `narf_hid` and turned
//! into profiles by [`crate::hid_sensor::enumerate_sensors`]; every
//! report is decoded by [`crate::hid_sensor::decode_report`].
//!
//! Unit contract (the transport owns these conversions; the
//! descriptor declares 32-bit fields with unit exponent −2):
//! - accel fields are centi-m/s²; events are milli-g
//!   (`milli_g = centi * 1000 / 981`, 1 g = 9.80665 m/s²).
//! - gyro fields are centi-deg/s; events are milli-deg/s (×10).
//!   MP2 1.1 firmware supplies rad/s, converted at report build.
//! - mag fields are centi-µT; events are µT (÷100).
//! - ALS fields are whole lux; HPD fields are the 2-bit presence
//!   value (non-zero = present).
//!
//! ## Composition conflict (issue #1046)
//!
//! `drivers/video`'s `amd_mp2_isp` scaffold registers PCI matches
//! for the same two device IDs and is registered earlier in boot
//! composition, so on current main it binds the MP2 function first
//! and this transport never probes on real hardware. That
//! arbitration is tracked in #1046; this module registers its
//! matches correctly and does not touch the video crate.
//!
//! ## Known gaps (named, not hidden)
//!
//! - ALS on MP2 1.0/V2 with `USE_C2P_REG` delivery: this driver
//!   enables ALS with a DRAM buffer like every other sensor. If
//!   firmware insists on C2P-register delivery there, ALS reports
//!   will not arrive (other sensors are unaffected); the C2P read
//!   path is a follow-up once silicon can confirm the packing.
//! - Tablet-mode (OP, 1.0 id 15 / 1.1 via OP mode register),
//!   colour (ACS, id 22) and SRA (1.1 id 3) sensors are discovered
//!   and logged but have no HID sensor profile in the shared
//!   taxonomy, so they are not enabled.
//! - MP2 1.2 (1022:1152, Strix) uses the 1.1 protocol with an
//!   alternate command register map; not registered here.
//! - Feature-report SET from userspace is not wired (no consumer
//!   yet); `set_period` is the in-kernel path and re-programmes
//!   the firmware period via the mailbox.
//!
//! TCB: this module lives in `drivers/input`, outside the TCB
//! (frame/ + memory/ domain manager + capabilities/ core +
//! scheduler executor core + security-model/).

use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_lib::sync::IrqSafeSpinLock;

use crate::hid_sensor::{self, HidSensorKind, HidSensorProfile, SensorEvent};

// ── PCI identity ─────────────────────────────────────────────────

/// AMD vendor ID.
pub const AMD_VENDOR: u16 = 0x1022;
/// MP2 1.0 — Renoir / Cezanne.
pub const MP2_DID_1_0: u16 = 0x15E4;
/// MP2 1.1 — Van Gogh / Phoenix.
pub const MP2_DID_1_1: u16 = 0x164A;

/// All (vendor, device) pairs this transport claims.
pub const PCI_IDS: &[(u16, u16)] = &[(AMD_VENDOR, MP2_DID_1_0), (AMD_VENDOR, MP2_DID_1_1)];

/// BAR holding the MP2 register window.
const BAR_REGS: u8 = 2;
/// Minimum BAR2 length: the register window spans 0x11000 bytes
/// (highest register C2P_MSG(22) at 0x10558 on 1.1, ACS/status
/// block up to 0x10958 on the alternate map; 128 KiB is what
/// firmware documents and Linux maps).
pub const MP2_BAR_MIN_LEN: usize = 0x1_1000;

// ── Register map (standard MP2 window) ───────────────────────────

/// C2P_MSG(n): CPU→MP2 mailbox registers.
pub const fn c2p_msg(n: u64) -> u64 {
    0x10500 + 4 * n
}
/// P2C_MSG(n): MP2→CPU mailbox registers.
pub const fn p2c_msg(n: u64) -> u64 {
    0x10680 + 4 * n
}

/// ACS register (P2C_MSG(3)): low nibble = discovery status,
/// bits [4..] = sensor-presence mask on MP2 1.0.
const ACS_REG: u64 = p2c_msg(3);
/// ACS low-nibble value selecting the V2 command layout.
const DISCOVERY_STATUS_V2: u32 = 2;

// ── Mailbox commands ─────────────────────────────────────────────

/// Mailbox command IDs (shared by both generations/layouts).
pub mod cmd {
    /// No operation.
    pub const NO_OP: u8 = 0;
    /// Enable one sensor.
    pub const ENABLE_SENSOR: u8 = 1;
    /// Disable one sensor.
    pub const DISABLE_SENSOR: u8 = 2;
    /// Stop every sensor (1.0 STOP_ALL / 1.1 DISABLE with id 0xF).
    pub const STOP_ALL_SENSORS: u8 = 8;
}

/// Firmware response codes (P2C_MSG(0) on 1.0/V2).
pub mod resp {
    /// Sensor is now enabled.
    pub const SENSOR_ENABLED: u8 = 4;
    /// Sensor is now disabled.
    pub const SENSOR_DISABLED: u8 = 5;
}

/// Default report period programmed at ENABLE (ms). Also the
/// feature-report REPORT_INTERVAL default.
pub const DEFAULT_PERIOD_MS: u16 = 80;

/// Bounded wait for a mailbox response / firmware-ready poll.
pub const RESPONSE_TIMEOUT_MS: u64 = 200;
/// Bounded wait for MP2 1.1 firmware to publish base info.
pub const FW_READY_TIMEOUT_MS: u64 = 2_000;

/// Per-sensor DMA report buffer length (1.0). Reports are ≤ 15
/// bytes; the headroom absorbs firmware report-format growth
/// (e.g. ALS colour fields) without re-allocation.
pub const REPORT_BUF_LEN: usize = 256;

/// Maximum input-report length including the report-ID byte
/// (accel/gyro/mag reports are the longest at 15 bytes).
pub const MAX_REPORT_LEN: usize = 32;

/// Sensor slots tracked per hub. 1.0 can report up to 7 sensors,
/// 1.1 up to 6; 8 covers both with margin.
pub const MAX_SENSORS: usize = 8;

// ── Sensor tables ────────────────────────────────────────────────

/// MP2 generation, from the PCI device ID.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mp2Gen {
    /// MP2 1.0 (1022:15E4): mailbox + DMA report buffers.
    V1_0,
    /// MP2 1.1 (1022:164A): mailbox + firmware shared window.
    V1_1,
}

impl Mp2Gen {
    /// Generation for a PCI device ID, or `None` if not an SFH
    /// function this transport claims.
    pub fn from_did(did: u16) -> Option<Self> {
        match did {
            MP2_DID_1_0 => Some(Mp2Gen::V1_0),
            MP2_DID_1_1 => Some(Mp2Gen::V1_1),
            _ => None,
        }
    }
}

/// MP2 1.0 mailbox command layout, selected by the ACS register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmdLayout {
    /// Legacy layout: 8-bit cmd / 8-bit sensor / 16-bit period,
    /// DMA address in C2P_MSG(2), params in C2P_MSG(1).
    V1,
    /// V2 layout: packed command word, DMA address in C2P_MSG(1),
    /// responses on P2C_MSG(0).
    V2,
}

// Sensor indices, MP2 1.0.
const SID_1_0_ACCEL: u8 = 0;
const SID_1_0_GYRO: u8 = 1;
const SID_1_0_MAG: u8 = 2;
const SID_1_0_OP: u8 = 15;
const SID_1_0_HPD: u8 = 16;
const SID_1_0_ALS: u8 = 19;
const SID_1_0_ACS: u8 = 22;
/// All 1.0 sensor indices the ACS mask can report.
const SIDS_1_0: &[u8] = &[
    SID_1_0_ACCEL,
    SID_1_0_GYRO,
    SID_1_0_MAG,
    SID_1_0_OP,
    SID_1_0_HPD,
    SID_1_0_ALS,
    SID_1_0_ACS,
];

// Sensor indices, MP2 1.1.
const SID_1_1_ACCEL: u8 = 0;
const SID_1_1_GYRO: u8 = 1;
const SID_1_1_MAG: u8 = 2;
const SID_1_1_SRA: u8 = 3;
const SID_1_1_ALS: u8 = 4;
const SID_1_1_HPD: u8 = 5;
/// All 1.1 sensor indices the base-info mask can report.
const SIDS_1_1: &[u8] = &[
    SID_1_1_ACCEL,
    SID_1_1_GYRO,
    SID_1_1_MAG,
    SID_1_1_SRA,
    SID_1_1_ALS,
    SID_1_1_HPD,
];

// ── Static HID descriptors ───────────────────────────────────────
//
// One descriptor per sensor kind, byte-format-faithful to the
// report layout the transport exchanges with firmware (and, on
// 1.1, synthesises): [state u8][event u8][data…] after the
// report-ID prefix byte. The feature section carries only the
// REPORT_INTERVAL property — the one property with a real
// transport channel (the mailbox period). Report IDs mirror
// Linux's per-sensor assignment (accel 1, gyro 2, mag 3, ALS 4,
// HPD 5).

/// HID descriptor + presentation facts for one sensor kind.
#[derive(Clone, Debug)]
pub struct HidDef {
    /// Decode-layer taxonomy kind.
    pub kind: HidSensorKind,
    /// Raw HID report descriptor bytes.
    pub descriptor: &'static [u8],
    /// Input report ID inside the descriptor.
    pub report_id: u8,
}

/// Accelerometer descriptor (report ID 1, usage 0x0073).
pub const ACCEL_DEF: HidDef = HidDef {
    kind: HidSensorKind::Accelerometer3D,
    report_id: 1,
    descriptor: &[
        0x05, 0x20, // Usage Page (Sensor)
        0x09, 0x73, // Usage (Motion: Accelerometer 3D)
        0xA1, 0x01, // Collection (Application)
        0x85, 0x01, //   Report ID (1)
        // Input: sensor state (0x0201), 8-bit
        0x0A, 0x01, 0x02, 0x15, 0x00, 0x25, 0x06, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00,
        // Input: sensor event (0x0202), 8-bit
        0x0A, 0x02, 0x02, 0x15, 0x00, 0x25, 0x05, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00,
        // Input: accel X (0x0453), i32, unit exponent -2
        0x0A, 0x53, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // Input: accel Y (0x0454)
        0x0A, 0x54, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // Input: accel Z (0x0455)
        0x0A, 0x55, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // Feature: report interval (0x030E), u32 ms
        0x85, 0x01, 0x0A, 0x0E, 0x03, 0x15, 0x00, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0x75, 0x20, 0x95,
        0x01, 0xB1, 0x02, 0xC0, // End Collection
    ],
};

/// Gyroscope descriptor (report ID 2, usage 0x0076).
pub const GYRO_DEF: HidDef = HidDef {
    kind: HidSensorKind::Gyrometer3D,
    report_id: 2,
    descriptor: &[
        0x05, 0x20, 0x09, 0x76, 0xA1, 0x01, 0x85, 0x02, // Page, Gyro 3D, Collection, ID 2
        0x0A, 0x01, 0x02, 0x15, 0x00, 0x25, 0x06, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, // state
        0x0A, 0x02, 0x02, 0x15, 0x00, 0x25, 0x05, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, // event
        // gyro X (0x0457)
        0x0A, 0x57, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // gyro Y (0x0458)
        0x0A, 0x58, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // gyro Z (0x0459)
        0x0A, 0x59, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // Feature: report interval
        0x85, 0x02, 0x0A, 0x0E, 0x03, 0x15, 0x00, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0x75, 0x20, 0x95,
        0x01, 0xB1, 0x02, 0xC0,
    ],
};

/// Magnetometer descriptor (report ID 3, usage 0x0083).
pub const MAG_DEF: HidDef = HidDef {
    kind: HidSensorKind::Magnetometer3D,
    report_id: 3,
    descriptor: &[
        0x05, 0x20, 0x09, 0x83, 0xA1, 0x01, 0x85,
        0x03, // Page, Magnetometer 3D, Collection, ID 3
        0x0A, 0x01, 0x02, 0x15, 0x00, 0x25, 0x06, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, // state
        0x0A, 0x02, 0x02, 0x15, 0x00, 0x25, 0x05, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, // event
        // mag X (0x0485)
        0x0A, 0x85, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // mag Y (0x0486)
        0x0A, 0x86, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // mag Z (0x0487)
        0x0A, 0x87, 0x04, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xFF, 0xFF, 0xFF, 0x7F, 0x75, 0x20,
        0x95, 0x01, 0x55, 0x0E, 0x81, 0x02, // Feature: report interval
        0x85, 0x03, 0x0A, 0x0E, 0x03, 0x15, 0x00, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0x75, 0x20, 0x95,
        0x01, 0xB1, 0x02, 0xC0,
    ],
};

/// Ambient-light descriptor (report ID 4, usage 0x0041).
pub const ALS_DEF: HidDef = HidDef {
    kind: HidSensorKind::AmbientLight,
    report_id: 4,
    descriptor: &[
        0x05, 0x20, 0x09, 0x41, 0xA1, 0x01, 0x85, 0x04, // Page, ALS, Collection, ID 4
        0x0A, 0x01, 0x02, 0x15, 0x00, 0x25, 0x06, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, // state
        0x0A, 0x02, 0x02, 0x15, 0x00, 0x25, 0x05, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, // event
        // illuminance (0x04D1), u32 lux
        0x0A, 0xD1, 0x04, 0x15, 0x00, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0x75, 0x20, 0x95, 0x01, 0x55,
        0x00, 0x81, 0x02, // Feature: report interval
        0x85, 0x04, 0x0A, 0x0E, 0x03, 0x15, 0x00, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0x75, 0x20, 0x95,
        0x01, 0xB1, 0x02, 0xC0,
    ],
};

/// Human-presence descriptor (report ID 5). Presented through the
/// decode layer's Proximity kind with the HUMAN_PRESENCE data
/// usage (0x04B1) — the same presentation Linux's HPD HID device
/// effectively exposes (a presence flag, no distance channel).
pub const HPD_DEF: HidDef = HidDef {
    kind: HidSensorKind::Proximity,
    report_id: 5,
    descriptor: &[
        0x05, 0x20, 0x09, 0xC1, 0xA1, 0x01, 0x85, 0x05, // Page, Proximity, Collection, ID 5
        0x0A, 0x01, 0x02, 0x15, 0x00, 0x25, 0x06, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, // state
        0x0A, 0x02, 0x02, 0x15, 0x00, 0x25, 0x05, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, // event
        // human presence (0x04B1), 8-bit, 0..3 (2-bit field value)
        0x0A, 0xB1, 0x04, 0x15, 0x00, 0x25, 0x03, 0x75, 0x08, 0x95, 0x01, 0x81, 0x02,
        // Feature: report interval
        0x85, 0x05, 0x0A, 0x0E, 0x03, 0x15, 0x00, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0x75, 0x20, 0x95,
        0x01, 0xB1, 0x02, 0xC0,
    ],
};

/// HID presentation for a sensor index, or `None` for sensors
/// with no profile in the shared taxonomy (OP / ACS / SRA).
fn hid_def_for(gen: Mp2Gen, sensor_id: u8) -> Option<&'static HidDef> {
    match gen {
        Mp2Gen::V1_0 => match sensor_id {
            SID_1_0_ACCEL => Some(&ACCEL_DEF),
            SID_1_0_GYRO => Some(&GYRO_DEF),
            SID_1_0_MAG => Some(&MAG_DEF),
            SID_1_0_ALS => Some(&ALS_DEF),
            SID_1_0_HPD => Some(&HPD_DEF),
            _ => None,
        },
        Mp2Gen::V1_1 => match sensor_id {
            SID_1_1_ACCEL => Some(&ACCEL_DEF),
            SID_1_1_GYRO => Some(&GYRO_DEF),
            SID_1_1_MAG => Some(&MAG_DEF),
            SID_1_1_ALS => Some(&ALS_DEF),
            SID_1_1_HPD => Some(&HPD_DEF),
            _ => None,
        },
    }
}

// ── Errors ───────────────────────────────────────────────────────

/// Transport-level failure modes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SfhError {
    /// Discovery has not run (or found nothing) yet.
    NotDiscovered,
    /// Firmware did not answer a mailbox command in time.
    ResponseTimeout,
    /// Firmware answered with an unexpected response word.
    UnexpectedResponse(u32),
    /// MP2 1.1 firmware never published base info (fw_ver stayed 0).
    FirmwareNotReady,
    /// DMA report-buffer allocation failed (MP2 1.0).
    AllocFailed,
    /// A static descriptor failed to parse / enumerate.
    Descriptor,
    /// Slot index out of range / sensor has no HID profile.
    NoSuchSensor,
}

// ── Hardware access traits ───────────────────────────────────────
//
// The protocol core is written against these three traits so the
// fixture model can stand in for the silicon: `Mp2Bus` is the
// BAR2 register window, `SharedWindow` is the MP2 1.1
// firmware-owned data window, and `ReportBuffers` owns the
// host-side DMA report buffers (MP2 1.0). Production impls are
// below; the fixture impls live in the tests module and model the
// firmware side of the conversation.

/// BAR2 register-window access (32/64-bit MMIO).
pub trait Mp2Bus {
    /// Read a 32-bit register at byte offset `off`.
    fn read32(&self, off: u64) -> u32;
    /// Write a 32-bit register at byte offset `off`.
    fn write32(&self, off: u64, val: u32);
    /// Write a 64-bit value across two adjacent 32-bit registers
    /// starting at byte offset `off` (low word first).
    fn write64(&self, off: u64, val: u64);
}

/// Byte-readable shared-memory window (MP2 1.1 data window).
pub trait SharedWindow {
    /// Copy `out.len()` bytes from window offset `off`.
    fn copy_out(&self, off: usize, out: &mut [u8]);

    /// Read a little-endian u32 at `off`.
    fn read_u32(&self, off: usize) -> u32 {
        let mut b = [0u8; 4];
        self.copy_out(off, &mut b);
        u32::from_le_bytes(b)
    }
    /// Read a little-endian u16 at `off`.
    fn read_u16(&self, off: usize) -> u16 {
        let mut b = [0u8; 2];
        self.copy_out(off, &mut b);
        u16::from_le_bytes(b)
    }
}

/// Host-side report-buffer provider (MP2 1.0 DMA path).
pub trait ReportBuffers {
    /// Allocate a zeroed report buffer of `len` bytes; returns
    /// (DMA address to hand the firmware, buffer id).
    fn alloc(&mut self, len: usize) -> Option<(u64, usize)>;
    /// Copy the current buffer contents into `out`; returns the
    /// number of bytes copied.
    fn read(&self, id: usize, out: &mut [u8]) -> usize;
    /// Overwrite the buffer with `data` (zero-init / fixture
    /// firmware delivery).
    fn write(&mut self, id: usize, data: &[u8]);
}

// ── Production hardware access ───────────────────────────────────

/// Production `Mp2Bus` over the mapped BAR2.
#[derive(Debug)]
pub struct MmioBus {
    regs: narf_driver_runtime::MmioRegion,
}

impl MmioBus {
    /// Wrap a mapped BAR2 region.
    pub fn new(regs: narf_driver_runtime::MmioRegion) -> Self {
        Self { regs }
    }
    /// BAR length in bytes.
    pub fn len(&self) -> usize {
        self.regs.len as usize
    }
    /// Whether the BAR is empty (never for a real mapping).
    pub fn is_empty(&self) -> bool {
        self.regs.len == 0
    }
}

impl Mp2Bus for MmioBus {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: offsets used by the protocol core are within the
        // BAR whose length probe validated (≥ MP2_BAR_MIN_LEN);
        // the bus probe contract gives this driver exclusive
        // ownership of the function.
        unsafe { self.regs.read32(off) }
    }
    fn write32(&self, off: u64, val: u32) {
        // SAFETY: same contract as read32.
        unsafe { self.regs.write32(off, val) }
    }
    fn write64(&self, off: u64, val: u64) {
        // SAFETY: same contract as read32.
        unsafe { self.regs.write64(off, val) }
    }
}

/// Production `SharedWindow`: either absent (MP2 1.0) or a
/// physical base read through the kernel direct map (MP2 1.1).
#[derive(Debug)]
pub enum ProdWindow {
    /// No shared window (MP2 1.0).
    Null,
    /// Firmware window at this physical base address.
    Phys(u64),
}

impl SharedWindow for ProdWindow {
    fn copy_out(&self, off: usize, out: &mut [u8]) {
        let base = match self {
            ProdWindow::Null => {
                for b in out.iter_mut() {
                    *b = 0;
                }
                return;
            }
            ProdWindow::Phys(p) => *p,
        };
        for (i, b) in out.iter_mut().enumerate() {
            // SAFETY: the window is firmware-reserved RAM whose
            // base probe read from C2P_MSG(22); the direct map
            // covers all of RAM, and volatile byte reads cannot
            // fault on mapped RAM or tear a value we depend on
            // (multi-byte reads re-check via intr_cnt discipline).
            *b = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(base + (off + i) as u64).kernel_ptr::<u8>(),
                )
            };
        }
    }
}

/// The MP2 1.1 window physical base from the raw C2P_MSG(22)
/// value: `phys = readl(C2P_MSG(22)) << 21`.
pub fn window_base_from_c2p22(raw: u32) -> u64 {
    (raw as u64) << 21
}

/// Production `ReportBuffers` over coherent DMA allocations.
#[derive(Debug)]
pub struct DmaReportBuffers {
    bufs: Vec<narf_driver_runtime::DmaBuffer>,
    domain: narf_driver_runtime::DomainId,
}

impl DmaReportBuffers {
    /// New provider allocating in `domain`.
    pub fn new(domain: narf_driver_runtime::DomainId) -> Self {
        Self {
            bufs: Vec::new(),
            domain,
        }
    }
}

impl ReportBuffers for DmaReportBuffers {
    fn alloc(&mut self, len: usize) -> Option<(u64, usize)> {
        let buf = narf_driver_runtime::alloc_coherent(len, self.domain).ok()?;
        let addr = buf.dma_addr().raw();
        // Zero the buffer so "no report yet" reads as all-zeroes
        // (an all-zero report has sensor-state 0 = unknown and
        // decodes to a zero event only if firmware-shaped; the
        // pump's change detection treats the zero buffer as the
        // baseline, so no phantom event is emitted).
        let n = len;
        // SAFETY: cpu_mut_ptr resolves through the direct map for
        // the whole allocation; n == allocation length.
        unsafe {
            core::ptr::write_bytes(buf.cpu_mut_ptr::<u8>(), 0, n);
        }
        self.bufs.push(buf);
        Some((addr, self.bufs.len() - 1))
    }

    fn read(&self, id: usize, out: &mut [u8]) -> usize {
        let Some(buf) = self.bufs.get(id) else {
            return 0;
        };
        let n = out.len().min(REPORT_BUF_LEN);
        // SAFETY: buffer is a live coherent allocation of
        // REPORT_BUF_LEN bytes ≥ n; the device writes reports
        // into it concurrently, which coherent DMA permits — a
        // torn read at worst yields one skipped/garbled sample,
        // and decode validates the report ID before use.
        unsafe {
            core::ptr::copy_nonoverlapping(buf.cpu_ptr::<u8>(), out.as_mut_ptr(), n);
        }
        n
    }

    fn write(&mut self, id: usize, data: &[u8]) {
        let Some(buf) = self.bufs.get(id) else {
            return;
        };
        let n = data.len().min(REPORT_BUF_LEN);
        // SAFETY: as read(); CPU-side overwrite of our own buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf.cpu_mut_ptr::<u8>(), n);
        }
    }
}

// ── IEEE-754 conversion (integer-only) ───────────────────────────
//
// MP2 1.1 publishes sensor values as f32 bit patterns. The kernel
// decode path is integer-only, so conversion happens here with
// exact integer arithmetic on the IEEE-754 decomposition.

/// Convert an f32 bit pattern to milli-units (value × 1000),
/// rounding to nearest. Zero and subnormals → 0; ±inf / NaN and
/// overflow saturate to i32 range.
pub fn sfh_float_to_milli(bits: u32) -> i32 {
    let negative = bits >> 31 != 0;
    let exp = ((bits >> 23) & 0xFF) as i32;
    let mantissa = (bits & 0x7F_FFFF) as i64;
    if exp == 0 {
        return 0; // zero / subnormal: below milli resolution
    }
    if exp == 0xFF {
        return if negative { i32::MIN } else { i32::MAX };
    }
    // value = (2^23 + mantissa) * 2^(exp-127-23);
    // milli = value * 1000, computed with exact shifts.
    let significand = mantissa | 0x80_0000;
    let shift = exp - 127 - 23;
    let scaled = significand * 1000;
    let mag: i64 = if shift >= 0 {
        if shift >= 21 {
            i64::MAX // saturate; clamped below
        } else {
            scaled << shift
        }
    } else {
        let s = -shift;
        if s >= 63 {
            0
        } else {
            // round to nearest: add half a unit before shifting
            (scaled + (1i64 << (s - 1))) >> s
        }
    };
    let v = mag.clamp(0, i32::MAX as i64);
    if negative {
        -(v as i32)
    } else {
        v as i32
    }
}

/// Convert an f32 bit pattern to the nearest integer (round to
/// nearest, ties away from zero via the milli path).
pub fn sfh_float_round(bits: u32) -> i32 {
    let milli = sfh_float_to_milli(bits);
    if milli >= 0 {
        (milli + 500) / 1000
    } else {
        (milli - 500) / 1000
    }
}

// ── Hub core ─────────────────────────────────────────────────────

/// One discovered sensor.
#[derive(Clone, Debug)]
struct SensorSlot {
    sensor_id: u8,
    def: Option<&'static HidDef>,
    profile: Option<HidSensorProfile>,
    enabled: bool,
    suspended: bool,
    /// Report-buffer id (MP2 1.0), once allocated.
    buf: Option<usize>,
    /// DMA address paired with `buf`.
    buf_addr: u64,
    /// Input-report length in bytes, incl. report-ID prefix.
    report_len: usize,
    /// Last report bytes seen (MP2 1.0 change detection).
    last_report: [u8; MAX_REPORT_LEN],
    /// Whether `last_report` holds a real firmware report yet.
    have_report: bool,
    /// Last firmware interrupt counter (MP2 1.1 change detection).
    last_intr_cnt: u32,
    period_ms: u16,
}

impl SensorSlot {
    const fn empty() -> Self {
        Self {
            sensor_id: 0,
            def: None,
            profile: None,
            enabled: false,
            suspended: false,
            buf: None,
            buf_addr: 0,
            report_len: 0,
            last_report: [0; MAX_REPORT_LEN],
            have_report: false,
            last_intr_cnt: 0,
            period_ms: DEFAULT_PERIOD_MS,
        }
    }
}

/// SFH transport hub: owns the mailbox, the (optional) 1.1 data
/// window and the 1.0 report buffers, and drives discovered
/// sensors into the shared HID sensor decode layer.
pub struct SfhHub<B: Mp2Bus, W: SharedWindow, P: ReportBuffers> {
    bus: B,
    window: W,
    bufs: P,
    gen: Mp2Gen,
    layout: Option<CmdLayout>,
    slots: [SensorSlot; MAX_SENSORS],
    slot_count: usize,
    discovered: bool,
    /// Response-wait budget; fixtures shrink it.
    response_timeout_ms: u64,
    /// MP2 1.1 firmware-ready budget; fixtures shrink it.
    fw_ready_timeout_ms: u64,
    /// MP2 1.1 window sensor-data base offset (1024).
    data_base: usize,
}

impl<B: Mp2Bus, W: SharedWindow, P: ReportBuffers> core::fmt::Debug for SfhHub<B, W, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SfhHub")
            .field("gen", &self.gen)
            .field("layout", &self.layout)
            .field("slot_count", &self.slot_count)
            .field("discovered", &self.discovered)
            .finish_non_exhaustive()
    }
}

/// MP2 1.1 base-info field offsets (sfh_base_info, 96 bytes).
mod base_info {
    /// Firmware version word; non-zero once firmware configured.
    pub const FW_VER: usize = 4;
    /// Sensor-presence mask (u16): bit n = sensor n present.
    pub const SENSORS: usize = 8;
}

/// MP2 1.1 per-sensor data layout: data at
/// `SENSOR_DATA_BASE + idx * SENSOR_DATA_STRIDE`, payload after
/// the 16-byte common header.
mod data_1_1 {
    /// Offset of the per-sensor data area in the window.
    pub const BASE: usize = 1024;
    /// Per-sensor stride.
    pub const STRIDE: usize = 256;
    /// intr_cnt offset inside sfh_common_data.
    pub const INTR_CNT: usize = 8;
    /// Payload offset (after sfh_common_data).
    pub const PAYLOAD: usize = 16;
}

/// Sensor-state byte used in synthesised 1.1 reports
/// (HID_USAGE_SENSOR_STATE_READY).
const REPORT_STATE_READY: u8 = 2;
/// Sensor-event byte (HID_USAGE_SENSOR_EVENT_DATA_UPDATED).
const REPORT_EVENT_DATA_UPDATED: u8 = 4;

impl<B: Mp2Bus, W: SharedWindow, P: ReportBuffers> SfhHub<B, W, P> {
    /// New hub. `discover()` must run before sensors can start.
    pub fn new(bus: B, window: W, bufs: P, gen: Mp2Gen) -> Self {
        Self {
            bus,
            window,
            bufs,
            gen,
            layout: None,
            slots: [const { SensorSlot::empty() }; MAX_SENSORS],
            slot_count: 0,
            discovered: false,
            response_timeout_ms: RESPONSE_TIMEOUT_MS,
            fw_ready_timeout_ms: FW_READY_TIMEOUT_MS,
            data_base: data_1_1::BASE,
        }
    }

    /// The MP2 generation this hub drives.
    pub fn gen(&self) -> Mp2Gen {
        self.gen
    }

    /// The 1.0 command layout selected at discovery (None on 1.1
    /// or before discovery).
    pub fn layout(&self) -> Option<CmdLayout> {
        self.layout
    }

    /// Number of discovered sensors (HID-presented or not).
    pub fn sensor_count(&self) -> usize {
        self.slot_count
    }

    /// Sensor index of the `i`-th discovered sensor.
    pub fn sensor_id(&self, i: usize) -> Option<u8> {
        self.slots.get(i).map(|s| s.sensor_id)
    }

    /// Whether sensor `sensor_id` is currently enabled.
    pub fn is_enabled(&self, sensor_id: u8) -> bool {
        self.slots[..self.slot_count]
            .iter()
            .any(|s| s.sensor_id == sensor_id && s.enabled)
    }

    // -- discovery ------------------------------------------------

    /// Run firmware discovery: select the command layout (1.0),
    /// read the presence mask, and build a decode profile for
    /// every HID-presentable sensor. Returns the sensor count.
    pub fn discover(&mut self) -> Result<usize, SfhError> {
        let present: &[u8];
        let mask: u32;
        match self.gen {
            Mp2Gen::V1_0 => {
                let acs = self.bus.read32(ACS_REG);
                self.layout = Some(if acs & 0xF == DISCOVERY_STATUS_V2 {
                    CmdLayout::V2
                } else {
                    CmdLayout::V1
                });
                mask = acs >> 4;
                present = SIDS_1_0;
            }
            Mp2Gen::V1_1 => {
                // Firmware needs configuration time before the
                // base-info block is valid (Linux sleeps a fixed
                // 5 s; a bounded poll for fw_ver + mask is the
                // same contract without the dead time).
                let deadline = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(
                    self.fw_ready_timeout_ms * 1_000_000,
                ));
                loop {
                    let fw_ver = self.window.read_u32(base_info::FW_VER);
                    let sensors = self.window.read_u16(base_info::SENSORS);
                    if fw_ver != 0 && sensors != 0 {
                        mask = sensors as u32;
                        break;
                    }
                    if narf_time::now_cycles() >= deadline {
                        return Err(SfhError::FirmwareNotReady);
                    }
                    narf_scheduler::sleep_pumps::run();
                }
                present = SIDS_1_1;
            }
        }

        self.slot_count = 0;
        for &sid in present {
            if mask & (1u32 << sid) == 0 {
                continue;
            }
            if self.slot_count >= MAX_SENSORS {
                break;
            }
            let def = hid_def_for(self.gen, sid);
            let mut slot = SensorSlot::empty();
            slot.sensor_id = sid;
            slot.def = def;
            if let Some(def) = def {
                let rd = narf_hid::descriptor::parse(def.descriptor)
                    .map_err(|_| SfhError::Descriptor)?;
                let profiles = hid_sensor::enumerate_sensors(&rd);
                let profile = profiles
                    .into_iter()
                    .find(|p| p.kind == def.kind && p.input_report_id == def.report_id)
                    .ok_or(SfhError::Descriptor)?;
                slot.report_len = report_len_for(&profile);
                let kind = profile.kind;
                slot.profile = Some(profile);
                // Publish the collection through the shared surface
                // (idempotent across rediscovery).
                crate::hid_sensor_pub::register_sensor(
                    crate::hid_sensor_pub::SensorSource::AmdSfh,
                    sid as u32,
                    kind,
                );
            }
            self.slots[self.slot_count] = slot;
            self.slot_count += 1;
        }
        self.discovered = true;
        Ok(self.slot_count)
    }

    // -- mailbox commands -----------------------------------------

    fn slot_index(&self, sensor_id: u8) -> Option<usize> {
        self.slots[..self.slot_count]
            .iter()
            .position(|s| s.sensor_id == sensor_id)
    }

    /// Wait for the firmware response on P2C_MSG(0) matching
    /// `expect(word)`. Bounded by the hub's response timeout;
    /// drives sleep pumps while waiting (never a bare spin).
    fn wait_response(&self, expect: impl Fn(u32) -> bool) -> Result<u32, SfhError> {
        let deadline = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(
            self.response_timeout_ms * 1_000_000,
        ));
        loop {
            let word = self.bus.read32(p2c_msg(0));
            if expect(word) {
                return Ok(word);
            }
            if narf_time::now_cycles() >= deadline {
                return Err(SfhError::ResponseTimeout);
            }
            narf_scheduler::sleep_pumps::run();
            core::hint::spin_loop();
        }
    }

    /// Encode a 1.0/V2 command word.
    fn cmd_word_v2(&self, cmd_id: u8, sensor_id: u8, period_ms: u16, use_c2p_reg: bool) -> u32 {
        let period = period_ms.min(255) as u32;
        (cmd_id as u32)
            | (16u32 << 8) // length = 16 (command record size)
            | ((use_c2p_reg as u32) << 15)
            | ((sensor_id as u32) << 16)
            | (period << 24)
    }

    /// Encode a 1.0/V1 command base word.
    fn cmd_word_v1(&self, cmd_id: u8, sensor_id: u8, period_ms: u16) -> u32 {
        (cmd_id as u32) | ((sensor_id as u32) << 8) | ((period_ms as u32) << 16)
    }

    /// Encode a 1.1 command word.
    fn cmd_word_1_1(&self, cmd_id: u8, sensor_id: u8, sub_cmd_value: u32) -> u32 {
        (sensor_id as u32) | ((cmd_id as u32) << 4) | ((sub_cmd_value & 0xFFF) << 16)
    }

    /// Issue ENABLE for one sensor and (where the protocol has
    /// responses and `wait` is set) validate the response.
    /// Follows Linux client-init order: stop, clear the response
    /// register, start.
    pub fn start_sensor(&mut self, sensor_id: u8, wait: bool) -> Result<(), SfhError> {
        if !self.discovered {
            return Err(SfhError::NotDiscovered);
        }
        let idx = self.slot_index(sensor_id).ok_or(SfhError::NoSuchSensor)?;
        if self.slots[idx].profile.is_none() {
            return Err(SfhError::NoSuchSensor);
        }
        let period = self.slots[idx].period_ms;

        // Stop first (ignore its result — a never-started sensor
        // may not answer) and clear any stale response.
        let _ = self.stop_sensor(sensor_id, false);
        self.bus.write32(p2c_msg(0), 0);

        match self.gen {
            Mp2Gen::V1_0 => {
                // Allocate the report buffer on first start.
                if self.slots[idx].buf.is_none() {
                    let (addr, id) = self
                        .bufs
                        .alloc(REPORT_BUF_LEN)
                        .ok_or(SfhError::AllocFailed)?;
                    self.slots[idx].buf = Some(id);
                    self.slots[idx].buf_addr = addr;
                }
                let addr = self.slots[idx].buf_addr;
                let report_len = self.slots[idx].report_len as u32;
                match self.layout.unwrap_or(CmdLayout::V2) {
                    CmdLayout::V1 => {
                        let param = report_len << 1; // buf_layout 0, buf_length
                        self.bus.write64(c2p_msg(2), addr);
                        self.bus.write32(c2p_msg(1), param);
                        self.bus.write32(
                            c2p_msg(0),
                            self.cmd_word_v1(cmd::ENABLE_SENSOR, sensor_id, period),
                        );
                    }
                    CmdLayout::V2 => {
                        self.bus.write64(c2p_msg(1), addr);
                        self.bus.write32(
                            c2p_msg(0),
                            self.cmd_word_v2(cmd::ENABLE_SENSOR, sensor_id, period, false),
                        );
                        if wait {
                            self.wait_response(|w| {
                                let status = w & 0x3;
                                let response = ((w >> 4) & 0xF) as u8;
                                let sid = ((w >> 16) & 0x3F) as u8;
                                status == 0 && response == resp::SENSOR_ENABLED && sid == sensor_id
                            })?;
                        }
                    }
                }
            }
            Mp2Gen::V1_1 => {
                self.bus.write32(
                    c2p_msg(0),
                    self.cmd_word_1_1(cmd::ENABLE_SENSOR, sensor_id, 1),
                );
                if wait {
                    self.wait_response(|w| {
                        let response = (w & 0xFF) as u8;
                        let sid = ((w >> 8) & 0xF) as u8;
                        let cid = ((w >> 12) & 0xF) as u8;
                        response == 0 && sid == sensor_id && cid == cmd::ENABLE_SENSOR
                    })?;
                }
            }
        }
        self.slots[idx].enabled = true;
        self.slots[idx].suspended = false;
        self.slots[idx].have_report = false;
        Ok(())
    }

    /// Issue DISABLE for one sensor.
    pub fn stop_sensor(&mut self, sensor_id: u8, wait: bool) -> Result<(), SfhError> {
        let idx = self.slot_index(sensor_id).ok_or(SfhError::NoSuchSensor)?;
        let period = self.slots[idx].period_ms;
        match self.gen {
            Mp2Gen::V1_0 => match self.layout.unwrap_or(CmdLayout::V2) {
                CmdLayout::V1 => {
                    self.bus.write64(c2p_msg(2), 0);
                    self.bus.write32(
                        c2p_msg(0),
                        self.cmd_word_v1(cmd::DISABLE_SENSOR, sensor_id, period),
                    );
                }
                CmdLayout::V2 => {
                    self.bus.write64(c2p_msg(1), 0);
                    self.bus.write32(
                        c2p_msg(0),
                        self.cmd_word_v2(cmd::DISABLE_SENSOR, sensor_id, period, false),
                    );
                    if wait {
                        let _ = self.wait_response(|w| {
                            let status = w & 0x3;
                            let response = ((w >> 4) & 0xF) as u8;
                            let sid = ((w >> 16) & 0x3F) as u8;
                            status == 0 && response == resp::SENSOR_DISABLED && sid == sensor_id
                        });
                    }
                    self.clear_v2_interrupt();
                }
            },
            Mp2Gen::V1_1 => {
                self.bus.write32(
                    c2p_msg(0),
                    self.cmd_word_1_1(cmd::DISABLE_SENSOR, sensor_id, 0),
                );
                self.bus.write64(c2p_msg(1), 0);
                if wait {
                    let _ = self.wait_response(|w| {
                        let response = (w & 0xFF) as u8;
                        let sid = ((w >> 8) & 0xF) as u8;
                        let cid = ((w >> 12) & 0xF) as u8;
                        response == 0 && sid == sensor_id && cid == cmd::DISABLE_SENSOR
                    });
                }
            }
        }
        self.slots[idx].enabled = false;
        self.slots[idx].suspended = false;
        Ok(())
    }

    /// V2 interrupt-latch clear: if P2C_MSG(4) is non-zero, clear
    /// it and post the clear mask to P2C_MSG(5).
    fn clear_v2_interrupt(&self) {
        if self.bus.read32(p2c_msg(4)) != 0 {
            self.bus.write32(p2c_msg(4), 0);
            self.bus.write32(p2c_msg(5), 0xF);
        }
    }

    /// Stop every sensor with the protocol's stop-all encoding.
    pub fn stop_all(&mut self) {
        match self.gen {
            Mp2Gen::V1_0 => match self.layout.unwrap_or(CmdLayout::V2) {
                CmdLayout::V1 => {
                    self.bus
                        .write32(c2p_msg(0), self.cmd_word_v1(cmd::STOP_ALL_SENSORS, 0, 0));
                }
                CmdLayout::V2 => {
                    let word = (cmd::STOP_ALL_SENSORS as u32) | (16u32 << 8);
                    self.bus.write32(c2p_msg(0), word);
                }
            },
            Mp2Gen::V1_1 => {
                self.bus
                    .write32(c2p_msg(0), self.cmd_word_1_1(cmd::DISABLE_SENSOR, 0xF, 0));
            }
        }
        for slot in self.slots[..self.slot_count].iter_mut() {
            slot.enabled = false;
            slot.suspended = false;
        }
    }

    /// Start every HID-presentable discovered sensor. Individual
    /// failures are logged and skipped (one dead sensor must not
    /// dark the hub); returns how many sensors started.
    pub fn enable_all(&mut self) -> usize {
        let mut started = 0;
        for i in 0..self.slot_count {
            if self.slots[i].profile.is_none() {
                continue;
            }
            let sid = self.slots[i].sensor_id;
            match self.start_sensor(sid, true) {
                Ok(()) => started += 1,
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  amd-sfh: sensor {sid} enable failed: {e:?}"
                    );
                }
            }
        }
        started
    }

    /// Set a sensor's report period (ms). This is the value the
    /// REPORT_INTERVAL feature report carries; if the sensor is
    /// running it is restarted so the firmware picks the new
    /// period up through the mailbox.
    pub fn set_period(&mut self, sensor_id: u8, period_ms: u16) -> Result<(), SfhError> {
        let idx = self.slot_index(sensor_id).ok_or(SfhError::NoSuchSensor)?;
        self.slots[idx].period_ms = period_ms;
        if self.slots[idx].enabled {
            self.start_sensor(sensor_id, true)?;
        }
        Ok(())
    }

    /// The profile for a discovered sensor (fixture / consumer
    /// introspection).
    pub fn profile(&self, sensor_id: u8) -> Option<&HidSensorProfile> {
        self.slot_index(sensor_id)
            .and_then(|i| self.slots[i].profile.as_ref())
    }

    // -- report path ------------------------------------------------

    /// Poll every enabled sensor once; decode any new report and
    /// publish the resulting event through the shared publication
    /// path (`hid_sensor_pub` — sysfs/IIO surface + legacy sensor
    /// ring). Returns how many events reached the ring.
    pub fn poll_all(&mut self, timestamp_ns: u64) -> usize {
        let mut pushed = 0;
        for i in 0..self.slot_count {
            if !self.slots[i].enabled || self.slots[i].suspended {
                continue;
            }
            if self.slots[i].profile.is_none() {
                continue;
            }
            if let Some(ev) = self.poll_sensor(i, timestamp_ns) {
                let slot = &self.slots[i];
                let kind = slot.profile.as_ref().map(|p| p.kind);
                let reached_ring = match kind {
                    Some(kind) => crate::hid_sensor_pub::publish(
                        crate::hid_sensor_pub::SensorSource::AmdSfh,
                        slot.sensor_id as u32,
                        kind,
                        ev,
                    ),
                    None => hid_sensor::push_sensor_event(ev),
                };
                if reached_ring {
                    pushed += 1;
                }
            }
        }
        pushed
    }

    fn poll_sensor(&mut self, idx: usize, timestamp_ns: u64) -> Option<SensorEvent> {
        let mut report = [0u8; MAX_REPORT_LEN];
        let len = match self.gen {
            Mp2Gen::V1_0 => {
                let buf = self.slots[idx].buf?;
                let want = self.slots[idx].report_len;
                let n = self.bufs.read(buf, &mut report[..want]);
                if n < want {
                    return None;
                }
                if self.slots[idx].have_report
                    && report[..want] == self.slots[idx].last_report[..want]
                {
                    return None; // no new sample
                }
                self.slots[idx].last_report[..want].copy_from_slice(&report[..want]);
                self.slots[idx].have_report = true;
                want
            }
            Mp2Gen::V1_1 => self.build_report_1_1(idx, &mut report)?,
        };
        let profile = self.slots[idx].profile.as_ref()?;
        let ev = hid_sensor::decode_report(profile, &report[..len], timestamp_ns).ok()?;
        Some(rescale_event(ev))
    }

    /// Build a HID input report for one 1.1 sensor from the
    /// firmware window. Returns the report length, or None when
    /// the sensor has no new sample (intr_cnt unchanged) — HPD
    /// excepted: its state lives in a mailbox register, so a
    /// presence *change* is the new-sample signal there.
    fn build_report_1_1(&mut self, idx: usize, out: &mut [u8; MAX_REPORT_LEN]) -> Option<usize> {
        let slot = &self.slots[idx];
        let sid = slot.sensor_id;
        let def = slot.def?;
        out[0] = def.report_id;
        out[1] = REPORT_STATE_READY;
        out[2] = REPORT_EVENT_DATA_UPDATED;

        if sid == SID_1_1_HPD {
            // Presence: C2P_MSG(4) hpd_status, presence bits [25:24].
            let status = self.bus.read32(c2p_msg(4));
            let presence = ((status >> 24) & 0x3) as u8;
            out[3] = presence;
            let changed = !slot.have_report || slot.last_report[3] != presence;
            let slot = &mut self.slots[idx];
            slot.last_report[3] = presence;
            slot.have_report = true;
            return if changed { Some(4) } else { None };
        }

        let data_off = self.data_base + (sid as usize) * data_1_1::STRIDE;
        let intr_cnt = self.window.read_u32(data_off + data_1_1::INTR_CNT);
        if slot.have_report && intr_cnt == slot.last_intr_cnt {
            return None;
        }
        let payload = data_off + data_1_1::PAYLOAD;
        let len = match def.kind {
            HidSensorKind::Accelerometer3D
            | HidSensorKind::Gyrometer3D
            | HidSensorKind::Magnetometer3D => {
                let mut axes = [0i32; 3];
                for (a, axis) in axes.iter_mut().enumerate() {
                    let bits = self.window.read_u32(payload + 4 * a);
                    let milli = sfh_float_to_milli(bits);
                    *axis = match def.kind {
                        // firmware: m/s² → descriptor field: centi-m/s²
                        HidSensorKind::Accelerometer3D => milli / 10,
                        // firmware: rad/s → descriptor field: centi-deg/s
                        HidSensorKind::Gyrometer3D => (milli * 57_296 / 1000) / 10,
                        // firmware: µT → descriptor field: centi-µT
                        _ => milli / 10,
                    };
                }
                for (a, v) in axes.iter().enumerate() {
                    out[3 + 4 * a..7 + 4 * a].copy_from_slice(&v.to_le_bytes());
                }
                15
            }
            HidSensorKind::AmbientLight => {
                let bits = self.window.read_u32(payload);
                let lux = sfh_float_round(bits).max(0);
                out[3..7].copy_from_slice(&lux.to_le_bytes());
                7
            }
            _ => return None,
        };
        let slot = &mut self.slots[idx];
        slot.last_intr_cnt = intr_cnt;
        slot.have_report = true;
        Some(len)
    }

    // -- power ------------------------------------------------------

    /// Suspend: stop every enabled sensor except HPD (presence
    /// must survive sleep so it can be a wake source — the same
    /// carve-out Linux makes). Fire-and-forget: PM handlers run
    /// with interrupts gated and must not wait on firmware.
    pub fn suspend(&mut self) {
        for i in 0..self.slot_count {
            let is_hpd = self.slots[i].def.map(|d| d.kind) == Some(HidSensorKind::Proximity);
            if self.slots[i].enabled && !is_hpd {
                let sid = self.slots[i].sensor_id;
                let _ = self.stop_sensor(sid, false);
                self.slots[i].suspended = true;
                // stop_sensor cleared `enabled`; suspend keeps the
                // logical "was running" bit in `suspended` so
                // resume knows what to restart.
                self.slots[i].enabled = false;
            }
        }
    }

    /// Resume: restart the sensors `suspend` stopped.
    pub fn resume(&mut self) {
        for i in 0..self.slot_count {
            if self.slots[i].suspended {
                let sid = self.slots[i].sensor_id;
                self.slots[i].suspended = false;
                let _ = self.start_sensor(sid, false);
            }
        }
    }
}

/// Input-report length (incl. report-ID prefix) implied by a
/// profile's data fields.
fn report_len_for(profile: &HidSensorProfile) -> usize {
    let mut bits = 16u32; // state + event bytes precede data fields
    for f in &profile.fields {
        bits = bits.max(f.bit_offset + f.report_size * f.report_count);
    }
    (bits.div_ceil(8) as usize) + 1 // + report-ID prefix byte
}

/// Apply the transport's unit contract to a decoded event:
/// descriptor fields are centi-units (unit exponent −2), events
/// are the decode layer's milli/integer conventions.
fn rescale_event(ev: SensorEvent) -> SensorEvent {
    match ev {
        SensorEvent::Accel3d {
            x_milli_g,
            y_milli_g,
            z_milli_g,
            timestamp_ns,
        } => SensorEvent::Accel3d {
            x_milli_g: centi_ms2_to_milli_g(x_milli_g),
            y_milli_g: centi_ms2_to_milli_g(y_milli_g),
            z_milli_g: centi_ms2_to_milli_g(z_milli_g),
            timestamp_ns,
        },
        SensorEvent::Gyro3d {
            x_milli_dps,
            y_milli_dps,
            z_milli_dps,
            timestamp_ns,
        } => SensorEvent::Gyro3d {
            x_milli_dps: x_milli_dps * 10,
            y_milli_dps: y_milli_dps * 10,
            z_milli_dps: z_milli_dps * 10,
            timestamp_ns,
        },
        SensorEvent::Magneto3d {
            x_micro_t,
            y_micro_t,
            z_micro_t,
            timestamp_ns,
        } => SensorEvent::Magneto3d {
            x_micro_t: x_micro_t / 100,
            y_micro_t: y_micro_t / 100,
            z_micro_t: z_micro_t / 100,
            timestamp_ns,
        },
        other => other,
    }
}

/// centi-m/s² → milli-g (1 g = 9.80665 m/s² ⇒ factor 1000/981).
fn centi_ms2_to_milli_g(centi: i32) -> i32 {
    ((centi as i64) * 1000 / 981) as i32
}

// ── Production glue ──────────────────────────────────────────────

/// The bound hub (one MP2 function per machine in practice).
static HUB: IrqSafeSpinLock<Option<SfhHub<MmioBus, ProdWindow, DmaReportBuffers>>> =
    IrqSafeSpinLock::new(None);

/// Whether an SFH hub was probed and discovered sensors.
pub fn is_probed() -> bool {
    HUB.lock()
        .as_ref()
        .map(|h| h.sensor_count() > 0)
        .unwrap_or(false)
}

/// device_pm suspend hook: stop all sensors except HPD. Always
/// `Ok` — the hub holds no in-flight host transfer state, so
/// there is no SFH state in which suspending is unsafe; sensors
/// that fail to stop are re-stopped by stop_all at next probe /
/// resume bookkeeping. (A blanket Busy here is what #1028 was
/// filed against; this handler answers from actual state.)
fn pm_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if let Some(hub) = HUB.lock().as_mut() {
        hub.suspend();
    }
    Ok(())
}

/// device_pm resume hook: restart what suspend stopped.
fn pm_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if let Some(hub) = HUB.lock().as_mut() {
        hub.resume();
    }
    Ok(())
}

/// Report pump: polls the hub at the sensors' cadence and feeds
/// the shared sensor ring. INTx from the MP2 is not routed yet
/// (see the module header); the firmware posts reports at the
/// programmed period, so a 5 ms poll cadence loses nothing.
async fn pump_task() {
    let mut last_poll_ns: u64 = 0;
    loop {
        let now = narf_time::monotonic_ns();
        if now.saturating_sub(last_poll_ns) >= 5_000_000 {
            last_poll_ns = now;
            let mut guard = HUB.lock();
            if let Some(hub) = guard.as_mut() {
                hub.poll_all(now);
            }
            drop(guard);
        }
        narf_scheduler::yield_now().await;
    }
}

/// PCI probe entry point.
///
/// # Safety
/// Exclusive BAR access held by the bus probe framework.
pub fn probe(
    device: narf_driver_runtime::BusDevice,
    cap: narf_driver_runtime::Cap<narf_driver_runtime::BusDeviceCap, narf_driver_runtime::Write>,
) -> Result<(), narf_bus::ProbeError> {
    if HUB.lock().is_some() {
        return Ok(()); // singleton: a second MP2 function is not expected
    }
    if device.id.vendor != AMD_VENDOR {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let gen = Mp2Gen::from_did(device.id.device).ok_or(narf_bus::ProbeError::NotForThisDriver)?;

    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: exclusive BAR ownership held by the bus probe contract.
    let regs = unsafe { narf_driver_runtime::map_bar(&device, BAR_REGS) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let bus = MmioBus::new(regs);
    if bus.len() < MP2_BAR_MIN_LEN {
        let _ = writeln!(
            narf_console::Writer,
            "  amd-sfh: BAR2 too small ({} bytes, need {MP2_BAR_MIN_LEN}); not an SFH window",
            bus.len()
        );
        return Err(narf_bus::ProbeError::BadDevice);
    }

    // MP2 1.1: read the firmware window base before the hub takes
    // ownership of the bus.
    let window = match gen {
        Mp2Gen::V1_0 => ProdWindow::Null,
        Mp2Gen::V1_1 => ProdWindow::Phys(window_base_from_c2p22(bus.read32(c2p_msg(22)))),
    };

    let bound_domain = narf_drivers::BoundKind::Input.default_domain();
    let mut hub = SfhHub::new(
        bus,
        window,
        DmaReportBuffers::new(narf_driver_runtime::DomainId::DRIVER_0),
        gen,
    );
    match hub.discover() {
        Ok(0) => {
            let _ = writeln!(
                narf_console::Writer,
                "  amd-sfh: MP2 {:?} present but reports no sensors",
                gen
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
        Ok(n) => {
            let _ = writeln!(
                narf_console::Writer,
                "  amd-sfh: MP2 {:?} discovered {n} sensor(s), layout {:?}",
                gen,
                hub.layout()
            );
        }
        Err(e) => {
            let _ = writeln!(narf_console::Writer, "  amd-sfh: discovery failed: {e:?}");
            return Err(narf_bus::ProbeError::BadDevice);
        }
    }
    let started = hub.enable_all();
    hid_sensor::init_sensor_ring();
    *HUB.lock() = Some(hub);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("amd-sfh"),
        kind: narf_drivers::BoundKind::Input,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: bound_domain,
    });
    narf_power::device_pm::register_device_pm("amd-sfh", pm_suspend, pm_resume);
    narf_scheduler::spawn(pump_task());

    let _ = writeln!(
        narf_console::Writer,
        "  amd-sfh: probed (0x{:04X}:0x{:04X}, {:?}), {started} sensor(s) streaming",
        device.id.vendor,
        device.id.device,
        gen
    );
    Ok(())
}

/// Register the SFH PCI matches with the bus. Called from the
/// input crate's `register_initcalls` (composition in
/// `frame/src/bare_main.rs` calls that at Stage::Device).
pub fn register_initcalls() {
    for &(vendor, device) in PCI_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "amd-sfh",
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}

// ── Tests ────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // -- Fake firmware -------------------------------------------
    //
    // The fake models the MP2 firmware side of the conversation,
    // from the protocol contract — not from the driver's wishes:
    // it owns a register file, decodes mailbox commands written
    // to C2P_MSG(0) per the layout it was configured with, tracks
    // which sensors are enabled, and posts response words to
    // P2C_MSG(0) the way firmware does (V2 / 1.1 only; V1 has no
    // responses). DMA report delivery and the 1.1 window are
    // separate shared stores the tests write as firmware would.

    const REG_WORDS: usize = 0x4400; // 0x11000 bytes of registers

    #[derive(Debug)]
    struct FakeFw {
        regs: Vec<u32>,
        layout: CmdLayout,
        never_respond: bool,
        enabled: [bool; 32],
        stop_all_count: u32,
    }

    impl FakeFw {
        fn new(layout: CmdLayout) -> Self {
            Self {
                regs: vec![0; REG_WORDS],
                layout,
                never_respond: false,
                enabled: [false; 32],
                stop_all_count: 0,
            }
        }
        fn reg(&self, off: u64) -> u32 {
            self.regs[(off / 4) as usize]
        }
        fn set_reg(&mut self, off: u64, val: u32) {
            self.regs[(off / 4) as usize] = val;
        }
        fn respond(&mut self, word: u32) {
            if !self.never_respond {
                self.set_reg(p2c_msg(0), word);
            }
        }
        /// Firmware command handling for a write to C2P_MSG(0).
        fn on_command(&mut self, gen: Mp2Gen, word: u32) {
            match gen {
                Mp2Gen::V1_1 => {
                    let sid = (word & 0xF) as usize;
                    let cid = ((word >> 4) & 0xF) as u8;
                    match cid {
                        cmd::ENABLE_SENSOR => {
                            if sid < 32 {
                                self.enabled[sid] = true;
                            }
                            self.respond(((cid as u32) << 12) | ((sid as u32) << 8));
                        }
                        cmd::DISABLE_SENSOR => {
                            if sid == 0xF {
                                self.enabled = [false; 32];
                                self.stop_all_count += 1;
                            } else if sid < 32 {
                                self.enabled[sid] = false;
                            }
                            self.respond(((cid as u32) << 12) | ((sid as u32) << 8));
                        }
                        _ => {}
                    }
                }
                Mp2Gen::V1_0 => match self.layout {
                    CmdLayout::V1 => {
                        let cid = (word & 0xFF) as u8;
                        let sid = ((word >> 8) & 0xFF) as usize;
                        match cid {
                            cmd::ENABLE_SENSOR => {
                                if sid < 32 {
                                    self.enabled[sid] = true;
                                }
                            }
                            cmd::DISABLE_SENSOR => {
                                if sid < 32 {
                                    self.enabled[sid] = false;
                                }
                            }
                            cmd::STOP_ALL_SENSORS => {
                                self.enabled = [false; 32];
                                self.stop_all_count += 1;
                            }
                            _ => {}
                        }
                    }
                    CmdLayout::V2 => {
                        let cid = (word & 0xF) as u8;
                        let sid = ((word >> 16) & 0x3F) as usize;
                        match cid {
                            cmd::ENABLE_SENSOR => {
                                if sid < 32 {
                                    self.enabled[sid] = true;
                                }
                                self.respond(
                                    ((sid as u32) << 16) | ((resp::SENSOR_ENABLED as u32) << 4),
                                );
                            }
                            cmd::DISABLE_SENSOR => {
                                if sid < 32 {
                                    self.enabled[sid] = false;
                                }
                                self.respond(
                                    ((sid as u32) << 16) | ((resp::SENSOR_DISABLED as u32) << 4),
                                );
                            }
                            cmd::STOP_ALL_SENSORS => {
                                self.enabled = [false; 32];
                                self.stop_all_count += 1;
                            }
                            _ => {}
                        }
                    }
                },
            }
        }
    }

    #[derive(Clone, Debug)]
    struct FakeBus {
        fw: Rc<RefCell<FakeFw>>,
        gen: Mp2Gen,
    }

    impl Mp2Bus for FakeBus {
        fn read32(&self, off: u64) -> u32 {
            self.fw.borrow().reg(off)
        }
        fn write32(&self, off: u64, val: u32) {
            let mut fw = self.fw.borrow_mut();
            fw.set_reg(off, val);
            if off == c2p_msg(0) {
                fw.on_command(self.gen, val);
            }
        }
        fn write64(&self, off: u64, val: u64) {
            let mut fw = self.fw.borrow_mut();
            fw.set_reg(off, val as u32);
            fw.set_reg(off + 4, (val >> 32) as u32);
        }
    }

    #[derive(Debug)]
    struct NullWindow;
    impl SharedWindow for NullWindow {
        fn copy_out(&self, _off: usize, out: &mut [u8]) {
            for b in out.iter_mut() {
                *b = 0;
            }
        }
    }

    #[derive(Clone, Debug)]
    struct FakeWindow {
        mem: Rc<RefCell<Vec<u8>>>,
    }
    impl SharedWindow for FakeWindow {
        fn copy_out(&self, off: usize, out: &mut [u8]) {
            let m = self.mem.borrow();
            out.copy_from_slice(&m[off..off + out.len()]);
        }
    }

    #[derive(Clone, Debug)]
    struct FakeBuffers {
        store: Rc<RefCell<Vec<Vec<u8>>>>,
    }
    impl ReportBuffers for FakeBuffers {
        fn alloc(&mut self, len: usize) -> Option<(u64, usize)> {
            let mut s = self.store.borrow_mut();
            s.push(vec![0; len]);
            Some((0xF000_0000 + ((s.len() - 1) as u64) * 0x1000, s.len() - 1))
        }
        fn read(&self, id: usize, out: &mut [u8]) -> usize {
            let s = self.store.borrow();
            let n = out.len().min(s[id].len());
            out[..n].copy_from_slice(&s[id][..n]);
            n
        }
        fn write(&mut self, id: usize, data: &[u8]) {
            let mut s = self.store.borrow_mut();
            s[id][..data.len()].copy_from_slice(data);
        }
    }

    type Hub10 = SfhHub<FakeBus, NullWindow, FakeBuffers>;
    type Hub11 = SfhHub<FakeBus, FakeWindow, FakeBuffers>;
    type SharedFw = Rc<RefCell<FakeFw>>;
    type SharedBufs = Rc<RefCell<Vec<Vec<u8>>>>;
    type SharedWin = Rc<RefCell<Vec<u8>>>;

    fn hub10(layout: CmdLayout, acs: u32) -> (Hub10, SharedFw, SharedBufs) {
        let fw = Rc::new(RefCell::new(FakeFw::new(layout)));
        fw.borrow_mut().set_reg(ACS_REG, acs);
        let store = Rc::new(RefCell::new(Vec::new()));
        let hub = SfhHub::new(
            FakeBus {
                fw: fw.clone(),
                gen: Mp2Gen::V1_0,
            },
            NullWindow,
            FakeBuffers {
                store: store.clone(),
            },
            Mp2Gen::V1_0,
        );
        (hub, fw, store)
    }

    fn hub11(sensors: u16, fw_ver: u32) -> (Hub11, SharedFw, SharedWin) {
        let fw = Rc::new(RefCell::new(FakeFw::new(CmdLayout::V2)));
        let mem = Rc::new(RefCell::new(vec![0u8; 128 * 1024]));
        {
            let mut m = mem.borrow_mut();
            m[base_info::FW_VER..base_info::FW_VER + 4].copy_from_slice(&fw_ver.to_le_bytes());
            m[base_info::SENSORS..base_info::SENSORS + 2].copy_from_slice(&sensors.to_le_bytes());
        }
        let store = Rc::new(RefCell::new(Vec::new()));
        let hub = SfhHub::new(
            FakeBus {
                fw: fw.clone(),
                gen: Mp2Gen::V1_1,
            },
            FakeWindow { mem: mem.clone() },
            FakeBuffers { store },
            Mp2Gen::V1_1,
        );
        (hub, fw, mem)
    }

    fn acs_for(mask: u32, status: u32) -> u32 {
        (mask << 4) | status
    }

    fn win_put_u32(mem: &SharedWin, off: usize, val: u32) {
        mem.borrow_mut()[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }

    fn reset_ring() {
        hid_sensor::init_sensor_ring();
        hid_sensor::__reset_sensor_ring_for_test();
    }

    // -- discovery -------------------------------------------------

    fn smoke_sfh10_discovery_v2() -> TestResult {
        let mask = (1 << SID_1_0_ACCEL) | (1 << SID_1_0_GYRO) | (1 << SID_1_0_ALS);
        let (mut hub, _fw, _s) = hub10(CmdLayout::V2, acs_for(mask, DISCOVERY_STATUS_V2));
        let n = match hub.discover() {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("discover failed"),
        };
        if n != 3 || hub.layout() != Some(CmdLayout::V2) {
            return TestResult::Fail("v2 discovery count/layout wrong");
        }
        if hub.sensor_id(0) != Some(0)
            || hub.sensor_id(1) != Some(1)
            || hub.sensor_id(2) != Some(19)
        {
            return TestResult::Fail("v2 discovery sensor ids wrong");
        }
        match hub.profile(19).map(|p| p.kind) {
            Some(HidSensorKind::AmbientLight) => TestResult::Pass,
            _ => TestResult::Fail("ALS profile missing"),
        }
    }
    kernel_test_in!("drivers/input", smoke_sfh10_discovery_v2);

    fn smoke_sfh10_discovery_v1_layout() -> TestResult {
        let mask = 1 << SID_1_0_ACCEL;
        let (mut hub, _fw, _s) = hub10(CmdLayout::V1, acs_for(mask, 0));
        match hub.discover() {
            Ok(1) if hub.layout() == Some(CmdLayout::V1) => TestResult::Pass,
            Ok(_) => TestResult::Fail("v1 discovery count wrong"),
            Err(_) => TestResult::Fail("discover failed"),
        }
    }
    kernel_test_in!("drivers/input", smoke_sfh10_discovery_v1_layout);

    fn smoke_sfh11_discovery() -> TestResult {
        let sensors = (1 << SID_1_1_ACCEL) | (1 << SID_1_1_ALS);
        let (mut hub, _fw, _m) = hub11(sensors, 0x0001_0000);
        match hub.discover() {
            Ok(2) if hub.sensor_id(0) == Some(0) && hub.sensor_id(1) == Some(4) => TestResult::Pass,
            Ok(_) => TestResult::Fail("1.1 discovery count wrong"),
            Err(_) => TestResult::Fail("discover failed"),
        }
    }
    kernel_test_in!("drivers/input", smoke_sfh11_discovery);

    fn smoke_sfh11_firmware_not_ready() -> TestResult {
        let (mut hub, _fw, _m) = hub11(0, 0);
        hub.fw_ready_timeout_ms = 5;
        match hub.discover() {
            Err(SfhError::FirmwareNotReady) => TestResult::Pass,
            _ => TestResult::Fail("expected FirmwareNotReady"),
        }
    }
    kernel_test_in!("drivers/input", smoke_sfh11_firmware_not_ready);

    fn smoke_sfh_window_base_math() -> TestResult {
        if window_base_from_c2p22(0x123) == 0x2460_0000 && window_base_from_c2p22(0) == 0 {
            TestResult::Pass
        } else {
            TestResult::Fail("window base shift wrong")
        }
    }
    kernel_test_in!("drivers/input", smoke_sfh_window_base_math);

    // -- command encoding -------------------------------------------

    fn smoke_sfh10_enable_v2_encoding() -> TestResult {
        let mask = 1 << SID_1_0_ACCEL;
        let (mut hub, fw, _s) = hub10(CmdLayout::V2, acs_for(mask, DISCOVERY_STATUS_V2));
        if hub.discover().is_err() {
            return TestResult::Fail("discover failed");
        }
        if hub.start_sensor(SID_1_0_ACCEL, true).is_err() {
            return TestResult::Fail("start failed");
        }
        let fw = fw.borrow();
        // cmd word: ENABLE(1) | len 16<<8 | sid 0<<16 | period 80<<24
        if fw.reg(c2p_msg(0)) != 0x5000_1001 {
            return TestResult::Fail("v2 enable cmd word wrong");
        }
        // DMA address written as u64 to C2P_MSG(1)
        if fw.reg(c2p_msg(1)) != 0xF000_0000 || fw.reg(c2p_msg(1) + 4) != 0 {
            return TestResult::Fail("v2 enable dma address wrong");
        }
        if !fw.enabled[0] || !hub.is_enabled(SID_1_0_ACCEL) {
            return TestResult::Fail("v2 enable state wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh10_enable_v2_encoding);

    fn smoke_sfh10_enable_v1_encoding() -> TestResult {
        let mask = 1 << SID_1_0_ACCEL;
        let (mut hub, fw, _s) = hub10(CmdLayout::V1, acs_for(mask, 0));
        if hub.discover().is_err() {
            return TestResult::Fail("discover failed");
        }
        if hub.start_sensor(SID_1_0_ACCEL, true).is_err() {
            return TestResult::Fail("start failed");
        }
        let fw = fw.borrow();
        // base word: cmd 1 | sid 0<<8 | period 80<<16
        if fw.reg(c2p_msg(0)) != 0x0050_0001 {
            return TestResult::Fail("v1 enable base word wrong");
        }
        // param: buf_length(15) << 1 in C2P_MSG(1); DMA addr in C2P_MSG(2)
        if fw.reg(c2p_msg(1)) != 30 {
            return TestResult::Fail("v1 enable param word wrong");
        }
        if fw.reg(c2p_msg(2)) != 0xF000_0000 {
            return TestResult::Fail("v1 enable dma address wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh10_enable_v1_encoding);

    fn smoke_sfh11_enable_encoding() -> TestResult {
        let sensors = 1 << SID_1_1_ACCEL;
        let (mut hub, fw, _m) = hub11(sensors, 0x0001_0000);
        if hub.discover().is_err() {
            return TestResult::Fail("discover failed");
        }
        if hub.start_sensor(SID_1_1_ACCEL, true).is_err() {
            return TestResult::Fail("start failed");
        }
        let fw = fw.borrow();
        // cmd word: sid 0 | ENABLE(1)<<4 | sub_cmd_value 1<<16
        if fw.reg(c2p_msg(0)) != 0x0001_0010 {
            return TestResult::Fail("1.1 enable cmd word wrong");
        }
        if !fw.enabled[0] || !hub.is_enabled(SID_1_1_ACCEL) {
            return TestResult::Fail("1.1 enable state wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh11_enable_encoding);

    fn smoke_sfh_response_timeout() -> TestResult {
        let mask = 1 << SID_1_0_ACCEL;
        let (mut hub, fw, _s) = hub10(CmdLayout::V2, acs_for(mask, DISCOVERY_STATUS_V2));
        fw.borrow_mut().never_respond = true;
        hub.response_timeout_ms = 5;
        if hub.discover().is_err() {
            return TestResult::Fail("discover failed");
        }
        match hub.start_sensor(SID_1_0_ACCEL, true) {
            Err(SfhError::ResponseTimeout) if !hub.is_enabled(SID_1_0_ACCEL) => TestResult::Pass,
            _ => TestResult::Fail("expected ResponseTimeout"),
        }
    }
    kernel_test_in!("drivers/input", smoke_sfh_response_timeout);

    fn smoke_sfh_stop_all() -> TestResult {
        let mask = (1 << SID_1_0_ACCEL) | (1 << SID_1_0_GYRO);
        let (mut hub, fw, _s) = hub10(CmdLayout::V2, acs_for(mask, DISCOVERY_STATUS_V2));
        if hub.discover().is_err() || hub.enable_all() != 2 {
            return TestResult::Fail("enable_all failed");
        }
        hub.stop_all();
        let fw = fw.borrow();
        if fw.stop_all_count != 1 || fw.enabled.iter().any(|e| *e) {
            return TestResult::Fail("stop_all did not stop firmware sensors");
        }
        if fw.reg(c2p_msg(0)) != 0x1008 {
            return TestResult::Fail("stop_all cmd word wrong");
        }
        if hub.is_enabled(SID_1_0_ACCEL) || hub.is_enabled(SID_1_0_GYRO) {
            return TestResult::Fail("hub still marks sensors enabled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh_stop_all);

    fn smoke_sfh_set_period_reprograms() -> TestResult {
        let mask = 1 << SID_1_0_ACCEL;
        let (mut hub, fw, _s) = hub10(CmdLayout::V2, acs_for(mask, DISCOVERY_STATUS_V2));
        if hub.discover().is_err() || hub.start_sensor(SID_1_0_ACCEL, true).is_err() {
            return TestResult::Fail("setup failed");
        }
        if hub.set_period(SID_1_0_ACCEL, 20).is_err() {
            return TestResult::Fail("set_period failed");
        }
        // last C2P(0) write is the re-issued ENABLE with period 20
        if fw.borrow().reg(c2p_msg(0)) != 0x1400_1001 {
            return TestResult::Fail("period not reprogrammed via mailbox");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh_set_period_reprograms);

    // -- report path --------------------------------------------------

    fn accel_report(x: i32, y: i32, z: i32) -> [u8; 15] {
        let mut r = [0u8; 15];
        r[0] = 1; // report id
        r[1] = 2; // sensor state: ready
        r[2] = 4; // event: data updated
        r[3..7].copy_from_slice(&x.to_le_bytes());
        r[7..11].copy_from_slice(&y.to_le_bytes());
        r[11..15].copy_from_slice(&z.to_le_bytes());
        r
    }

    fn smoke_sfh10_report_end_to_end() -> TestResult {
        reset_ring();
        let mask = 1 << SID_1_0_ACCEL;
        let (mut hub, _fw, store) = hub10(CmdLayout::V2, acs_for(mask, DISCOVERY_STATUS_V2));
        if hub.discover().is_err() || hub.start_sensor(SID_1_0_ACCEL, true).is_err() {
            return TestResult::Fail("setup failed");
        }
        // Firmware DMA-writes a report: x=-981, y=0, z=+981 centi-m/s²
        store.borrow_mut()[0][..15].copy_from_slice(&accel_report(-981, 0, 981));
        if hub.poll_all(123) != 1 {
            return TestResult::Fail("first poll pushed nothing");
        }
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Accel3d {
                x_milli_g: -1000,
                y_milli_g: 0,
                z_milli_g: 1000,
                timestamp_ns: 123,
            }) => {}
            _ => return TestResult::Fail("bad event"),
        }
        // Unchanged buffer → no duplicate event.
        if hub.poll_all(124) != 0 || hid_sensor::pop_sensor_event().is_some() {
            return TestResult::Fail("unchanged report re-emitted");
        }
        // Changed sample → new event.
        store.borrow_mut()[0][..15].copy_from_slice(&accel_report(981, 0, 981));
        if hub.poll_all(125) != 1 {
            return TestResult::Fail("changed report not emitted");
        }
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Accel3d {
                x_milli_g: 1000, ..
            }) => TestResult::Pass,
            _ => TestResult::Fail("bad second event"),
        }
    }
    kernel_test_in!("drivers/input", smoke_sfh10_report_end_to_end);

    fn smoke_sfh11_report_end_to_end() -> TestResult {
        reset_ring();
        let sensors = (1 << SID_1_1_ACCEL) | (1 << SID_1_1_ALS);
        let (mut hub, _fw, mem) = hub11(sensors, 0x0001_0000);
        if hub.discover().is_err() || hub.enable_all() != 2 {
            return TestResult::Fail("setup failed");
        }
        // Accel data @1024: intr_cnt=1, payload x=0, y=0, z=9.81f
        win_put_u32(&mem, 1024 + data_1_1::INTR_CNT, 1);
        win_put_u32(&mem, 1024 + data_1_1::PAYLOAD, 0x0000_0000);
        win_put_u32(&mem, 1024 + data_1_1::PAYLOAD + 4, 0x0000_0000);
        win_put_u32(&mem, 1024 + data_1_1::PAYLOAD + 8, 0x411C_F5C3); // 9.81f
                                                                      // ALS data @2048: intr_cnt=1, lux=250.0f
        win_put_u32(&mem, 2048 + data_1_1::INTR_CNT, 1);
        win_put_u32(&mem, 2048 + data_1_1::PAYLOAD, 0x437A_0000); // 250.0f
        if hub.poll_all(777) != 2 {
            return TestResult::Fail("1.1 poll pushed wrong count");
        }
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Accel3d {
                x_milli_g: 0,
                y_milli_g: 0,
                z_milli_g: 1000,
                timestamp_ns: 777,
            }) => {}
            _ => return TestResult::Fail("bad accel event"),
        }
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Lux {
                lux: 250,
                timestamp_ns: 777,
            }) => {}
            _ => return TestResult::Fail("bad lux event"),
        }
        // intr_cnt unchanged → nothing new.
        if hub.poll_all(778) != 0 {
            return TestResult::Fail("1.1 unchanged sample re-emitted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh11_report_end_to_end);

    // Publication round trip (issue #773): discovery registers the
    // hub's sensors, and one poll publishes BOTH the accelerometer
    // and the ALS reading to their own IIO sysfs devices — the two
    // kinds concurrently live on one hub must not alias. Values are
    // the firmware encodings the report-path fixture above pins:
    // accel z = 9.81f m/s² → 1000 milli-g; ALS = 250.0f → 250 lux.
    fn smoke_sfh_publication_round_trip() -> TestResult {
        reset_ring();
        crate::hid_sensor_pub::__reset_for_test();
        narf_filesystem::sysfs::__reset_for_test();
        let sensors = (1 << SID_1_1_ACCEL) | (1 << SID_1_1_ALS);
        let (mut hub, _fw, mem) = hub11(sensors, 0x0001_0000);
        if hub.discover().is_err() || hub.enable_all() != 2 {
            return TestResult::Fail("setup failed");
        }
        let infos = crate::hid_sensor_pub::sensors();
        let find = |kind: hid_sensor::HidSensorKind| {
            infos
                .iter()
                .find(|i| i.kind == kind && i.source == crate::hid_sensor_pub::SensorSource::AmdSfh)
                .map(|i| i.id)
        };
        let (Some(accel), Some(als)) = (
            find(hid_sensor::HidSensorKind::Accelerometer3D),
            find(hid_sensor::HidSensorKind::AmbientLight),
        ) else {
            return TestResult::Fail("discover did not register the SFH sensors");
        };
        let show = |id: crate::hid_sensor_pub::SensorId, attr: &str| {
            narf_filesystem::sysfs::class_register("iio")
                .get_child(&alloc::format!("iio:device{}", id.0))
                .and_then(|k| k.attr_show(attr))
        };
        // Registered at discovery, before any reading: identity is
        // live, raw is empty (no fabricated sample).
        if show(als, "name").as_deref() != Some("als\n")
            || show(als, "in_illuminance_raw").as_deref() != Some("")
        {
            return TestResult::Fail("ALS device wrong before first reading");
        }
        win_put_u32(&mem, 1024 + data_1_1::INTR_CNT, 1);
        win_put_u32(&mem, 1024 + data_1_1::PAYLOAD, 0x0000_0000);
        win_put_u32(&mem, 1024 + data_1_1::PAYLOAD + 4, 0x0000_0000);
        win_put_u32(&mem, 1024 + data_1_1::PAYLOAD + 8, 0x411C_F5C3); // 9.81f
        win_put_u32(&mem, 2048 + data_1_1::INTR_CNT, 1);
        win_put_u32(&mem, 2048 + data_1_1::PAYLOAD, 0x437A_0000); // 250.0f
        if hub.poll_all(777) != 2 {
            return TestResult::Fail("poll pushed wrong count");
        }
        if show(accel, "in_accel_z_raw").as_deref() != Some("1000\n") {
            return TestResult::Fail("accel reading not published to sysfs");
        }
        if show(als, "in_illuminance_raw").as_deref() != Some("250\n") {
            return TestResult::Fail("ALS reading not published to sysfs");
        }
        if show(accel, "in_illuminance_raw").is_some() || show(als, "in_accel_z_raw").is_some() {
            return TestResult::Fail("channels leaked across kinds");
        }
        if crate::hid_sensor_pub::latest_of_kind(hid_sensor::HidSensorKind::AmbientLight)
            != Some((
                als,
                SensorEvent::Lux {
                    lux: 250,
                    timestamp_ns: 777,
                },
            ))
        {
            return TestResult::Fail("ALS reading not in the published store");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh_publication_round_trip);

    fn smoke_sfh11_hpd_presence() -> TestResult {
        reset_ring();
        let sensors = 1 << SID_1_1_HPD;
        let (mut hub, fw, _m) = hub11(sensors, 0x0001_0000);
        if hub.discover().is_err() || hub.start_sensor(SID_1_1_HPD, true).is_err() {
            return TestResult::Fail("setup failed");
        }
        // C2P_MSG(4) = 0 → not present (first poll emits baseline).
        if hub.poll_all(1) != 1 {
            return TestResult::Fail("hpd baseline not emitted");
        }
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Proximity { present: false, .. }) => {}
            _ => return TestResult::Fail("bad hpd event"),
        }
        // Presence field (bits [25:24]) = 1 → present.
        fw.borrow_mut().set_reg(c2p_msg(4), 1 << 24);
        if hub.poll_all(2) != 1 {
            return TestResult::Fail("hpd change not emitted");
        }
        match hid_sensor::pop_sensor_event() {
            Some(SensorEvent::Proximity { present: true, .. }) => TestResult::Pass,
            _ => TestResult::Fail("bad hpd event 2"),
        }
    }
    kernel_test_in!("drivers/input", smoke_sfh11_hpd_presence);

    // -- power ---------------------------------------------------------

    fn smoke_sfh_suspend_resume() -> TestResult {
        let mask = (1 << SID_1_0_ACCEL) | (1 << SID_1_0_HPD);
        let (mut hub, fw, _s) = hub10(CmdLayout::V2, acs_for(mask, DISCOVERY_STATUS_V2));
        if hub.discover().is_err() || hub.enable_all() != 2 {
            return TestResult::Fail("setup failed");
        }
        hub.suspend();
        {
            let fw = fw.borrow();
            if fw.enabled[SID_1_0_ACCEL as usize] {
                return TestResult::Fail("accel not stopped at suspend");
            }
            if !fw.enabled[SID_1_0_HPD as usize] {
                return TestResult::Fail("HPD must stay enabled across suspend");
            }
        }
        hub.resume();
        if !fw.borrow().enabled[SID_1_0_ACCEL as usize] || !hub.is_enabled(SID_1_0_ACCEL) {
            return TestResult::Fail("accel not restarted at resume");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh_suspend_resume);

    // -- descriptor / conversion contracts ------------------------------

    fn smoke_sfh_descriptor_profiles() -> TestResult {
        let cases: [(&HidDef, usize); 5] = [
            (&ACCEL_DEF, 15),
            (&GYRO_DEF, 15),
            (&MAG_DEF, 15),
            (&ALS_DEF, 7),
            (&HPD_DEF, 4),
        ];
        for (def, want_len) in cases {
            let rd = match narf_hid::descriptor::parse(def.descriptor) {
                Ok(r) => r,
                Err(_) => return TestResult::Fail("descriptor parse failed"),
            };
            let profiles = hid_sensor::enumerate_sensors(&rd);
            if profiles.len() != 1 {
                return TestResult::Fail("descriptor must yield exactly one profile");
            }
            let p = &profiles[0];
            if p.kind != def.kind || p.input_report_id != def.report_id {
                return TestResult::Fail("profile kind/rid mismatch");
            }
            if p.interval_field.is_none() || p.feature_report_id != def.report_id {
                return TestResult::Fail("interval feature missing");
            }
            if report_len_for(p) != want_len {
                return TestResult::Fail("report length mismatch");
            }
            let mut buf = [0u8; 8];
            let n = match hid_sensor::build_interval_feature_report(p, 50, &mut buf) {
                Ok(n) => n,
                Err(_) => return TestResult::Fail("interval feature build failed"),
            };
            match hid_sensor::parse_interval_feature_report(p, &buf[..n]) {
                Ok(50) => {}
                _ => return TestResult::Fail("interval feature round-trip failed"),
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh_descriptor_profiles);

    fn smoke_sfh_float_conversion() -> TestResult {
        let cases: [(u32, i32); 6] = [
            (0x3F80_0000, 1000),     // 1.0
            (0xC020_0000, -2500),    // -2.5
            (0x0000_0000, 0),        // 0.0
            (0x411C_F5C3, 9810),     // 9.81
            (0x437A_0000, 250_000),  // 250.0
            (0x7F80_0000, i32::MAX), // +inf saturates
        ];
        for (bits, want) in cases {
            if sfh_float_to_milli(bits) != want {
                return TestResult::Fail("float→milli vector wrong");
            }
        }
        if sfh_float_round(0x411C_F5C3) != 10 || sfh_float_round(0x437A_0000) != 250 {
            return TestResult::Fail("float round wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sfh_float_conversion);
}
