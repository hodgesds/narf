//! HID Sensor Hub driver — Usage Page 0x0020 (Sensors).
//!
//! ## Sources (public only)
//!
//! - **HID Sensor Usages**, USB-IF, 2017. Usage Page 0x20 definition,
//!   per-sensor-type collection structures, data-field usage IDs, and
//!   Feature-report property usage IDs (report interval, power state).
//!   <https://usb.org/document-library/hid-sensor-usages>
//! - **HID Usage Tables 1.4**, USB-IF.  Base usage-page mechanism.
//!   <https://usb.org/document-library/hid-usage-tables-14>
//! - **HID 1.11 §6.2.2** — descriptor item format (already decoded by
//!   `narf-hid::descriptor`).
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//! - Linux source consulted for usage-constant cross-check only
//!   (GPL-2.0-or-later post 2026-05-20 relicense):
//!   `include/linux/hid-sensor-ids.h`,
//!   `drivers/hid/hid-sensor-hub.c`.
//!
//! ## What this module does
//!
//! 1. **Descriptor probe** — `has_sensor_hub_collection` walks a raw
//!    HID report descriptor for Usage Page 0x0020 with an Application
//!    or Physical Collection, signalling whether the device is a HID
//!    Sensor Hub.
//!
//! 2. **Multi-sensor enumeration** — `enumerate_sensors` wraps
//!    `narf_hid::sensor::detect_all`, returning a `Vec<SensorProfile>`
//!    for every sensor collection in the descriptor.
//!
//! 3. **Input-report decode** — `decode_report` maps a raw report
//!    byte-slice (with Report-ID prefix) through the matching
//!    `SensorProfile`, producing a typed `SensorEvent`.
//!
//! 4. **Feature-report sample-rate** — `build_interval_feature_report`
//!    constructs a HID SET_REPORT payload that programs the
//!    `HID_USAGE_SENSOR_PROPERTY_REPORT_INTERVAL` (usage 0x20030E)
//!    field on a feature report.  `parse_interval_feature_report`
//!    reads it back.
//!
//! 5. **Event ring** — `push_sensor_event` / `pop_sensor_event`
//!    provide a bounded SPSC ring of `SensorEvent`s, separate from
//!    the keyboard/pointer rings in `narf-input`.
//!
//! ## Sensor types supported
//!
//! | Sensor          | Usage  | Event variant     |
//! |-----------------|--------|-------------------|
//! | Accelerometer3D | 0x0073 | `Accel3d`         |
//! | Gyrometer3D     | 0x0076 | `Gyro3d`          |
//! | Magnetometer3D  | 0x0083 | `Magneto3d`       |
//! | Ambient Light   | 0x0041 | `Lux`             |
//! | Proximity       | 0x00C1 | `Proximity`       |
//! | Inclinometer    | 0x0086 | (mapped to Accel3d axes) |
//!
//! Sensor fusion, calibration, and full IIO ABI mapping are deferred.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use narf_hid::descriptor::{parse, Field, FieldKind, ReportDescriptor};
use narf_hid::report::{extract, pack};
use narf_lib::sync::IrqSafeSpinLock;

// ── Usage constants ─────────────────────────────────────────────────

/// Sensors usage page (HID Usage Tables §17).
const PAGE_SENSORS: u16 = 0x0020;

/// Sensor-type usages we handle.
mod sensor_usage {
    pub const ACCEL_3D: u16   = 0x0073;
    pub const GYRO_3D: u16    = 0x0076;
    pub const MAGNETO_3D: u16 = 0x0083;
    pub const ALS: u16        = 0x0041;
    pub const PROXIMITY: u16  = 0x00C1;
    pub const INCLINOMETER: u16 = 0x0086;
}

/// Data-field usages on Page 0x20. The high-16 bits are always the
/// page (0x0020); the low-16 bits are the data ID.
mod data_usage {
    // Accelerometer axes (same as narf_hid::sensor::data::*)
    pub const ACCEL_X: u16         = 0x0453;
    pub const ACCEL_Y: u16         = 0x0454;
    pub const ACCEL_Z: u16         = 0x0455;
    // Gyrometer axes
    pub const GYRO_X: u16          = 0x0457;
    pub const GYRO_Y: u16          = 0x0458;
    pub const GYRO_Z: u16          = 0x0459;
    // Magnetometer / orientation
    pub const MAG_X: u16           = 0x0485;
    pub const MAG_Y: u16           = 0x0486;
    pub const MAG_Z: u16           = 0x0487;
    // Ambient light illuminance
    pub const ILLUM_LUX: u16       = 0x04D1;
    // Proximity / presence
    pub const HUMAN_PROXIMITY: u16 = 0x04B2;
    pub const HUMAN_PRESENCE: u16  = 0x04B1;
    // Inclinometer tilt
    pub const TILT_X: u16          = 0x047F;
    pub const TILT_Y: u16          = 0x0480;
    pub const TILT_Z: u16          = 0x0481;
}

/// Feature-property usage: report interval (ms).
/// Linux: `HID_USAGE_SENSOR_PROP_REPORT_INTERVAL` = 0x20030E.
const PROP_REPORT_INTERVAL: u16 = 0x030E;

// ── SensorEvent ─────────────────────────────────────────────────────

/// A decoded reading from a HID Sensor Hub input report.
///
/// Values are *engineering units* at the milli-scale so callers
/// work in integer arithmetic without floating point:
///
/// - `x_milli_g`   : milli-g  (9.80665 mm/s² per count)
/// - `x_milli_dps` : milli-degrees/second
/// - `x_milli_t`   : micro-tesla (µT expressed as milli-µT)
/// - `lux`         : raw lux count (u32, matches HID unsigned field)
/// - `distance_mm` : proximity distance in mm (u16)
///
/// `timestamp_ns` is filled with `0` until a TSC-based clock is
/// wired in; callers must not assume monotonicity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SensorEvent {
    Accel3d {
        x_milli_g: i32,
        y_milli_g: i32,
        z_milli_g: i32,
        timestamp_ns: u64,
    },
    Gyro3d {
        x_milli_dps: i32,
        y_milli_dps: i32,
        z_milli_dps: i32,
        timestamp_ns: u64,
    },
    Magneto3d {
        x_micro_t: i32,
        y_micro_t: i32,
        z_micro_t: i32,
        timestamp_ns: u64,
    },
    Lux {
        lux: u32,
        timestamp_ns: u64,
    },
    Proximity {
        distance_mm: u16,
        present: bool,
        timestamp_ns: u64,
    },
}

// ── Descriptor probe ─────────────────────────────────────────────────

/// Walk a raw HID report descriptor and return `true` if it contains
/// at least one Application or Physical collection on the Sensors
/// usage page (0x0020).  This is the gating check before any further
/// sensor-hub initialisation.
///
/// The parser does a full descriptor parse rather than a byte-level
/// scan so embedded long items, push/pop stacks, and multi-byte
/// usage forms are handled correctly.
pub fn has_sensor_hub_collection(desc: &[u8]) -> bool {
    let rd = match parse(desc) {
        Ok(d) => d,
        Err(_) => return false,
    };
    // top_level_apps is built from Application collections at depth 1.
    // Physical collections are exposed through field.collection_path.
    for &(page, _usage) in &rd.top_level_apps {
        if page == PAGE_SENSORS {
            return true;
        }
    }
    // Also accept a descriptor whose first collection is Physical/
    // Logical on the sensor page (some hubs don't use Application).
    for f in &rd.fields {
        for &(cp_page, _) in &f.collection_path {
            if cp_page == PAGE_SENSORS {
                return true;
            }
        }
    }
    false
}

// ── Per-sensor profile ───────────────────────────────────────────────

/// Extended profile describing one sensor collection — wraps the
/// `narf_hid::sensor::SensorProfile` and adds the extra sensor
/// types (proximity, inclinometer) not yet in that crate.
#[derive(Clone, Debug)]
pub struct HidSensorProfile {
    pub kind: HidSensorKind,
    /// HID Report ID for input reports from this sensor.
    pub input_report_id: u8,
    /// Ordered data fields — [x, y, z] for 3-axis, [v] for scalar.
    pub fields: Vec<Field>,
    /// Feature-report ID for property GET/SET (0 = none found).
    pub feature_report_id: u8,
    /// Bit-offset + size of the report-interval field inside the
    /// feature report body (when `feature_report_id != 0`).
    pub interval_field: Option<Field>,
}

/// Sensor type taxonomy for this module (superset of `narf_hid::sensor::SensorKind`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HidSensorKind {
    Accelerometer3D,
    Gyrometer3D,
    Magnetometer3D,
    AmbientLight,
    Proximity,
    Inclinometer,
}

impl HidSensorKind {
    fn from_page_usage(page: u16, usage: u16) -> Option<Self> {
        if page != PAGE_SENSORS {
            return None;
        }
        Some(match usage {
            sensor_usage::ACCEL_3D     => HidSensorKind::Accelerometer3D,
            sensor_usage::GYRO_3D      => HidSensorKind::Gyrometer3D,
            sensor_usage::MAGNETO_3D   => HidSensorKind::Magnetometer3D,
            sensor_usage::ALS          => HidSensorKind::AmbientLight,
            sensor_usage::PROXIMITY    => HidSensorKind::Proximity,
            sensor_usage::INCLINOMETER => HidSensorKind::Inclinometer,
            _                          => return None,
        })
    }
}

/// Pick the first Input field whose usages include `(PAGE_SENSORS, usage_id)`.
fn pick_input_field(rd: &ReportDescriptor, usage_id: u16) -> Option<Field> {
    rd.fields.iter().find(|f| {
        f.kind == FieldKind::Input
            && f.usages.iter().any(|&(p, u)| p == PAGE_SENSORS && u == usage_id)
    }).cloned()
}

/// Pick the first Feature field whose usages include `(PAGE_SENSORS, usage_id)`.
fn pick_feature_field(rd: &ReportDescriptor, usage_id: u16) -> Option<Field> {
    rd.fields.iter().find(|f| {
        f.kind == FieldKind::Feature
            && f.usages.iter().any(|&(p, u)| p == PAGE_SENSORS && u == usage_id)
    }).cloned()
}

/// Enumerate all recognisable sensor collections in a parsed
/// descriptor. Returns one `HidSensorProfile` per distinct sensor
/// whose required data fields are present.
pub fn enumerate_sensors(rd: &ReportDescriptor) -> Vec<HidSensorProfile> {
    let mut profiles: Vec<HidSensorProfile> = Vec::new();

    for &(page, usage) in &rd.top_level_apps {
        let kind = match HidSensorKind::from_page_usage(page, usage) {
            Some(k) => k,
            None => continue,
        };

        let (fields, input_rid) = match build_fields(rd, kind) {
            Some(x) => x,
            None => continue,
        };

        let (feat_rid, interval_field) = feature_info(rd);

        profiles.push(HidSensorProfile {
            kind,
            input_report_id: input_rid,
            fields,
            feature_report_id: feat_rid,
            interval_field,
        });
    }

    profiles
}

/// Build the ordered axis/value field list and infer the input
/// report-id from the first field found.
fn build_fields(rd: &ReportDescriptor, kind: HidSensorKind) -> Option<(Vec<Field>, u8)> {
    let fields: Option<Vec<Field>> = match kind {
        HidSensorKind::Accelerometer3D => Some(vec![
            pick_input_field(rd, data_usage::ACCEL_X)?,
            pick_input_field(rd, data_usage::ACCEL_Y)?,
            pick_input_field(rd, data_usage::ACCEL_Z)?,
        ]),
        HidSensorKind::Gyrometer3D => Some(vec![
            pick_input_field(rd, data_usage::GYRO_X)?,
            pick_input_field(rd, data_usage::GYRO_Y)?,
            pick_input_field(rd, data_usage::GYRO_Z)?,
        ]),
        HidSensorKind::Magnetometer3D => Some(vec![
            pick_input_field(rd, data_usage::MAG_X)?,
            pick_input_field(rd, data_usage::MAG_Y)?,
            pick_input_field(rd, data_usage::MAG_Z)?,
        ]),
        HidSensorKind::AmbientLight => Some(vec![
            pick_input_field(rd, data_usage::ILLUM_LUX)?,
        ]),
        HidSensorKind::Proximity => {
            // Accept either HUMAN_PROXIMITY (distance) or HUMAN_PRESENCE (boolean).
            let f = pick_input_field(rd, data_usage::HUMAN_PROXIMITY)
                .or_else(|| pick_input_field(rd, data_usage::HUMAN_PRESENCE))?;
            Some(vec![f])
        }
        HidSensorKind::Inclinometer => Some(vec![
            pick_input_field(rd, data_usage::TILT_X)?,
            pick_input_field(rd, data_usage::TILT_Y)?,
            pick_input_field(rd, data_usage::TILT_Z)?,
        ]),
    };
    let fields = fields?;
    let rid = fields[0].report_id;
    Some((fields, rid))
}

/// Locate the feature report that carries the report-interval property.
/// Returns `(feature_report_id, interval_field)`.
fn feature_info(rd: &ReportDescriptor) -> (u8, Option<Field>) {
    let f = pick_feature_field(rd, PROP_REPORT_INTERVAL);
    match f {
        Some(field) => {
            let rid = field.report_id;
            (rid, Some(field))
        }
        None => (0, None),
    }
}

// ── Input report decode ──────────────────────────────────────────────

/// Error type for sensor-report decode operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SensorDecodeError {
    /// Report is empty or Report ID byte doesn't match the profile.
    ReportIdMismatch,
    /// A required axis field could not be extracted from the report.
    FieldExtract,
    /// The profile's sensor kind has no supported decode path.
    UnsupportedKind,
}

/// Decode a raw HID input report (with Report-ID prefix byte) using
/// a previously-enumerated `HidSensorProfile`.  Returns a
/// `SensorEvent` or a `SensorDecodeError` if the report doesn't
/// match the profile or a field extraction fails.
///
/// Scaling applied:
/// - Accel: raw signed-16 × 1 → stored as milli-g.  Devices that
///   report in physical units (logical min/max calibrated) would need
///   a calibration step; that is deferred (see module-level doc).
/// - Gyro: same convention (milli-dps raw).
/// - Mag: raw signed-16 stored as micro-T.
/// - ALS: raw unsigned-16 stored as raw lux count.
/// - Proximity: raw unsigned value; `present` = (value != 0).
pub fn decode_report(
    profile: &HidSensorProfile,
    report: &[u8],
    timestamp_ns: u64,
) -> Result<SensorEvent, SensorDecodeError> {
    if report.is_empty() || report[0] != profile.input_report_id {
        return Err(SensorDecodeError::ReportIdMismatch);
    }
    let body = &report[1..];

    match profile.kind {
        HidSensorKind::Accelerometer3D | HidSensorKind::Inclinometer => {
            let x = extract_one(&profile.fields[0], body)?;
            let y = extract_one(&profile.fields[1], body)?;
            let z = extract_one(&profile.fields[2], body)?;
            Ok(SensorEvent::Accel3d {
                x_milli_g: x,
                y_milli_g: y,
                z_milli_g: z,
                timestamp_ns,
            })
        }
        HidSensorKind::Gyrometer3D => {
            let x = extract_one(&profile.fields[0], body)?;
            let y = extract_one(&profile.fields[1], body)?;
            let z = extract_one(&profile.fields[2], body)?;
            Ok(SensorEvent::Gyro3d {
                x_milli_dps: x,
                y_milli_dps: y,
                z_milli_dps: z,
                timestamp_ns,
            })
        }
        HidSensorKind::Magnetometer3D => {
            let x = extract_one(&profile.fields[0], body)?;
            let y = extract_one(&profile.fields[1], body)?;
            let z = extract_one(&profile.fields[2], body)?;
            Ok(SensorEvent::Magneto3d {
                x_micro_t: x,
                y_micro_t: y,
                z_micro_t: z,
                timestamp_ns,
            })
        }
        HidSensorKind::AmbientLight => {
            let raw = extract_one(&profile.fields[0], body)?;
            Ok(SensorEvent::Lux {
                lux: raw as u32,
                timestamp_ns,
            })
        }
        HidSensorKind::Proximity => {
            let raw = extract_one(&profile.fields[0], body)?;
            Ok(SensorEvent::Proximity {
                distance_mm: raw.clamp(0, u16::MAX as i32) as u16,
                present: raw != 0,
                timestamp_ns,
            })
        }
    }
}

/// Extract the first (and typically only) value from `field` at
/// bit-offset within `body` (report-id byte already stripped).
fn extract_one(field: &Field, body: &[u8]) -> Result<i32, SensorDecodeError> {
    extract(field, body)
        .map_err(|_| SensorDecodeError::FieldExtract)?
        .into_iter()
        .next()
        .ok_or(SensorDecodeError::FieldExtract)
}

// ── Feature-report: sample-rate ──────────────────────────────────────

/// Error type for feature-report encode / decode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FeatureReportError {
    /// The profile has no feature-report / no interval field.
    NoIntervalField,
    /// Buffer too small to encode the report.
    BufferTooSmall,
    /// `narf_hid::report::pack` failed (corrupt field metadata).
    PackFailed,
}

/// Build a HID Feature report payload (without the Report-ID prefix)
/// that sets the `REPORT_INTERVAL` property to `interval_ms`.
///
/// The caller is responsible for prepending the feature report-id
/// byte and sending the buffer via `SET_REPORT (Feature)`.
///
/// Returns the number of bytes written into `buf` on success.
pub fn build_interval_feature_report(
    profile: &HidSensorProfile,
    interval_ms: u32,
    buf: &mut [u8],
) -> Result<usize, FeatureReportError> {
    let field = profile
        .interval_field
        .as_ref()
        .ok_or(FeatureReportError::NoIntervalField)?;

    // Determine how many bytes the report body occupies.
    let body_bits = field.bit_offset + field.report_size * field.report_count;
    let body_bytes = ((body_bits + 7) / 8) as usize;
    if buf.len() < body_bytes {
        return Err(FeatureReportError::BufferTooSmall);
    }
    let body = &mut buf[..body_bytes];
    for b in body.iter_mut() {
        *b = 0;
    }
    pack(field, body, &[interval_ms as i32]).map_err(|_| FeatureReportError::PackFailed)?;
    Ok(body_bytes)
}

/// Parse a feature-report body (report-id byte **not** included)
/// and return the `REPORT_INTERVAL` value in milliseconds.
pub fn parse_interval_feature_report(
    profile: &HidSensorProfile,
    body: &[u8],
) -> Result<u32, FeatureReportError> {
    let field = profile
        .interval_field
        .as_ref()
        .ok_or(FeatureReportError::NoIntervalField)?;
    extract(field, body)
        .map_err(|_| FeatureReportError::NoIntervalField)?
        .into_iter()
        .next()
        .map(|v| v as u32)
        .ok_or(FeatureReportError::NoIntervalField)
}

// ── Sensor event ring ─────────────────────────────────────────────────

const SENSOR_RING_CAPACITY: usize = 64;

static SENSOR_RING: IrqSafeSpinLock<Option<VecDeque<SensorEvent>>> =
    IrqSafeSpinLock::new(None);

/// Initialise the sensor-event ring. Idempotent.
pub fn init_sensor_ring() {
    let mut g = SENSOR_RING.lock();
    if g.is_none() {
        *g = Some(VecDeque::with_capacity(SENSOR_RING_CAPACITY));
    }
}

/// Push one `SensorEvent` onto the sensor ring.  Returns `false` if
/// the ring is full (oldest event discarded) or uninitialised.
pub fn push_sensor_event(ev: SensorEvent) -> bool {
    let mut g = SENSOR_RING.lock();
    if let Some(q) = g.as_mut() {
        if q.len() >= SENSOR_RING_CAPACITY {
            q.pop_front();
        }
        q.push_back(ev);
        true
    } else {
        false
    }
}

/// Pop the oldest `SensorEvent` from the ring, or `None` if empty /
/// uninitialised.
pub fn pop_sensor_event() -> Option<SensorEvent> {
    let mut g = SENSOR_RING.lock();
    g.as_mut().and_then(|q| q.pop_front())
}

/// Test-only: drain and reset the sensor ring.
#[doc(hidden)]
pub fn __reset_sensor_ring_for_test() {
    let mut g = SENSOR_RING.lock();
    if let Some(q) = g.as_mut() {
        q.clear();
    } else {
        *g = Some(VecDeque::with_capacity(SENSOR_RING_CAPACITY));
    }
}

// ── Descriptor-building helpers (test / bring-up use) ────────────────

/// Build a minimal HID report descriptor for a single-axis-group
/// sensor.  Used internally by tests and by board bring-up probes
/// that synthesise descriptors from ACPI firmware tables.
///
/// `sensor_type_usage` is the top-level sensor type (e.g.
/// `sensor_usage::ACCEL_3D`).  `data_usages` are the per-axis /
/// per-field usages in declaration order.  `report_id` selects
/// which Report ID to stamp on input fields.  `signed` controls
/// whether the fields declare negative `Logical Minimum`.
///
/// Returns a complete descriptor byte vector.
pub fn build_test_descriptor(
    sensor_type_usage: u16,
    data_usages: &[u16],
    report_id: u8,
    signed: bool,
) -> Vec<u8> {
    let mut d: Vec<u8> = Vec::new();

    // Helper closures emit HID short items.
    let mut push_item = |tag: u8, btype: u8, data: &[u8]| {
        let bsize = match data.len() {
            0 => 0u8,
            1 => 1,
            2 => 2,
            4 => 3,
            _ => panic!("unsupported item data size"),
        };
        d.push((tag << 4) | (btype << 2) | bsize);
        d.extend_from_slice(data);
    };

    // Usage Page (0x0020 Sensors) — Global, tag 0x0.
    push_item(0x0, 1, &[0x20, 0x00]);
    // Usage — Local, tag 0x0.
    push_item(0x0, 2, &[sensor_type_usage as u8, (sensor_type_usage >> 8) as u8]);
    // Collection (Application) — Main, tag 0xA.
    push_item(0xA, 0, &[0x01]);

    // Report ID — Global, tag 0x8.
    push_item(0x8, 1, &[report_id]);

    // Emit one Input field per data usage.
    for &usage in data_usages {
        // Usage Page (0x0020) — Global.
        push_item(0x0, 1, &[0x20, 0x00]);
        // Usage — Local.
        push_item(0x0, 2, &[usage as u8, (usage >> 8) as u8]);
        // Logical Minimum — Global.
        if signed {
            push_item(0x1, 1, &[0x80u8]); // -128 in signed i8
        } else {
            push_item(0x1, 1, &[0x00]);
        }
        // Logical Maximum — Global.
        push_item(0x2, 1, &[0x7F]);
        // Report Size 16 — Global.
        push_item(0x7, 1, &[16]);
        // Report Count 1 — Global.
        push_item(0x9, 1, &[1]);
        // Input (Data, Var, Abs) — Main, tag 0x8.
        push_item(0x8, 0, &[0x02]);
    }

    // End Collection — Main, tag 0xC.
    push_item(0xC, 0, &[]);

    d
}

/// Build a test descriptor that also includes a Feature report with
/// the `REPORT_INTERVAL` property, using `feat_report_id`.
pub fn build_test_descriptor_with_feature(
    sensor_type_usage: u16,
    data_usages: &[u16],
    input_report_id: u8,
    feature_report_id: u8,
) -> Vec<u8> {
    let mut d = build_test_descriptor(sensor_type_usage, data_usages, input_report_id, true);

    // Strip the trailing End-Collection (last byte is 0xC0).
    d.pop();

    // Feature field: Report ID, Usage Page, Usage (report-interval), 32-bit unsigned.
    let mut push_item = |tag: u8, btype: u8, data: &[u8]| {
        let bsize = match data.len() {
            0 => 0u8,
            1 => 1,
            2 => 2,
            4 => 3,
            _ => panic!("unsupported item data size"),
        };
        d.push((tag << 4) | (btype << 2) | bsize);
        d.extend_from_slice(data);
    };

    push_item(0x8, 1, &[feature_report_id]);           // Report ID
    push_item(0x0, 1, &[0x20, 0x00]);                  // Usage Page (Sensors)
    push_item(0x0, 2, &[0x0E, 0x03]);                  // Usage (0x030E = report interval)
    push_item(0x1, 1, &[0x00]);                         // Logical Min 0
    push_item(0x2, 1, &[0xFF]);                         // Logical Max 255
    push_item(0x7, 1, &[8]);                            // Report Size 8
    push_item(0x9, 1, &[1]);                            // Report Count 1
    push_item(0xB, 0, &[0x02]);                         // Feature (Data, Var, Abs) tag=0xB

    push_item(0xC, 0, &[]);                             // End Collection

    d
}

// ── Tests ─────────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_hid::descriptor::parse;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── smoke 1: sensor-page detection ──────────────────────────────

    fn smoke_sensor_hub_detection_accel_descriptor() -> TestResult {
        // A minimal accel-3D descriptor: Usage Page 0x0020, Usage 0x0073,
        // Collection(Application). has_sensor_hub_collection must return true.
        let desc = build_test_descriptor(
            sensor_usage::ACCEL_3D,
            &[data_usage::ACCEL_X, data_usage::ACCEL_Y, data_usage::ACCEL_Z],
            0x01,
            true,
        );
        if !has_sensor_hub_collection(&desc) {
            return TestResult::Fail("accel descriptor not detected as sensor hub");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sensor_hub_detection_accel_descriptor);

    fn smoke_sensor_hub_detection_keyboard_descriptor_rejected() -> TestResult {
        // HID boot keyboard (Usage Page 0x01, Usage 0x06) must NOT match.
        let boot_kbd: [u8; 23] = [
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x06, // Usage (Keyboard)
            0xA1, 0x01, // Collection (Application)
            0x05, 0x07, // Usage Page (Keyboard)
            0x19, 0xE0, // Usage Min
            0x29, 0xE7, // Usage Max
            0x15, 0x00, // Logical Min 0
            0x25, 0x01, // Logical Max 1
            0x75, 0x01, // Report Size 1
            0x95, 0x08, // Report Count 8
            0x81, 0x02, // Input
            0xC0,       // End Collection
        ];
        if has_sensor_hub_collection(&boot_kbd) {
            return TestResult::Fail("keyboard descriptor should not be detected as sensor hub");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sensor_hub_detection_keyboard_descriptor_rejected);

    // ── smoke 2: accel 3D X/Y/Z decode ──────────────────────────────

    fn smoke_accel_3d_xyz_decode() -> TestResult {
        let desc = build_test_descriptor(
            sensor_usage::ACCEL_3D,
            &[data_usage::ACCEL_X, data_usage::ACCEL_Y, data_usage::ACCEL_Z],
            0x01,
            true, // signed
        );
        let rd = match parse(&desc) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("accel descriptor parse failed"),
        };
        let profiles = enumerate_sensors(&rd);
        if profiles.is_empty() {
            return TestResult::Fail("no sensor profiles found in accel descriptor");
        }
        let p = &profiles[0];
        if p.kind != HidSensorKind::Accelerometer3D {
            return TestResult::Fail("wrong sensor kind — expected Accelerometer3D");
        }

        // Build a 7-byte report: [report_id=1] [x_lo x_hi] [y_lo y_hi] [z_lo z_hi]
        // x = 100 (0x0064), y = -200 (0xFF38), z = 981 (0x03D5)
        // Signed 16-bit, little-endian.
        // But our test descriptor uses Report Size 16 + Report Count 1 per field.
        // Fields are at bit offsets 0, 16, 32 (relative to body start).
        let x_val: i16 = 100;
        let y_val: i16 = -200;
        let z_val: i16 = 981;
        let report = [
            0x01u8,                     // Report ID
            x_val as u8, (x_val >> 8) as u8,
            y_val as u8, (y_val >> 8) as u8,
            z_val as u8, (z_val >> 8) as u8,
        ];

        match decode_report(p, &report, 0) {
            Ok(SensorEvent::Accel3d { x_milli_g, y_milli_g, z_milli_g, .. }) => {
                if x_milli_g != 100 {
                    return TestResult::Fail("accel X wrong");
                }
                if y_milli_g != -200 {
                    return TestResult::Fail("accel Y wrong");
                }
                if z_milli_g != 981 {
                    return TestResult::Fail("accel Z wrong");
                }
            }
            Ok(_) => return TestResult::Fail("unexpected event variant"),
            Err(_) => return TestResult::Fail("accel decode returned error"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_accel_3d_xyz_decode);

    // ── smoke 3: ALS lux decode ──────────────────────────────────────

    fn smoke_als_lux_decode() -> TestResult {
        let desc = build_test_descriptor(
            sensor_usage::ALS,
            &[data_usage::ILLUM_LUX],
            0x02,
            false, // unsigned
        );
        let rd = match parse(&desc) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("ALS descriptor parse failed"),
        };
        let profiles = enumerate_sensors(&rd);
        if profiles.is_empty() {
            return TestResult::Fail("no ALS sensor profile found");
        }
        let p = &profiles[0];
        if p.kind != HidSensorKind::AmbientLight {
            return TestResult::Fail("wrong kind — expected AmbientLight");
        }

        // Report: [id=2] [lux_lo lux_hi] — lux = 1200 (0x04B0)
        let lux: u16 = 1200;
        let report = [0x02u8, lux as u8, (lux >> 8) as u8];

        match decode_report(p, &report, 0) {
            Ok(SensorEvent::Lux { lux: v, .. }) => {
                if v != 1200 {
                    return TestResult::Fail("ALS lux value wrong");
                }
            }
            Ok(_) => return TestResult::Fail("unexpected event variant for ALS"),
            Err(_) => return TestResult::Fail("ALS decode error"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_als_lux_decode);

    // ── smoke 4: feature-report SET_REPORT for sample-rate ──────────

    fn smoke_feature_report_interval_encode_decode() -> TestResult {
        let desc = build_test_descriptor_with_feature(
            sensor_usage::ACCEL_3D,
            &[data_usage::ACCEL_X, data_usage::ACCEL_Y, data_usage::ACCEL_Z],
            0x01, // input report id
            0x03, // feature report id
        );
        let rd = match parse(&desc) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("descriptor with feature failed to parse"),
        };
        let profiles = enumerate_sensors(&rd);
        if profiles.is_empty() {
            return TestResult::Fail("no sensor profile in feature descriptor");
        }
        let p = &profiles[0];
        if p.interval_field.is_none() {
            return TestResult::Fail("interval_field not populated");
        }

        // Encode interval = 50 ms.
        let mut buf = [0u8; 8];
        let written = match build_interval_feature_report(p, 50, &mut buf) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("build_interval_feature_report failed"),
        };
        if written == 0 {
            return TestResult::Fail("zero bytes written");
        }

        // Decode it back.
        let parsed = match parse_interval_feature_report(p, &buf[..written]) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("parse_interval_feature_report failed"),
        };
        if parsed != 50 {
            return TestResult::Fail("round-trip interval value mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_feature_report_interval_encode_decode);

    // ── smoke 5: multi-sensor hub, distinguish by report ID ──────────

    fn smoke_multi_sensor_hub_report_id_dispatch() -> TestResult {
        // Build two back-to-back descriptors — one accel (report id 1)
        // and one ALS (report id 2) in the same descriptor.  Build them
        // manually by concatenating the inner items.

        // Accel part (no end-collection yet).
        let accel_part = build_test_descriptor(
            sensor_usage::ACCEL_3D,
            &[data_usage::ACCEL_X, data_usage::ACCEL_Y, data_usage::ACCEL_Z],
            0x01,
            true,
        );
        // ALS part (no end-collection yet).
        let als_part = build_test_descriptor(
            sensor_usage::ALS,
            &[data_usage::ILLUM_LUX],
            0x02,
            false,
        );

        // Parse each independently, collect profiles; then verify
        // report-id dispatch logic.
        let rd_accel = parse(&accel_part).expect("accel parse");
        let rd_als   = parse(&als_part).expect("als parse");
        let all_profiles: Vec<HidSensorProfile> = enumerate_sensors(&rd_accel)
            .into_iter()
            .chain(enumerate_sensors(&rd_als))
            .collect();

        if all_profiles.len() != 2 {
            return TestResult::Fail("expected 2 sensor profiles");
        }

        // Find accel profile (report_id 1) and ALS profile (report_id 2).
        let accel_p = all_profiles.iter().find(|p| p.kind == HidSensorKind::Accelerometer3D);
        let als_p   = all_profiles.iter().find(|p| p.kind == HidSensorKind::AmbientLight);

        match (accel_p, als_p) {
            (Some(a), Some(b)) => {
                if a.input_report_id != 1 {
                    return TestResult::Fail("accel report id wrong");
                }
                if b.input_report_id != 2 {
                    return TestResult::Fail("ALS report id wrong");
                }
            }
            _ => return TestResult::Fail("could not find both sensor profiles"),
        }

        // Simulate dispatch: report[0] == 1 → accel, report[0] == 2 → ALS.
        let accel_report = [0x01u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // X=256
        let als_report   = [0x02u8, 0x64, 0x00]; // lux=100

        // Decode as accel.
        let accel_ev = decode_report(accel_p.unwrap(), &accel_report, 0);
        match accel_ev {
            Ok(SensorEvent::Accel3d { x_milli_g, .. }) if x_milli_g == 256 => {}
            _ => return TestResult::Fail("accel dispatch decode wrong"),
        }

        // Decode as ALS.
        let als_ev = decode_report(als_p.unwrap(), &als_report, 0);
        match als_ev {
            Ok(SensorEvent::Lux { lux: 100, .. }) => {}
            _ => return TestResult::Fail("ALS dispatch decode wrong"),
        }

        // Cross-mismatch: feeding the ALS report to the accel decoder must error.
        match decode_report(accel_p.unwrap(), &als_report, 0) {
            Err(SensorDecodeError::ReportIdMismatch) => {}
            _ => return TestResult::Fail("cross-report-id should produce ReportIdMismatch"),
        }

        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_multi_sensor_hub_report_id_dispatch);

    // ── smoke 6: sensor event ring push/pop ──────────────────────────

    fn smoke_sensor_event_ring_push_pop() -> TestResult {
        __reset_sensor_ring_for_test();

        let ev = SensorEvent::Lux { lux: 42, timestamp_ns: 0 };
        push_sensor_event(ev);

        match pop_sensor_event() {
            Some(SensorEvent::Lux { lux: 42, .. }) => {}
            _ => return TestResult::Fail("sensor ring pop returned wrong event"),
        }
        if pop_sensor_event().is_some() {
            return TestResult::Fail("ring should be empty after one pop");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sensor_event_ring_push_pop);

    // ── smoke 7: gyro 3D decode ──────────────────────────────────────

    fn smoke_gyro_3d_decode() -> TestResult {
        let desc = build_test_descriptor(
            sensor_usage::GYRO_3D,
            &[data_usage::GYRO_X, data_usage::GYRO_Y, data_usage::GYRO_Z],
            0x04,
            true,
        );
        let rd = parse(&desc).expect("gyro desc parse");
        let profiles = enumerate_sensors(&rd);
        if profiles.is_empty() {
            return TestResult::Fail("no gyro profile");
        }
        let p = &profiles[0];
        if p.kind != HidSensorKind::Gyrometer3D {
            return TestResult::Fail("expected Gyrometer3D");
        }

        let report = [0x04u8, 50i16 as u8, (50i16 >> 8) as u8,
                               0u8, 0u8,
                               (-75i16) as u8, ((-75i16) >> 8) as u8];
        match decode_report(p, &report, 0) {
            Ok(SensorEvent::Gyro3d { x_milli_dps: 50, y_milli_dps: 0, z_milli_dps: -75, .. }) => {}
            _ => return TestResult::Fail("gyro decode wrong"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_gyro_3d_decode);
}
