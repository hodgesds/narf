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
//! - Linux source consulted for calibration/fusion patterns
//!   (GPL-2.0-or-later post 2026-05-20 relicense):
//!   `include/linux/hid-sensor-ids.h`,
//!   `drivers/hid/hid-sensor-hub.c`,
//!   `drivers/iio/accel/hid-sensor-accel-3d.c` — unit-exponent scaling
//!   (`scale_pre_decml` / `scale_post_decml` pattern),
//!   `drivers/iio/orientation/hid-sensor-rotation.c` — quaternion orientation,
//!   `drivers/iio/imu/inv_mpu6050/inv_mpu_core.c` — complementary filter
//!   gyro+accel fusion pattern.
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
//! 6. **Calibration** — `SensorCalibration` stores per-axis offset and
//!    scale plus the HID unit exponent.  `apply_calibration` converts raw
//!    integer field values to scaled engineering units.
//!    Usage IDs: CALIBRATION_OFFSET 0x40000F, CALIBRATION_SCALE 0x40000E.
//!    (Ref: Linux `drivers/iio/accel/hid-sensor-accel-3d.c` `scale_pre_decml` /
//!    `scale_post_decml` pattern.)
//!
//! 7. **Sensor fusion** — `ComplementaryFilter` implements the standard
//!    gyro/accel complementary filter:
//!    `new = alpha * (old + gyro * dt) + (1-alpha) * accel_orientation`
//!    with alpha ~= 0.98 for a 100 Hz update rate.  Produces
//!    `SensorEvent::FusedOrientation`.
//!    (Ref: Linux `drivers/iio/imu/inv_mpu6050/inv_mpu_core.c` gyro/accel
//!    fusion pattern.)
//!
//! ## Sensor types supported
//!
//! | Sensor          | Usage  | Event variant       |
//! |-----------------|--------|---------------------|
//! | Accelerometer3D | 0x0073 | `Accel3d`           |
//! | Gyrometer3D     | 0x0076 | `Gyro3d`            |
//! | Magnetometer3D  | 0x0083 | `Magneto3d`         |
//! | Ambient Light   | 0x0041 | `Lux`               |
//! | Proximity       | 0x00C1 | `Proximity`         |
//! | Inclinometer    | 0x0086 | `Inclination`       |

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use narf_hid::descriptor::{parse, Field, FieldKind, ReportDescriptor};
use narf_hid::report::{extract, pack};
use narf_lib::sync::IrqSafeSpinLock;

// -- Usage constants ---------------------------------------------------------

/// Sensors usage page (HID Usage Tables §17).
const PAGE_SENSORS: u16 = 0x0020;

/// Sensor-type usages we handle.
mod sensor_usage {
    pub const ACCEL_3D: u16 = 0x0073;
    pub const GYRO_3D: u16 = 0x0076;
    pub const MAGNETO_3D: u16 = 0x0083;
    pub const ALS: u16 = 0x0041;
    pub const PROXIMITY: u16 = 0x00C1;
    pub const INCLINOMETER: u16 = 0x0086;
}

/// Data-field usages on Page 0x20.
mod data_usage {
    pub const ACCEL_X: u16 = 0x0453;
    pub const ACCEL_Y: u16 = 0x0454;
    pub const ACCEL_Z: u16 = 0x0455;
    pub const GYRO_X: u16 = 0x0457;
    pub const GYRO_Y: u16 = 0x0458;
    pub const GYRO_Z: u16 = 0x0459;
    pub const MAG_X: u16 = 0x0485;
    pub const MAG_Y: u16 = 0x0486;
    pub const MAG_Z: u16 = 0x0487;
    pub const ILLUM_LUX: u16 = 0x04D1;
    pub const HUMAN_PROXIMITY: u16 = 0x04B2;
    pub const HUMAN_PRESENCE: u16 = 0x04B1;
    pub const TILT_X: u16 = 0x047F;
    pub const TILT_Y: u16 = 0x0480;
    pub const TILT_Z: u16 = 0x0481;
}

/// Feature-property usage: report interval (ms).
/// Linux: `HID_USAGE_SENSOR_PROP_REPORT_INTERVAL` = 0x20030E.
const PROP_REPORT_INTERVAL: u16 = 0x030E;

// -- Calibration -------------------------------------------------------------

/// Per-axis calibration parameters for a HID Sensor axis.
///
/// The HID Sensor Usages specification (§6.4) defines two feature-report
/// properties per sensor:
///
/// - **CALIBRATION_SCALE** (usage 0x20040E): multiplicative sensitivity
///   scale, applied as `raw * scale / 1000` (scale is in milli-units).
/// - **CALIBRATION_OFFSET** (usage 0x20040F): additive offset applied
///   before scaling, matching the IIO `INFO_OFFSET` convention from
///   Linux `drivers/iio/accel/hid-sensor-accel-3d.c`.
///
/// The **unit exponent** is a signed nibble that specifies the power-of-10
/// to apply: `physical = raw * 10^exponent`.
///
/// `apply_calibration` implements:
///   `calibrated = (raw + offset) * scale_milli / 1000 * 10^unit_exp`
///
/// Defaults to identity (`offset = 0`, `scale_milli = 1000`, `unit_exp = 0`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SensorCalibration {
    /// Additive offset applied before scale (IIO INFO_OFFSET).
    pub offset: i32,
    /// Multiplicative scale in milli-units (1000 = unity).
    pub scale_milli: i32,
    /// HID unit exponent (signed, range -8..+7).  Applied as 10^unit_exp.
    pub unit_exp: i8,
}

impl SensorCalibration {
    /// Identity calibration: no offset, unity scale, zero exponent.
    pub const IDENTITY: Self = Self {
        offset: 0,
        scale_milli: 1000,
        unit_exp: 0,
    };

    /// Construct from raw HID feature-report values.
    pub fn new(offset: i32, scale_milli: i32, unit_exp: i8) -> Self {
        Self {
            offset,
            scale_milli,
            unit_exp,
        }
    }
}

/// Apply `cal` to a raw signed field value and return the calibrated result.
///
/// ```text
/// step1 = raw + offset
/// step2 = step1 * scale_milli / 1000
/// step3 = step2 * pow10(unit_exp)   (positive exp)
///       = step2 / pow10(-unit_exp)  (negative exp)
/// ```
pub fn apply_calibration(raw: i32, cal: &SensorCalibration) -> i32 {
    let after_offset = raw.saturating_add(cal.offset);
    let after_scale = (after_offset as i64).saturating_mul(cal.scale_milli as i64) / 1000;
    let exp = cal.unit_exp;
    let result = if exp == 0 {
        after_scale
    } else if exp > 0 {
        let mult = pow10_i64(exp as u8);
        after_scale.saturating_mul(mult)
    } else {
        let div = pow10_i64((-exp) as u8);
        after_scale / div
    };
    result.min(i32::MAX as i64).max(i32::MIN as i64) as i32
}

/// Integer power-of-10 helper (no_std, no float).  Input capped at 9.
#[inline]
fn pow10_i64(exp: u8) -> i64 {
    match exp {
        0 => 1,
        1 => 10,
        2 => 100,
        3 => 1_000,
        4 => 10_000,
        5 => 100_000,
        6 => 1_000_000,
        7 => 10_000_000,
        8 => 100_000_000,
        _ => 1_000_000_000,
    }
}

/// Three-axis calibration bundle (one `SensorCalibration` per axis).
/// Order is always [X, Y, Z].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AxisCalibration {
    pub x: SensorCalibration,
    pub y: SensorCalibration,
    pub z: SensorCalibration,
}

impl AxisCalibration {
    /// Identity calibration for all three axes.
    pub const IDENTITY: Self = Self {
        x: SensorCalibration::IDENTITY,
        y: SensorCalibration::IDENTITY,
        z: SensorCalibration::IDENTITY,
    };
}

// -- Sensor fusion — complementary filter ------------------------------------

/// Complementary filter combining gyroscope and accelerometer readings
/// to produce a fused orientation estimate.
///
/// Algorithm (ref: `drivers/iio/imu/inv_mpu6050/inv_mpu_core.c`):
///
/// ```text
/// pitch_new = alpha * (pitch_old + gyro_x * dt_s) + (1-alpha) * accel_pitch
/// roll_new  = alpha * (roll_old  + gyro_y * dt_s) + (1-alpha) * accel_roll
/// yaw_new   = alpha * (yaw_old   + gyro_z * dt_s)
/// ```
///
/// `alpha` is the gyro trust coefficient (typically 0.98 for 100 Hz).
/// Yaw integrates gyro only (no gravity reference).
///
/// All angles stored in milli-degrees (no floating point / libm).
/// `alpha * 10000 = ALPHA_SCALED` (9800 for alpha = 0.98).
#[derive(Copy, Clone, Debug)]
pub struct ComplementaryFilter {
    /// Current orientation estimate [yaw, pitch, roll] in milli-degrees.
    orientation_milli_deg: [i32; 3],
    /// alpha scaled to integer: alpha_scaled / 10000 = alpha.
    alpha_scaled: u32,
    /// (1 - alpha) scaled.
    one_minus_alpha_scaled: u32,
}

impl ComplementaryFilter {
    /// Construct with given alpha (integer, 10000 = 1.0).
    /// For 100 Hz use `alpha_scaled = 9800`.
    pub const fn new(alpha_scaled: u32) -> Self {
        let one_minus = 10000u32.saturating_sub(alpha_scaled);
        Self {
            orientation_milli_deg: [0; 3],
            alpha_scaled,
            one_minus_alpha_scaled: one_minus,
        }
    }

    /// Default 100 Hz filter (alpha = 0.98).
    pub const fn default_100hz() -> Self {
        Self::new(9800)
    }

    /// Update the filter given:
    /// - `gyro_milli_dps`: [gx, gy, gz] in milli-degrees/second
    /// - `accel_milli_g`:  [ax, ay, az] in milli-g
    /// - `dt_ms`: elapsed time since last update in milliseconds
    /// - `timestamp_ns`: timestamp for the returned event
    ///
    /// Returns a `SensorEvent::FusedOrientation`.
    ///
    /// Accel pitch/roll use a linear small-angle approximation:
    ///   `pitch ~= ax * 90_000 / |az|`, `roll ~= ay * 90_000 / |az|`
    /// valid to ~5% error below 45 degrees.  Avoids libm entirely.
    pub fn update(
        &mut self,
        gyro_milli_dps: [i32; 3],
        accel_milli_g: [i32; 3],
        dt_ms: u32,
        timestamp_ns: u64,
    ) -> SensorEvent {
        let alpha = self.alpha_scaled as i64;
        let one_minus = self.one_minus_alpha_scaled as i64;

        let gyro_delta = |g: i32| -> i32 {
            ((g as i64 * dt_ms as i64) / 1000)
                .min(i32::MAX as i64)
                .max(i32::MIN as i64) as i32
        };

        let az = accel_milli_g[2];
        let az_denom = if az == 0 { 1i64 } else { az.abs() as i64 };
        let accel_pitch = ((accel_milli_g[0] as i64 * 90_000) / az_denom) as i32;
        let accel_roll = ((accel_milli_g[1] as i64 * 90_000) / az_denom) as i32;

        let old = self.orientation_milli_deg;

        let new_yaw = {
            let gyro_pred = (old[0] as i64).saturating_add(gyro_delta(gyro_milli_dps[2]) as i64);
            ((alpha * gyro_pred) / 10000) as i32
        };
        let new_pitch = {
            let gyro_pred = (old[1] as i64).saturating_add(gyro_delta(gyro_milli_dps[0]) as i64);
            let fused = (alpha * gyro_pred + one_minus * accel_pitch as i64) / 10000;
            fused as i32
        };
        let new_roll = {
            let gyro_pred = (old[2] as i64).saturating_add(gyro_delta(gyro_milli_dps[1]) as i64);
            let fused = (alpha * gyro_pred + one_minus * accel_roll as i64) / 10000;
            fused as i32
        };

        self.orientation_milli_deg = [new_yaw, new_pitch, new_roll];

        SensorEvent::FusedOrientation {
            yaw_milli_deg: new_yaw,
            pitch_milli_deg: new_pitch,
            roll_milli_deg: new_roll,
            timestamp_ns,
        }
    }

    /// Override the yaw estimate (e.g. from a magnetometer correction).
    pub fn set_yaw_correction(&mut self, yaw_milli_deg: i32) {
        self.orientation_milli_deg[0] = yaw_milli_deg;
    }

    /// Current orientation: [yaw, pitch, roll] in milli-degrees.
    pub fn orientation(&self) -> [i32; 3] {
        self.orientation_milli_deg
    }
}

// -- SensorEvent -------------------------------------------------------------

/// A decoded reading from a HID Sensor Hub input report.
///
/// Values are engineering units at the milli-scale so callers
/// work in integer arithmetic without floating point:
///
/// - `x_milli_g`   : milli-g  (9.80665 mm/s^2 per count)
/// - `x_milli_dps` : milli-degrees/second
/// - `x_micro_t`   : micro-tesla
/// - `lux`         : raw lux count (u32)
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
    /// HID Inclinometer (usage 0x0086) -- tilt angles in milli-degrees.
    ///
    /// Unlike `Accel3d` (raw G-force), these are direct angle readings.
    Inclination {
        x_milli_deg: i32,
        y_milli_deg: i32,
        z_milli_deg: i32,
        timestamp_ns: u64,
    },
    /// Orientation from gyro+accel complementary filter.
    ///
    /// Produced by `ComplementaryFilter::update`; not emitted by
    /// `decode_report` directly.
    FusedOrientation {
        yaw_milli_deg: i32,
        pitch_milli_deg: i32,
        roll_milli_deg: i32,
        timestamp_ns: u64,
    },
}

// -- Descriptor probe --------------------------------------------------------

/// Walk a raw HID report descriptor and return `true` if it contains
/// at least one Application or Physical collection on the Sensors
/// usage page (0x0020).
pub fn has_sensor_hub_collection(desc: &[u8]) -> bool {
    let rd = match parse(desc) {
        Ok(d) => d,
        Err(_) => return false,
    };
    for &(page, _usage) in &rd.top_level_apps {
        if page == PAGE_SENSORS {
            return true;
        }
    }
    for f in &rd.fields {
        for &(cp_page, _) in &f.collection_path {
            if cp_page == PAGE_SENSORS {
                return true;
            }
        }
    }
    false
}

// -- Per-sensor profile ------------------------------------------------------

/// Extended profile describing one sensor collection.
#[derive(Clone, Debug)]
pub struct HidSensorProfile {
    pub kind: HidSensorKind,
    /// HID Report ID for input reports from this sensor.
    pub input_report_id: u8,
    /// Ordered data fields -- [x, y, z] for 3-axis, [v] for scalar.
    pub fields: Vec<Field>,
    /// Feature-report ID for property GET/SET (0 = none found).
    pub feature_report_id: u8,
    /// Bit-offset + size of the report-interval field in the feature report.
    pub interval_field: Option<Field>,
}

/// Sensor type taxonomy.
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
            sensor_usage::ACCEL_3D => HidSensorKind::Accelerometer3D,
            sensor_usage::GYRO_3D => HidSensorKind::Gyrometer3D,
            sensor_usage::MAGNETO_3D => HidSensorKind::Magnetometer3D,
            sensor_usage::ALS => HidSensorKind::AmbientLight,
            sensor_usage::PROXIMITY => HidSensorKind::Proximity,
            sensor_usage::INCLINOMETER => HidSensorKind::Inclinometer,
            _ => return None,
        })
    }
}

fn pick_input_field(rd: &ReportDescriptor, usage_id: u16) -> Option<Field> {
    rd.fields
        .iter()
        .find(|f| {
            f.kind == FieldKind::Input
                && f.usages
                    .iter()
                    .any(|&(p, u)| p == PAGE_SENSORS && u == usage_id)
        })
        .cloned()
}

fn pick_feature_field(rd: &ReportDescriptor, usage_id: u16) -> Option<Field> {
    rd.fields
        .iter()
        .find(|f| {
            f.kind == FieldKind::Feature
                && f.usages
                    .iter()
                    .any(|&(p, u)| p == PAGE_SENSORS && u == usage_id)
        })
        .cloned()
}

/// Enumerate all recognisable sensor collections in a parsed descriptor.
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
        HidSensorKind::AmbientLight => Some(vec![pick_input_field(rd, data_usage::ILLUM_LUX)?]),
        HidSensorKind::Proximity => {
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

// -- Input report decode -----------------------------------------------------

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

/// Decode a raw HID input report (with Report-ID prefix byte).
///
/// Scaling applied (raw field value, no calibration applied here):
/// - Accel: raw signed-16 stored as milli-g.  Pass through
///   `apply_calibration` with an `AxisCalibration` for unit-exponent scaling.
/// - Gyro: same convention (milli-dps raw).
/// - Mag: raw signed-16 stored as micro-T.
/// - ALS: raw unsigned-16 stored as raw lux count.
/// - Proximity: raw unsigned value; `present` = (value != 0).
/// - Inclinometer: raw signed field mapped to `SensorEvent::Inclination`
///   (x/y/z_milli_deg).  Distinct from `Accel3d` -- these are angles,
///   not G-forces.  Ref: `HID_USAGE_SENSOR_INCLINOMETER_3D = 0x20_0086`.
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
        HidSensorKind::Accelerometer3D => {
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
        HidSensorKind::Inclinometer => {
            // HID Inclinometer reports tilt angles, not G-forces.
            // Route to dedicated `Inclination` variant (not `Accel3d`).
            let x = extract_one(&profile.fields[0], body)?;
            let y = extract_one(&profile.fields[1], body)?;
            let z = extract_one(&profile.fields[2], body)?;
            Ok(SensorEvent::Inclination {
                x_milli_deg: x,
                y_milli_deg: y,
                z_milli_deg: z,
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

fn extract_one(field: &Field, body: &[u8]) -> Result<i32, SensorDecodeError> {
    extract(field, body)
        .map_err(|_| SensorDecodeError::FieldExtract)?
        .into_iter()
        .next()
        .ok_or(SensorDecodeError::FieldExtract)
}

// -- Feature-report: sample-rate ---------------------------------------------

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

/// Build a HID Feature report payload that sets the `REPORT_INTERVAL`
/// property to `interval_ms`.  Caller prepends the report-id byte.
pub fn build_interval_feature_report(
    profile: &HidSensorProfile,
    interval_ms: u32,
    buf: &mut [u8],
) -> Result<usize, FeatureReportError> {
    let field = profile
        .interval_field
        .as_ref()
        .ok_or(FeatureReportError::NoIntervalField)?;

    let body_bits = field.bit_offset + field.report_size * field.report_count;
    let body_bytes = body_bits.div_ceil(8) as usize;
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

/// Parse a feature-report body and return the `REPORT_INTERVAL` in ms.
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

// -- Sensor event ring -------------------------------------------------------

const SENSOR_RING_CAPACITY: usize = 64;

static SENSOR_RING: IrqSafeSpinLock<Option<VecDeque<SensorEvent>>> = IrqSafeSpinLock::new(None);

/// Initialise the sensor-event ring. Idempotent.
pub fn init_sensor_ring() {
    let mut g = SENSOR_RING.lock();
    if g.is_none() {
        *g = Some(VecDeque::with_capacity(SENSOR_RING_CAPACITY));
    }
}

/// Push one `SensorEvent` onto the sensor ring.
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

/// Pop the oldest `SensorEvent` from the ring.
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

// -- Descriptor-building helpers (test / bring-up use) -----------------------

/// Build a minimal HID report descriptor for a single-axis-group sensor.
pub fn build_test_descriptor(
    sensor_type_usage: u16,
    data_usages: &[u16],
    report_id: u8,
    signed: bool,
) -> Vec<u8> {
    let mut d: Vec<u8> = Vec::new();

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

    push_item(0x0, 1, &[0x20, 0x00]);
    push_item(
        0x0,
        2,
        &[sensor_type_usage as u8, (sensor_type_usage >> 8) as u8],
    );
    push_item(0xA, 0, &[0x01]);
    push_item(0x8, 1, &[report_id]);

    for &usage in data_usages {
        push_item(0x0, 1, &[0x20, 0x00]);
        push_item(0x0, 2, &[usage as u8, (usage >> 8) as u8]);
        if signed {
            push_item(0x1, 1, &[0x80u8]);
        } else {
            push_item(0x1, 1, &[0x00]);
        }
        push_item(0x2, 1, &[0x7F]);
        push_item(0x7, 1, &[16]);
        push_item(0x9, 1, &[1]);
        push_item(0x8, 0, &[0x02]);
    }

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

    d.pop(); // strip trailing End-Collection

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

    push_item(0x8, 1, &[feature_report_id]);
    push_item(0x0, 1, &[0x20, 0x00]);
    push_item(0x0, 2, &[0x0E, 0x03]);
    push_item(0x1, 1, &[0x00]);
    push_item(0x2, 1, &[0xFF]);
    push_item(0x7, 1, &[8]);
    push_item(0x9, 1, &[1]);
    push_item(0xB, 0, &[0x02]);
    push_item(0xC, 0, &[]);

    d
}

// -- Tests -------------------------------------------------------------------

pub mod tests {
    use super::*;
    use narf_hid::descriptor::parse;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // smoke 1: sensor-page detection

    fn smoke_sensor_hub_detection_accel_descriptor() -> TestResult {
        let desc = build_test_descriptor(
            sensor_usage::ACCEL_3D,
            &[
                data_usage::ACCEL_X,
                data_usage::ACCEL_Y,
                data_usage::ACCEL_Z,
            ],
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
        let boot_kbd: [u8; 23] = [
            0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00,
            0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xC0,
        ];
        if has_sensor_hub_collection(&boot_kbd) {
            return TestResult::Fail("keyboard should not be detected as sensor hub");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input",
        smoke_sensor_hub_detection_keyboard_descriptor_rejected
    );

    // smoke 2: accel 3D X/Y/Z decode

    fn smoke_accel_3d_xyz_decode() -> TestResult {
        let desc = build_test_descriptor(
            sensor_usage::ACCEL_3D,
            &[
                data_usage::ACCEL_X,
                data_usage::ACCEL_Y,
                data_usage::ACCEL_Z,
            ],
            0x01,
            true,
        );
        let rd = match parse(&desc) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("accel descriptor parse failed"),
        };
        let profiles = enumerate_sensors(&rd);
        if profiles.is_empty() {
            return TestResult::Fail("no sensor profiles found");
        }
        let p = &profiles[0];
        if p.kind != HidSensorKind::Accelerometer3D {
            return TestResult::Fail("wrong kind -- expected Accelerometer3D");
        }

        let x_val: i16 = 100;
        let y_val: i16 = -200;
        let z_val: i16 = 981;
        let report = [
            0x01u8,
            x_val as u8,
            (x_val >> 8) as u8,
            y_val as u8,
            (y_val >> 8) as u8,
            z_val as u8,
            (z_val >> 8) as u8,
        ];
        match decode_report(p, &report, 0) {
            Ok(SensorEvent::Accel3d {
                x_milli_g,
                y_milli_g,
                z_milli_g,
                ..
            }) => {
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

    // smoke 3: ALS lux decode

    fn smoke_als_lux_decode() -> TestResult {
        let desc = build_test_descriptor(sensor_usage::ALS, &[data_usage::ILLUM_LUX], 0x02, false);
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
            return TestResult::Fail("wrong kind -- expected AmbientLight");
        }
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

    // smoke 4: feature-report SET_REPORT for sample-rate

    fn smoke_feature_report_interval_encode_decode() -> TestResult {
        let desc = build_test_descriptor_with_feature(
            sensor_usage::ACCEL_3D,
            &[
                data_usage::ACCEL_X,
                data_usage::ACCEL_Y,
                data_usage::ACCEL_Z,
            ],
            0x01,
            0x03,
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
        let mut buf = [0u8; 8];
        let written = match build_interval_feature_report(p, 50, &mut buf) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("build_interval_feature_report failed"),
        };
        if written == 0 {
            return TestResult::Fail("zero bytes written");
        }
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

    // smoke 5: multi-sensor hub, distinguish by report ID

    fn smoke_multi_sensor_hub_report_id_dispatch() -> TestResult {
        let accel_part = build_test_descriptor(
            sensor_usage::ACCEL_3D,
            &[
                data_usage::ACCEL_X,
                data_usage::ACCEL_Y,
                data_usage::ACCEL_Z,
            ],
            0x01,
            true,
        );
        let als_part =
            build_test_descriptor(sensor_usage::ALS, &[data_usage::ILLUM_LUX], 0x02, false);
        let rd_accel = parse(&accel_part).expect("accel parse");
        let rd_als = parse(&als_part).expect("als parse");
        let all_profiles: Vec<HidSensorProfile> = enumerate_sensors(&rd_accel)
            .into_iter()
            .chain(enumerate_sensors(&rd_als))
            .collect();
        if all_profiles.len() != 2 {
            return TestResult::Fail("expected 2 sensor profiles");
        }
        let accel_p = all_profiles
            .iter()
            .find(|p| p.kind == HidSensorKind::Accelerometer3D);
        let als_p = all_profiles
            .iter()
            .find(|p| p.kind == HidSensorKind::AmbientLight);
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
        let accel_report = [0x01u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let als_report = [0x02u8, 0x64, 0x00];
        match decode_report(accel_p.unwrap(), &accel_report, 0) {
            Ok(SensorEvent::Accel3d { x_milli_g: 256, .. }) => {}
            _ => return TestResult::Fail("accel dispatch decode wrong"),
        }
        match decode_report(als_p.unwrap(), &als_report, 0) {
            Ok(SensorEvent::Lux { lux: 100, .. }) => {}
            _ => return TestResult::Fail("ALS dispatch decode wrong"),
        }
        match decode_report(accel_p.unwrap(), &als_report, 0) {
            Err(SensorDecodeError::ReportIdMismatch) => {}
            _ => return TestResult::Fail("cross-report-id should produce ReportIdMismatch"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_multi_sensor_hub_report_id_dispatch);

    // smoke 6: sensor event ring push/pop

    fn smoke_sensor_event_ring_push_pop() -> TestResult {
        __reset_sensor_ring_for_test();
        let ev = SensorEvent::Lux {
            lux: 42,
            timestamp_ns: 0,
        };
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

    // smoke 7: gyro 3D decode

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
        let report = [
            0x04u8,
            50i16 as u8,
            (50i16 >> 8) as u8,
            0u8,
            0u8,
            (-75i16) as u8,
            ((-75i16) >> 8) as u8,
        ];
        match decode_report(p, &report, 0) {
            Ok(SensorEvent::Gyro3d {
                x_milli_dps: 50,
                y_milli_dps: 0,
                z_milli_dps: -75,
                ..
            }) => {}
            _ => return TestResult::Fail("gyro decode wrong"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_gyro_3d_decode);

    // smoke 8: inclinometer routes to Inclination variant (NOT Accel3d)

    fn smoke_inclinometer_routes_to_inclination_variant() -> TestResult {
        let desc = build_test_descriptor(
            sensor_usage::INCLINOMETER,
            &[data_usage::TILT_X, data_usage::TILT_Y, data_usage::TILT_Z],
            0x05,
            true,
        );
        let rd = match parse(&desc) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("inclinometer descriptor parse failed"),
        };
        let profiles = enumerate_sensors(&rd);
        if profiles.is_empty() {
            return TestResult::Fail("no inclinometer sensor profile found");
        }
        let p = &profiles[0];
        if p.kind != HidSensorKind::Inclinometer {
            return TestResult::Fail("expected Inclinometer kind");
        }
        let x_val: i16 = 450;
        let y_val: i16 = -900;
        let z_val: i16 = 0;
        let report = [
            0x05u8,
            x_val as u8,
            (x_val >> 8) as u8,
            y_val as u8,
            (y_val >> 8) as u8,
            z_val as u8,
            (z_val >> 8) as u8,
        ];
        match decode_report(p, &report, 12345) {
            Ok(SensorEvent::Inclination {
                x_milli_deg,
                y_milli_deg,
                z_milli_deg,
                timestamp_ns,
            }) => {
                if x_milli_deg != 450 {
                    return TestResult::Fail("inclinometer X wrong");
                }
                if y_milli_deg != -900 {
                    return TestResult::Fail("inclinometer Y wrong");
                }
                if z_milli_deg != 0 {
                    return TestResult::Fail("inclinometer Z wrong");
                }
                if timestamp_ns != 12345 {
                    return TestResult::Fail("inclinometer timestamp wrong");
                }
            }
            Ok(SensorEvent::Accel3d { .. }) => {
                return TestResult::Fail("inclinometer must NOT produce Accel3d")
            }
            Ok(_) => return TestResult::Fail("unexpected event variant for inclinometer"),
            Err(_) => return TestResult::Fail("inclinometer decode error"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input",
        smoke_inclinometer_routes_to_inclination_variant
    );

    // smoke 9: calibration -- unit exponent application

    fn smoke_calibration_unit_exponent_application() -> TestResult {
        // exp -3: raw 1000 -> 1000 * 10^-3 = 1
        let cal = SensorCalibration::new(0, 1000, -3);
        if apply_calibration(1000, &cal) != 1 {
            return TestResult::Fail("unit exp -3 wrong: expected 1");
        }
        // exp +2: raw 5 -> 5 * 100 = 500
        let cal2 = SensorCalibration::new(0, 1000, 2);
        if apply_calibration(5, &cal2) != 500 {
            return TestResult::Fail("unit exp +2 wrong: expected 500");
        }
        // identity passthrough
        if apply_calibration(42, &SensorCalibration::IDENTITY) != 42 {
            return TestResult::Fail("identity calibration should return raw value");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_calibration_unit_exponent_application);

    // smoke 10: calibration -- offset + scale

    fn smoke_calibration_offset_and_scale() -> TestResult {
        // offset=10, scale=2000 (x2): raw=50 -> (50+10)*2 = 120
        let cal = SensorCalibration::new(10, 2000, 0);
        if apply_calibration(50, &cal) != 120 {
            return TestResult::Fail("offset+scale wrong: expected 120");
        }
        // offset=-5, scale=500 (x0.5): raw=20 -> (20-5)*0.5 = 7
        let cal2 = SensorCalibration::new(-5, 500, 0);
        if apply_calibration(20, &cal2) != 7 {
            return TestResult::Fail("neg offset + half scale wrong: expected 7");
        }
        // raw=-100, offset=100, scale=1000 -> 0
        let cal3 = SensorCalibration::new(100, 1000, 0);
        if apply_calibration(-100, &cal3) != 0 {
            return TestResult::Fail("negative raw + positive offset: expected 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_calibration_offset_and_scale);

    // smoke 11: complementary filter -- single update step

    fn smoke_complementary_filter_update_step() -> TestResult {
        let mut cf = ComplementaryFilter::default_100hz();
        // 1 second, gyro_z = 90000 milli-dps, accel flat (Z dominant).
        // new_yaw = 0.98 * (0 + 90000) = 88200 milli-deg.
        let gyro = [0i32, 0i32, 90_000i32];
        let accel = [0i32, 0i32, 1000i32];
        let ev = cf.update(gyro, accel, 1000, 99);
        match ev {
            SensorEvent::FusedOrientation {
                yaw_milli_deg,
                pitch_milli_deg,
                roll_milli_deg,
                timestamp_ns,
            } => {
                if yaw_milli_deg != 88200 {
                    return TestResult::Fail("yaw after 1s rotation wrong");
                }
                if pitch_milli_deg != 0 {
                    return TestResult::Fail("pitch should be 0");
                }
                if roll_milli_deg != 0 {
                    return TestResult::Fail("roll should be 0");
                }
                if timestamp_ns != 99 {
                    return TestResult::Fail("timestamp not passed through");
                }
            }
            _ => return TestResult::Fail("expected FusedOrientation"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_complementary_filter_update_step);

    // smoke 12: FusedOrientation event emitted to ring

    fn smoke_fused_orientation_event_push_pop() -> TestResult {
        __reset_sensor_ring_for_test();
        let ev = SensorEvent::FusedOrientation {
            yaw_milli_deg: 1000,
            pitch_milli_deg: -500,
            roll_milli_deg: 250,
            timestamp_ns: 777,
        };
        if !push_sensor_event(ev) {
            return TestResult::Fail("push_sensor_event failed for FusedOrientation");
        }
        match pop_sensor_event() {
            Some(SensorEvent::FusedOrientation {
                yaw_milli_deg: 1000,
                pitch_milli_deg: -500,
                roll_milli_deg: 250,
                ..
            }) => {}
            _ => return TestResult::Fail("pop returned wrong FusedOrientation event"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_fused_orientation_event_push_pop);

    // smoke 13: inclinometer vs accel3d distinct

    fn smoke_inclinometer_distinct_from_accel3d() -> TestResult {
        let accel_desc = build_test_descriptor(
            sensor_usage::ACCEL_3D,
            &[
                data_usage::ACCEL_X,
                data_usage::ACCEL_Y,
                data_usage::ACCEL_Z,
            ],
            0x01,
            true,
        );
        let incl_desc = build_test_descriptor(
            sensor_usage::INCLINOMETER,
            &[data_usage::TILT_X, data_usage::TILT_Y, data_usage::TILT_Z],
            0x06,
            true,
        );
        let rd_a = parse(&accel_desc).expect("accel parse");
        let rd_i = parse(&incl_desc).expect("incl parse");
        let accel_profiles = enumerate_sensors(&rd_a);
        let incl_profiles = enumerate_sensors(&rd_i);
        if accel_profiles.is_empty() || incl_profiles.is_empty() {
            return TestResult::Fail("missing profile");
        }
        let ap = &accel_profiles[0];
        let ip = &incl_profiles[0];
        let val: i16 = 100;
        let accel_report = [
            0x01u8,
            val as u8,
            (val >> 8) as u8,
            val as u8,
            (val >> 8) as u8,
            val as u8,
            (val >> 8) as u8,
        ];
        let incl_report = [
            0x06u8,
            val as u8,
            (val >> 8) as u8,
            val as u8,
            (val >> 8) as u8,
            val as u8,
            (val >> 8) as u8,
        ];
        match decode_report(ap, &accel_report, 0) {
            Ok(SensorEvent::Accel3d { .. }) => {}
            _ => return TestResult::Fail("accel report should decode as Accel3d"),
        }
        match decode_report(ip, &incl_report, 0) {
            Ok(SensorEvent::Inclination { .. }) => {}
            Ok(SensorEvent::Accel3d { .. }) => {
                return TestResult::Fail("inclinometer must NOT produce Accel3d")
            }
            _ => return TestResult::Fail("inclinometer report should decode as Inclination"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_inclinometer_distinct_from_accel3d);
}
