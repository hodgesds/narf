//! HID Sensor Collections profile decoder — clean-room.
//!
//! ## Sources (public only)
//!
//! - **HID Sensor Usages**, USB-IF, 2017 (HID Usage Tables 1.4
//!   Page 0x20 ratification + the supplementary "HID Sensor
//!   Usages" document).
//!   <https://usb.org/document-library/hid-sensor-usages>
//! - **HID Usage Tables 1.4** — base usage-page mechanism.
//!   <https://usb.org/document-library/hid-usage-tables-14>
//! - **HID 1.11 §6.2.2** — descriptor parsing (already in
//!   [`crate::descriptor`]).
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Profile probe + Input-report decoder for the sensor types every
//! laptop / phone / tablet exposes through HID Sensor Collections:
//!
//! - 3-axis Accelerometer (Sensor Type 0x73)
//! - 3-axis Gyrometer (Sensor Type 0x76)
//! - 3-axis Magnetometer / Compass (Sensor Type 0x83)
//! - Ambient Light (Sensor Type 0x41)
//!
//! Other sensor types (pressure, temperature, humidity, presence,
//! heart-rate) reuse the same descriptor mechanism — their decoders
//! plug in once a consumer cares.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::descriptor::{Field, FieldKind, ReportDescriptor};
use crate::report::{extract, ReportError};

/// HID Sensors page id (HID Usage Tables 1.4 §17).
pub const SENSORS_PAGE: u16 = 0x20;

/// Top-level Sensor Type usages identifying which sensor a
/// Collection describes. Listed values are the ones we decode;
/// the full spec carries dozens more.
pub mod sensor_type {
    /// 3D Accelerometer.
    pub const MOTION_ACCELEROMETER_3D: u16 = 0x0073;
    /// 3D Gyrometer (angular-velocity sensor).
    pub const MOTION_GYROMETER_3D: u16 = 0x0076;
    /// 3D Magnetometer / Compass.
    pub const ORIENTATION_COMPASS_3D: u16 = 0x0083;
    /// Ambient Light Sensor (illuminance in lux).
    pub const LIGHT_AMBIENT: u16 = 0x0041;
    /// Mechanical pressure (atmospheric).
    pub const MECHANICAL_PRESSURE: u16 = 0x0071;
}

/// Per-axis data field usages (page 0x20).
pub mod data {
    pub const ACCELERATION_X: u16 = 0x0453;
    pub const ACCELERATION_Y: u16 = 0x0454;
    pub const ACCELERATION_Z: u16 = 0x0455;
    pub const ANGULAR_VELOCITY_X: u16 = 0x0457;
    pub const ANGULAR_VELOCITY_Y: u16 = 0x0458;
    pub const ANGULAR_VELOCITY_Z: u16 = 0x0459;
    pub const MAGNETIC_FLUX_X: u16 = 0x0485;
    pub const MAGNETIC_FLUX_Y: u16 = 0x0486;
    pub const MAGNETIC_FLUX_Z: u16 = 0x0487;
    pub const ILLUMINANCE_LUX: u16 = 0x04D1;
    pub const ATMOSPHERIC_PRESSURE: u16 = 0x04D5;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SensorKind {
    Accelerometer3D,
    Gyrometer3D,
    Compass3D,
    AmbientLight,
    Pressure,
}

impl SensorKind {
    fn from_top_level((page, usage): (u16, u16)) -> Option<Self> {
        if page != SENSORS_PAGE {
            return None;
        }
        Some(match usage {
            sensor_type::MOTION_ACCELEROMETER_3D => Self::Accelerometer3D,
            sensor_type::MOTION_GYROMETER_3D => Self::Gyrometer3D,
            sensor_type::ORIENTATION_COMPASS_3D => Self::Compass3D,
            sensor_type::LIGHT_AMBIENT => Self::AmbientLight,
            sensor_type::MECHANICAL_PRESSURE => Self::Pressure,
            _ => return None,
        })
    }
}

/// Probed sensor profile.
#[derive(Clone, Debug)]
pub struct SensorProfile {
    pub kind: SensorKind,
    pub input_report_id: u8,
    /// For 3-axis sensors (accelerometer / gyrometer / compass):
    /// `[x_field, y_field, z_field]`. For single-value sensors
    /// (ambient light, pressure): `[value]`.
    pub axes: Vec<Field>,
}

fn pick_axis_field(d: &ReportDescriptor, usage: u16) -> Option<Field> {
    d.fields
        .iter()
        .find(|f| {
            f.kind == FieldKind::Input
                && f.usages.iter().any(|u| u.0 == SENSORS_PAGE && u.1 == usage)
        })
        .cloned()
}

/// Probe a parsed descriptor. Returns the first sensor collection
/// whose top-level Application Collection is one we recognise +
/// the field set required to decode runtime reports.
pub fn detect(d: &ReportDescriptor) -> Option<SensorProfile> {
    for tl in &d.top_level_apps {
        let kind = match SensorKind::from_top_level(*tl) {
            Some(k) => k,
            None => continue,
        };
        let axes: Option<Vec<Field>> = match kind {
            SensorKind::Accelerometer3D => Some(vec![
                pick_axis_field(d, data::ACCELERATION_X)?,
                pick_axis_field(d, data::ACCELERATION_Y)?,
                pick_axis_field(d, data::ACCELERATION_Z)?,
            ]),
            SensorKind::Gyrometer3D => Some(vec![
                pick_axis_field(d, data::ANGULAR_VELOCITY_X)?,
                pick_axis_field(d, data::ANGULAR_VELOCITY_Y)?,
                pick_axis_field(d, data::ANGULAR_VELOCITY_Z)?,
            ]),
            SensorKind::Compass3D => Some(vec![
                pick_axis_field(d, data::MAGNETIC_FLUX_X)?,
                pick_axis_field(d, data::MAGNETIC_FLUX_Y)?,
                pick_axis_field(d, data::MAGNETIC_FLUX_Z)?,
            ]),
            SensorKind::AmbientLight => Some(vec![pick_axis_field(d, data::ILLUMINANCE_LUX)?]),
            SensorKind::Pressure => Some(vec![pick_axis_field(d, data::ATMOSPHERIC_PRESSURE)?]),
        };
        let axes = axes?;
        let input_report_id = axes[0].report_id;
        return Some(SensorProfile {
            kind,
            input_report_id,
            axes,
        });
    }
    None
}

/// Decoded sensor reading. Vec ordering matches `SensorProfile::axes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedSensor {
    pub kind: SensorKind,
    pub values: Vec<i32>,
}

/// Decode an Input report.
pub fn decode_input(p: &SensorProfile, report: &[u8]) -> Result<DecodedSensor, ReportError> {
    if report.is_empty() || report[0] != p.input_report_id {
        return Err(ReportError::Short);
    }
    let body = &report[1..];
    let mut values = Vec::with_capacity(p.axes.len());
    for f in &p.axes {
        let v = extract(f, body)?;
        values.push(v.first().copied().unwrap_or(0));
    }
    Ok(DecodedSensor {
        kind: p.kind,
        values,
    })
}
