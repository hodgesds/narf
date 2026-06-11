//! Well-known GATT service builders (clean-room).
//!
//! Sources (public-only):
//! - Bluetooth Assigned Numbers — Service / Characteristic UUIDs and
//!   the Characteristic Presentation Format table.
//! - GATT Specification Supplement (GSS) — characteristic value
//!   layouts for the SIG-defined characteristics referenced below.
//! - Battery Service v1.1, Device Information Service v1.1,
//!   Heart Rate Service v1.0, HID Service v1.0, GAP Service per
//!   Core spec Vol 3 Part C §12.
//!
//! These helpers turn `(name, manufacturer, …)` tuples into the
//! attribute records the [`crate::gatt_server::AttributeDatabase`]
//! understands. They never own a server — the caller picks which
//! services to mount.
//!
//! No GPL Linux source consulted.

use alloc::vec::Vec;

use crate::gatt::{
    Uuid, CHAR_PROP_NOTIFY, CHAR_PROP_READ, CHAR_PROP_WRITE, UUID_CCC_DESCRIPTOR,
    UUID_SERVICE_BATTERY, UUID_SERVICE_DEVICE_INFORMATION, UUID_SERVICE_GAP, UUID_SERVICE_GATT,
};
use crate::gatt_server::{AttributeDatabase, Permissions};

// ── GAP service characteristics (Vol 3 Part C §12) ─────────────────

/// Device Name (Vol 3 Part C §12.1, Assigned Numbers 0x2A00).
pub const UUID_DEVICE_NAME: u16 = 0x2A00;
/// Appearance (Vol 3 Part C §12.2, Assigned Numbers 0x2A01).
pub const UUID_APPEARANCE: u16 = 0x2A01;
/// Peripheral Preferred Connection Parameters
/// (Vol 3 Part C §12.3, Assigned Numbers 0x2A04).
pub const UUID_PPCP: u16 = 0x2A04;
/// Central Address Resolution (Vol 3 Part C §12.5, 0x2AA6).
pub const UUID_CENTRAL_ADDRESS_RESOLUTION: u16 = 0x2AA6;

// ── Device Information service characteristics (DIS v1.1) ──────────

pub const UUID_MANUFACTURER_NAME_STRING: u16 = 0x2A29;
pub const UUID_MODEL_NUMBER_STRING: u16 = 0x2A24;
pub const UUID_SERIAL_NUMBER_STRING: u16 = 0x2A25;
pub const UUID_HARDWARE_REVISION_STRING: u16 = 0x2A27;
pub const UUID_FIRMWARE_REVISION_STRING: u16 = 0x2A26;
pub const UUID_SOFTWARE_REVISION_STRING: u16 = 0x2A28;
pub const UUID_SYSTEM_ID: u16 = 0x2A23;
pub const UUID_PNP_ID: u16 = 0x2A50;

// ── Battery Service characteristics (BAS v1.1) ─────────────────────

/// Battery Level (BAS §3, Assigned Numbers 0x2A19). 1 byte, 0..=100 %.
pub const UUID_BATTERY_LEVEL: u16 = 0x2A19;

// ── Heart Rate Service (HRS v1.0) ──────────────────────────────────

pub const UUID_SERVICE_HEART_RATE: u16 = 0x180D;
pub const UUID_HEART_RATE_MEASUREMENT: u16 = 0x2A37;
pub const UUID_BODY_SENSOR_LOCATION: u16 = 0x2A38;
pub const UUID_HEART_RATE_CONTROL_POINT: u16 = 0x2A39;

// ── GAP service ─────────────────────────────────────────────────────

/// Appearance category bits — Assigned Numbers (table 1.0).
/// Returned by the Appearance characteristic; subset.
pub const APPEARANCE_UNKNOWN: u16 = 0x0000;
pub const APPEARANCE_GENERIC_PHONE: u16 = 0x0040;
pub const APPEARANCE_GENERIC_COMPUTER: u16 = 0x0080;
pub const APPEARANCE_GENERIC_HID: u16 = 0x03C0;
pub const APPEARANCE_KEYBOARD: u16 = 0x03C1;
pub const APPEARANCE_MOUSE: u16 = 0x03C2;
pub const APPEARANCE_GAMEPAD: u16 = 0x03C4;
pub const APPEARANCE_GENERIC_HEART_RATE_SENSOR: u16 = 0x0340;

/// Mount the mandatory GAP service (UUID 0x1800) into the supplied
/// database. Includes Device Name + Appearance. Returns the service
/// declaration handle.
pub fn mount_gap_service(db: &mut AttributeDatabase, device_name: &str, appearance: u16) -> u16 {
    let svc_handle = db.add_primary_service(Uuid::U16(UUID_SERVICE_GAP));
    db.add_characteristic(
        Uuid::U16(UUID_DEVICE_NAME),
        CHAR_PROP_READ,
        Permissions::read(),
        device_name.as_bytes().to_vec(),
    );
    db.add_characteristic(
        Uuid::U16(UUID_APPEARANCE),
        CHAR_PROP_READ,
        Permissions::read(),
        appearance.to_le_bytes().to_vec(),
    );
    svc_handle
}

/// Mount the mandatory GATT service (UUID 0x1801). Currently empty —
/// the optional Service Changed indication characteristic lives
/// behind a feature flag we don't expose yet.
pub fn mount_gatt_service(db: &mut AttributeDatabase) -> u16 {
    db.add_primary_service(Uuid::U16(UUID_SERVICE_GATT))
}

/// Mount the Device Information Service. All characteristics are
/// optional per DIS v1.1 §3; only the ones provided as `Some(_)` are
/// added.
#[derive(Debug, Default)]
pub struct DeviceInformation<'a> {
    pub manufacturer: Option<&'a str>,
    pub model: Option<&'a str>,
    pub serial: Option<&'a str>,
    pub hardware_revision: Option<&'a str>,
    pub firmware_revision: Option<&'a str>,
    pub software_revision: Option<&'a str>,
    /// 8-byte System ID per DIS v1.1 §3.7.
    pub system_id: Option<[u8; 8]>,
    /// PnP ID per DIS v1.1 §3.9: VendorIDSource(1) + VendorID(2 LE) +
    /// ProductID(2 LE) + ProductVersion(2 LE).
    pub pnp_id: Option<[u8; 7]>,
}

pub fn mount_device_information_service(
    db: &mut AttributeDatabase,
    info: &DeviceInformation<'_>,
) -> u16 {
    let svc_handle = db.add_primary_service(Uuid::U16(UUID_SERVICE_DEVICE_INFORMATION));
    if let Some(s) = info.manufacturer {
        db.add_characteristic(
            Uuid::U16(UUID_MANUFACTURER_NAME_STRING),
            CHAR_PROP_READ,
            Permissions::read(),
            s.as_bytes().to_vec(),
        );
    }
    if let Some(s) = info.model {
        db.add_characteristic(
            Uuid::U16(UUID_MODEL_NUMBER_STRING),
            CHAR_PROP_READ,
            Permissions::read(),
            s.as_bytes().to_vec(),
        );
    }
    if let Some(s) = info.serial {
        db.add_characteristic(
            Uuid::U16(UUID_SERIAL_NUMBER_STRING),
            CHAR_PROP_READ,
            Permissions::read(),
            s.as_bytes().to_vec(),
        );
    }
    if let Some(s) = info.hardware_revision {
        db.add_characteristic(
            Uuid::U16(UUID_HARDWARE_REVISION_STRING),
            CHAR_PROP_READ,
            Permissions::read(),
            s.as_bytes().to_vec(),
        );
    }
    if let Some(s) = info.firmware_revision {
        db.add_characteristic(
            Uuid::U16(UUID_FIRMWARE_REVISION_STRING),
            CHAR_PROP_READ,
            Permissions::read(),
            s.as_bytes().to_vec(),
        );
    }
    if let Some(s) = info.software_revision {
        db.add_characteristic(
            Uuid::U16(UUID_SOFTWARE_REVISION_STRING),
            CHAR_PROP_READ,
            Permissions::read(),
            s.as_bytes().to_vec(),
        );
    }
    if let Some(id) = info.system_id {
        db.add_characteristic(
            Uuid::U16(UUID_SYSTEM_ID),
            CHAR_PROP_READ,
            Permissions::read(),
            id.to_vec(),
        );
    }
    if let Some(p) = info.pnp_id {
        db.add_characteristic(
            Uuid::U16(UUID_PNP_ID),
            CHAR_PROP_READ,
            Permissions::read(),
            p.to_vec(),
        );
    }
    svc_handle
}

// ── Battery Service ────────────────────────────────────────────────

/// Mount the Battery Service (BAS v1.1). The Battery Level
/// characteristic supports READ + NOTIFY per BAS v1.1 §3.1; a CCCD
/// follows so the host can subscribe.
///
/// Returns `(service_handle, level_value_handle, cccd_handle)`.
pub fn mount_battery_service(db: &mut AttributeDatabase, initial_level: u8) -> (u16, u16, u16) {
    let svc_handle = db.add_primary_service(Uuid::U16(UUID_SERVICE_BATTERY));
    let (_decl, level_handle) = db.add_characteristic(
        Uuid::U16(UUID_BATTERY_LEVEL),
        CHAR_PROP_READ | CHAR_PROP_NOTIFY,
        Permissions::read(),
        alloc::vec![initial_level.min(100)],
    );
    let cccd_handle = db.insert(
        Uuid::U16(UUID_CCC_DESCRIPTOR),
        Permissions::read_write(),
        alloc::vec![0x00, 0x00],
    );
    (svc_handle, level_handle, cccd_handle)
}

// ── Heart Rate Service ─────────────────────────────────────────────

/// Body Sensor Location values (HRS v1.0 §3.3).
pub const BODY_LOCATION_OTHER: u8 = 0x00;
pub const BODY_LOCATION_CHEST: u8 = 0x01;
pub const BODY_LOCATION_WRIST: u8 = 0x02;
pub const BODY_LOCATION_FINGER: u8 = 0x03;
pub const BODY_LOCATION_HAND: u8 = 0x04;
pub const BODY_LOCATION_EAR_LOBE: u8 = 0x05;
pub const BODY_LOCATION_FOOT: u8 = 0x06;

/// Mount the Heart Rate Service (HRS v1.0). Includes the mandatory
/// Heart Rate Measurement (notify) + optional Body Sensor Location
/// (read) + optional Heart Rate Control Point (write).
///
/// Returns `(service_handle, measurement_value_handle, cccd_handle)`.
pub fn mount_heart_rate_service(
    db: &mut AttributeDatabase,
    sensor_location: u8,
) -> (u16, u16, u16) {
    let svc_handle = db.add_primary_service(Uuid::U16(UUID_SERVICE_HEART_RATE));
    let (_decl, meas_handle) = db.add_characteristic(
        Uuid::U16(UUID_HEART_RATE_MEASUREMENT),
        CHAR_PROP_NOTIFY,
        Permissions::read(),
        Vec::new(),
    );
    let cccd_handle = db.insert(
        Uuid::U16(UUID_CCC_DESCRIPTOR),
        Permissions::read_write(),
        alloc::vec![0x00, 0x00],
    );
    db.add_characteristic(
        Uuid::U16(UUID_BODY_SENSOR_LOCATION),
        CHAR_PROP_READ,
        Permissions::read(),
        alloc::vec![sensor_location],
    );
    db.add_characteristic(
        Uuid::U16(UUID_HEART_RATE_CONTROL_POINT),
        CHAR_PROP_WRITE,
        Permissions::read_write(),
        Vec::new(),
    );
    (svc_handle, meas_handle, cccd_handle)
}

/// Build the Heart Rate Measurement characteristic value (HRS §3.1).
/// Flags byte: bit0 = 16-bit measurement (1) vs 8-bit (0); other
/// bits cover energy expended + RR-interval optional fields.
pub fn heart_rate_measurement_8bit(bpm: u8) -> Vec<u8> {
    let flags: u8 = 0x00; // 8-bit format, no extra fields.
    alloc::vec![flags, bpm]
}

/// 16-bit variant for high-rate measurements (> 255 bpm — rare but
/// HRS allows it).
pub fn heart_rate_measurement_16bit(bpm: u16) -> Vec<u8> {
    let flags: u8 = 0x01; // 16-bit format.
    let mut out = Vec::with_capacity(3);
    out.push(flags);
    out.extend_from_slice(&bpm.to_le_bytes());
    out
}

// ── CCCD bit definitions (Vol 3 Part G §3.3.3.3) ──────────────────

pub const CCCD_NOTIFICATIONS: u16 = 1 << 0;
pub const CCCD_INDICATIONS: u16 = 1 << 1;

/// Read a CCCD value and decode the subscription state.
pub fn cccd_value(notifications: bool, indications: bool) -> [u8; 2] {
    let mut v: u16 = 0;
    if notifications {
        v |= CCCD_NOTIFICATIONS;
    }
    if indications {
        v |= CCCD_INDICATIONS;
    }
    v.to_le_bytes()
}
