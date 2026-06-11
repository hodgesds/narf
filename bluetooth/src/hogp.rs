//! HID over GATT Profile (HOGP) — clean-room.
//!
//! Spec sources (public-only):
//! - HID over GATT Profile Specification v1.0 (Bluetooth SIG).
//! - HID Service Specification v1.0 (Bluetooth SIG, Service UUID 0x1812).
//! - Bluetooth Assigned Numbers — Characteristic UUIDs.
//! - USB-IF HID 1.11 (Report Descriptor format reused over BLE; only
//!   the byte layout is referenced).
//!
//! No GPL Linux source consulted.
//!
//! ## Service shape (HID Service v1.0 §3)
//!
//! Mandatory:
//! - HID Information         (0x2A4A) — read
//! - Report Map              (0x2A4B) — read
//! - HID Control Point       (0x2A4C) — write-without-response
//! - One or more Report      (0x2A4D) — read/write/notify, with a
//!   Report Reference descriptor (0x2908) giving (id, type).
//!
//! Optional (boot host fallback):
//! - Protocol Mode           (0x2A4E) — read + write-without-response
//! - Boot Keyboard Input Report  (0x2A22) — read + notify
//! - Boot Keyboard Output Report (0x2A32) — read + write/wwr
//! - Boot Mouse Input Report     (0x2A33) — read + notify
//!
//! Each input Report exposes a CCCD (0x2902) so the host can enable
//! notifications.
//!
//! This module does not own a GATT server; it builds the attribute
//! layout into an `AttributeDatabase` that the caller provides.

use alloc::vec::Vec;

use crate::gatt::{
    Uuid, CHAR_PROP_NOTIFY, CHAR_PROP_READ, CHAR_PROP_WRITE, CHAR_PROP_WRITE_WITHOUT_RESPONSE,
    UUID_CCC_DESCRIPTOR, UUID_SERVICE_HID,
};
use crate::gatt_server::{AttributeDatabase, Permissions};

// ── Characteristic UUIDs (Assigned Numbers) ────────────────────────

pub const UUID_BOOT_KEYBOARD_INPUT_REPORT: u16 = 0x2A22;
pub const UUID_BOOT_KEYBOARD_OUTPUT_REPORT: u16 = 0x2A32;
pub const UUID_BOOT_MOUSE_INPUT_REPORT: u16 = 0x2A33;
pub const UUID_HID_INFORMATION: u16 = 0x2A4A;
pub const UUID_REPORT_MAP: u16 = 0x2A4B;
pub const UUID_HID_CONTROL_POINT: u16 = 0x2A4C;
pub const UUID_REPORT: u16 = 0x2A4D;
pub const UUID_PROTOCOL_MODE: u16 = 0x2A4E;
pub const UUID_REPORT_REFERENCE: u16 = 0x2908;

// HID Information flags (HID Service v1.0 §3.1).
pub const HID_INFO_FLAG_REMOTE_WAKE: u8 = 1 << 0;
pub const HID_INFO_FLAG_NORMALLY_CONNECTABLE: u8 = 1 << 1;

// Protocol Mode (HID Service v1.0 §3.4).
pub const PROTOCOL_MODE_BOOT: u8 = 0x00;
pub const PROTOCOL_MODE_REPORT: u8 = 0x01;

// HID Control Point commands (HID Service v1.0 §3.6).
pub const HID_CTRL_SUSPEND: u8 = 0x00;
pub const HID_CTRL_EXIT_SUSPEND: u8 = 0x01;

/// Report Reference Descriptor "Report Type" enum (§3.7.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReportType {
    Input = 0x01,
    Output = 0x02,
    Feature = 0x03,
}

/// HID Information characteristic value (§3.1, 4 bytes LE).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HidInformation {
    /// USB-HID bcd version (e.g. 0x0111 for HID 1.11).
    pub bcd_hid: u16,
    /// HID country code (0 = not localised).
    pub country_code: u8,
    /// Bitmap of `HID_INFO_FLAG_*`.
    pub flags: u8,
}

impl HidInformation {
    pub fn encode(self) -> [u8; 4] {
        [
            (self.bcd_hid & 0xFF) as u8,
            (self.bcd_hid >> 8) as u8,
            self.country_code,
            self.flags,
        ]
    }

    pub fn decode(buf: &[u8; 4]) -> Self {
        Self {
            bcd_hid: u16::from_le_bytes([buf[0], buf[1]]),
            country_code: buf[2],
            flags: buf[3],
        }
    }
}

/// Report Reference Descriptor value — 2 bytes (id, type).
pub fn report_reference(report_id: u8, report_type: ReportType) -> [u8; 2] {
    [report_id, report_type as u8]
}

/// One Report characteristic the service should expose.
#[derive(Clone, Debug)]
pub struct ReportEntry {
    pub report_id: u8,
    pub report_type: ReportType,
    /// Characteristic property bits — typically NOTIFY|READ for input,
    /// WRITE|WRITE_WITHOUT_RESPONSE for output, READ|WRITE for feature.
    pub properties: u8,
    pub initial_value: Vec<u8>,
}

/// Handles returned for one Report after building.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReportHandles {
    pub declaration: u16,
    pub value: u16,
    pub report_reference: u16,
    /// CCCD handle if NOTIFY/INDICATE was requested, else None.
    pub cccd: Option<u16>,
}

/// Top-level handles returned after building the HID Service.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HidServiceHandles {
    pub service: u16,
    pub hid_information_value: u16,
    pub report_map_value: u16,
    pub control_point_value: u16,
    pub protocol_mode_value: Option<u16>,
    pub boot_keyboard_input_value: Option<u16>,
    pub boot_keyboard_output_value: Option<u16>,
    pub boot_mouse_input_value: Option<u16>,
    pub reports: Vec<ReportHandles>,
}

/// Builder for the HID Service — composes the standard layout into an
/// `AttributeDatabase`.
#[derive(Clone, Debug)]
pub struct HidServiceBuilder {
    info: HidInformation,
    report_map: Vec<u8>,
    reports: Vec<ReportEntry>,
    boot_keyboard: bool,
    boot_mouse: bool,
    expose_protocol_mode: bool,
}

impl HidServiceBuilder {
    pub fn new(info: HidInformation, report_map: Vec<u8>) -> Self {
        Self {
            info,
            report_map,
            reports: Vec::new(),
            boot_keyboard: false,
            boot_mouse: false,
            expose_protocol_mode: false,
        }
    }

    pub fn add_report(mut self, entry: ReportEntry) -> Self {
        self.reports.push(entry);
        self
    }

    pub fn with_boot_keyboard(mut self) -> Self {
        self.boot_keyboard = true;
        self.expose_protocol_mode = true;
        self
    }

    pub fn with_boot_mouse(mut self) -> Self {
        self.boot_mouse = true;
        self.expose_protocol_mode = true;
        self
    }

    pub fn with_protocol_mode(mut self) -> Self {
        self.expose_protocol_mode = true;
        self
    }

    /// Materialise the service into the database; returns the handles.
    pub fn build(self, db: &mut AttributeDatabase) -> HidServiceHandles {
        let mut handles = HidServiceHandles {
            service: db.add_primary_service(Uuid::U16(UUID_SERVICE_HID)),
            ..Default::default()
        };

        // HID Information — read-only.
        let (_, info_h) = db.add_characteristic(
            Uuid::U16(UUID_HID_INFORMATION),
            CHAR_PROP_READ,
            Permissions::read(),
            self.info.encode().to_vec(),
        );
        handles.hid_information_value = info_h;

        // Report Map — read-only blob.
        let (_, map_h) = db.add_characteristic(
            Uuid::U16(UUID_REPORT_MAP),
            CHAR_PROP_READ,
            Permissions::read(),
            self.report_map,
        );
        handles.report_map_value = map_h;

        // HID Control Point — write-without-response.
        let (_, cp_h) = db.add_characteristic(
            Uuid::U16(UUID_HID_CONTROL_POINT),
            CHAR_PROP_WRITE_WITHOUT_RESPONSE,
            Permissions {
                readable: false,
                writable: true,
                requires_auth: false,
                requires_encryption: false,
            },
            Vec::new(),
        );
        handles.control_point_value = cp_h;

        if self.expose_protocol_mode {
            let (_, pm_h) = db.add_characteristic(
                Uuid::U16(UUID_PROTOCOL_MODE),
                CHAR_PROP_READ | CHAR_PROP_WRITE_WITHOUT_RESPONSE,
                Permissions::read_write(),
                alloc::vec![PROTOCOL_MODE_REPORT],
            );
            handles.protocol_mode_value = Some(pm_h);
        }

        if self.boot_keyboard {
            let (_, in_h) = db.add_characteristic(
                Uuid::U16(UUID_BOOT_KEYBOARD_INPUT_REPORT),
                CHAR_PROP_READ | CHAR_PROP_NOTIFY,
                Permissions::read(),
                Vec::new(),
            );
            // CCCD for the input report.
            db.insert(
                Uuid::U16(UUID_CCC_DESCRIPTOR),
                Permissions::read_write(),
                alloc::vec![0, 0],
            );
            handles.boot_keyboard_input_value = Some(in_h);

            let (_, out_h) = db.add_characteristic(
                Uuid::U16(UUID_BOOT_KEYBOARD_OUTPUT_REPORT),
                CHAR_PROP_READ | CHAR_PROP_WRITE | CHAR_PROP_WRITE_WITHOUT_RESPONSE,
                Permissions::read_write(),
                Vec::new(),
            );
            handles.boot_keyboard_output_value = Some(out_h);
        }

        if self.boot_mouse {
            let (_, in_h) = db.add_characteristic(
                Uuid::U16(UUID_BOOT_MOUSE_INPUT_REPORT),
                CHAR_PROP_READ | CHAR_PROP_NOTIFY,
                Permissions::read(),
                Vec::new(),
            );
            db.insert(
                Uuid::U16(UUID_CCC_DESCRIPTOR),
                Permissions::read_write(),
                alloc::vec![0, 0],
            );
            handles.boot_mouse_input_value = Some(in_h);
        }

        for entry in self.reports {
            let needs_cccd = (entry.properties & CHAR_PROP_NOTIFY) != 0;
            let perms =
                if (entry.properties & (CHAR_PROP_WRITE | CHAR_PROP_WRITE_WITHOUT_RESPONSE)) != 0 {
                    Permissions::read_write()
                } else {
                    Permissions::read()
                };
            let (decl, value) = db.add_characteristic(
                Uuid::U16(UUID_REPORT),
                entry.properties,
                perms,
                entry.initial_value,
            );
            // Report Reference descriptor — read-only.
            let rr = db.insert(
                Uuid::U16(UUID_REPORT_REFERENCE),
                Permissions::read(),
                report_reference(entry.report_id, entry.report_type).to_vec(),
            );
            let cccd = if needs_cccd {
                Some(db.insert(
                    Uuid::U16(UUID_CCC_DESCRIPTOR),
                    Permissions::read_write(),
                    alloc::vec![0, 0],
                ))
            } else {
                None
            };
            handles.reports.push(ReportHandles {
                declaration: decl,
                value,
                report_reference: rr,
                cccd,
            });
        }

        handles
    }
}

/// Standard 8-byte HID Boot Keyboard input report layout (HID 1.11
/// boot protocol §B.1):
///
/// ```text
///   byte 0   modifiers bitmap (LCtrl, LShift, LAlt, LGUI, RCtrl, RShift, RAlt, RGUI)
///   byte 1   reserved (0)
///   bytes 2..8  six pressed keycodes (HID Usage Page 0x07), 0 = empty
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BootKeyboardReport {
    pub modifiers: u8,
    pub keycodes: [u8; 6],
}

impl BootKeyboardReport {
    pub fn encode(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = self.modifiers;
        // out[1] reserved
        out[2..8].copy_from_slice(&self.keycodes);
        out
    }

    pub fn decode(buf: &[u8; 8]) -> Self {
        let mut keycodes = [0u8; 6];
        keycodes.copy_from_slice(&buf[2..8]);
        Self {
            modifiers: buf[0],
            keycodes,
        }
    }
}

/// Standard 3-byte HID Boot Mouse input report (HID 1.11 §B.2):
///
/// ```text
///   byte 0   buttons bitmap (B1=left, B2=right, B3=middle)
///   byte 1   X displacement (signed)
///   byte 2   Y displacement (signed)
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BootMouseReport {
    pub buttons: u8,
    pub dx: i8,
    pub dy: i8,
}

impl BootMouseReport {
    pub fn encode(self) -> [u8; 3] {
        [self.buttons, self.dx as u8, self.dy as u8]
    }

    pub fn decode(buf: &[u8; 3]) -> Self {
        Self {
            buttons: buf[0],
            dx: buf[1] as i8,
            dy: buf[2] as i8,
        }
    }
}
