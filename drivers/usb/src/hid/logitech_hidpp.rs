//! Logitech HID++ protocol — clean-room.
//!
//! ## References
//!
//! - `drivers/hid/hid-logitech-hidpp.c` (Linux, GPL-2.0-or-later) —
//!   protocol versioning, FAP/RAP framing, feature-index discovery,
//!   battery / wireless-status / reprogramable-controls feature
//!   handlers.
//! - Logitech HID++ 2.0 spec public reference — Solaar project's
//!   `lib/logitech_receiver/hidpp20.py` mirrors the same protocol
//!   layout publicly.
//!
//! ## Shape
//!
//! HID++ is a vendor-defined RPC layer carried on top of HID. Every
//! Logitech wireless device (mice, keyboards, presenters) running
//! firmware later than ~2010 speaks HID++ 2.0; older devices speak
//! HID++ 1.0 (register-based). NARF targets HID++ 2.0 only — that's
//! every MX-series, K-series, G-series device sold since 2013.
//!
//! Two wire formats:
//!
//! ```text
//!   short  (7 bytes):  0x10 idx subid p0 p1 p2 p3
//!   long  (20 bytes):  0x11 idx subid p0..p16
//! ```
//!
//! `idx` is the receiver-side device index (1..7 for a paired sub-
//! device behind a Unifying receiver; 0xFF for a direct USB / BT
//! attached HID++ device). `subid` is the feature index *after*
//! feature-index discovery; before discovery it's the literal
//! command byte (e.g. `0x10` = GET_PROTOCOL_VERSION on page 0x0000).
//!
//! ## Feature-index resolution
//!
//! HID++ 2.0 organises device functionality into "features" identified
//! by a 16-bit Feature ID (e.g. `0x1000` = Battery Level Status,
//! `0x1D4B` = Wireless Device Status). Before invoking a feature the
//! host calls `Root.GetFeature(featureId)` (page 0x0000, command 0x00)
//! and the device returns a 1-byte index. Subsequent calls address
//! the feature by index instead of ID, which keeps every protocol
//! frame within the 7- or 20-byte limit.

#![allow(dead_code)]

// ── Report IDs + lengths (mirrors hid-logitech-hidpp.c:48,49) ──────

/// HID++ short report — 7 bytes on the wire including the report ID.
pub const HIDPP_REPORT_SHORT_LENGTH: usize = 7;
/// HID++ long report — 20 bytes on the wire including the report ID.
pub const HIDPP_REPORT_LONG_LENGTH: usize = 20;

pub const REPORT_ID_HIDPP_SHORT: u8 = 0x10;
pub const REPORT_ID_HIDPP_LONG: u8 = 0x11;
pub const REPORT_ID_HIDPP_VERY_LONG: u8 = 0x12;

/// `supported_reports` bitmask values (`hid-logitech-hidpp.c:52..53`).
pub const HIDPP_REPORT_SHORT_SUPPORTED: u8 = 1 << 0;
pub const HIDPP_REPORT_LONG_SUPPORTED: u8 = 1 << 1;

/// Receiver-side device index for a direct (USB / BT) HID++ device.
pub const HIDPP_RECEIVER_INDEX: u8 = 0xFF;

/// Software-id nibble OR'ed into command bytes. Linux uses 0x08
/// (kernel) — we follow.
pub const HIDPP_SW_ID: u8 = 0x08;

// ── Feature IDs (16-bit, used with Root.GetFeature) ────────────────

/// Root feature — Feature 0x0000. Used for feature-index discovery +
/// protocol version ping.
pub const HIDPP_PAGE_ROOT: u16 = 0x0000;
/// Root feature is always at index 0.
pub const HIDPP_PAGE_ROOT_IDX: u8 = 0x00;

/// Battery Level Status feature.
pub const HIDPP_PAGE_BATTERY_LEVEL_STATUS: u16 = 0x1000;
/// Battery Voltage feature (rechargeable devices).
pub const HIDPP_PAGE_BATTERY_VOLTAGE: u16 = 0x1001;
/// Unified Battery feature.
pub const HIDPP_PAGE_UNIFIED_BATTERY: u16 = 0x1004;
/// Wireless Device Status feature — emits a notification whenever
/// the link wakes up; used as the trigger for re-querying battery.
pub const HIDPP_PAGE_WIRELESS_DEVICE_STATUS: u16 = 0x1D4B;
/// Reprogramable Controls feature (V4). Carries the table of
/// programmable buttons / scroll modes.
pub const HIDPP_PAGE_REPROG_CONTROLS_V4: u16 = 0x1B04;
/// Device Information feature — name + type + serial.
pub const HIDPP_PAGE_DEVICE_INFO: u16 = 0x0003;
/// Get Device Name + Type feature.
pub const HIDPP_PAGE_GET_DEVICE_NAME_TYPE: u16 = 0x0005;

// ── Root commands (page 0x0000) ────────────────────────────────────

/// Sub-command — discover the index of a feature.
pub const CMD_ROOT_GET_FEATURE: u8 = 0x00;
/// Sub-command — ping the device + read its protocol version.
pub const CMD_ROOT_GET_PROTOCOL_VERSION: u8 = 0x10;

// ── Battery feature commands (page 0x1000) ─────────────────────────

pub const CMD_BATTERY_LEVEL_STATUS_GET_BATTERY_LEVEL_STATUS: u8 = 0x00;
pub const CMD_BATTERY_LEVEL_STATUS_GET_BATTERY_CAPABILITY: u8 = 0x10;

/// Battery capability flags from `hid-logitech-hidpp.c:1181..1183`.
pub const FLAG_BATTERY_LEVEL_DISABLE_OSD: u8 = 1 << 0;
pub const FLAG_BATTERY_LEVEL_MILEAGE: u8 = 1 << 1;
pub const FLAG_BATTERY_LEVEL_RECHARGEABLE: u8 = 1 << 2;

/// Per-spec battery charging states (`data[2]` in the level status
/// response).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BatteryStatus {
    Discharging = 0,
    Charging = 1,
    ChargingFinalStage = 2,
    ChargeComplete = 3,
    ChargingSlow = 4,
    InvalidBatteryType = 5,
    ThermalError = 6,
    OtherChargingError = 7,
}

impl BatteryStatus {
    /// Decode the raw status byte from the GET_BATTERY_LEVEL_STATUS
    /// response. Returns `Discharging` for unknown values to match
    /// Linux's default-case behaviour.
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => BatteryStatus::Discharging,
            1 => BatteryStatus::Charging,
            2 => BatteryStatus::ChargingFinalStage,
            3 => BatteryStatus::ChargeComplete,
            4 => BatteryStatus::ChargingSlow,
            5 => BatteryStatus::InvalidBatteryType,
            6 => BatteryStatus::ThermalError,
            7 => BatteryStatus::OtherChargingError,
            _ => BatteryStatus::Discharging,
        }
    }
}

// ── Encode helpers ────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HidppError {
    BufferTooSmall,
    PayloadTooLong,
    ShortReport,
    NotHidppReport,
}

/// Encode a HID++ short FAP (Feature Access Protocol) command.
///
/// FAP framing per `hid-logitech-hidpp.c:240`:
///
/// ```text
///   byte 0 : 0x10 (short) or 0x11 (long)
///   byte 1 : device_index (1..7 behind a receiver, 0xFF direct)
///   byte 2 : feature_index (after Root.GetFeature)
///   byte 3 : sub-command | software-id nibble (low 4 bits)
///   byte 4..: params, padded with zeros
/// ```
pub fn encode_short_fap(
    out: &mut [u8],
    device_index: u8,
    feature_index: u8,
    sub_command: u8,
    params: &[u8],
) -> Result<usize, HidppError> {
    if out.len() < HIDPP_REPORT_SHORT_LENGTH {
        return Err(HidppError::BufferTooSmall);
    }
    if params.len() > HIDPP_REPORT_SHORT_LENGTH - 4 {
        return Err(HidppError::PayloadTooLong);
    }
    out[..HIDPP_REPORT_SHORT_LENGTH].fill(0);
    out[0] = REPORT_ID_HIDPP_SHORT;
    out[1] = device_index;
    out[2] = feature_index;
    out[3] = (sub_command & 0xF0) | (HIDPP_SW_ID & 0x0F);
    out[4..4 + params.len()].copy_from_slice(params);
    Ok(HIDPP_REPORT_SHORT_LENGTH)
}

/// Encode a HID++ long FAP command. Same shape as the short form but
/// 20 bytes total, 16 bytes of parameters.
pub fn encode_long_fap(
    out: &mut [u8],
    device_index: u8,
    feature_index: u8,
    sub_command: u8,
    params: &[u8],
) -> Result<usize, HidppError> {
    if out.len() < HIDPP_REPORT_LONG_LENGTH {
        return Err(HidppError::BufferTooSmall);
    }
    if params.len() > HIDPP_REPORT_LONG_LENGTH - 4 {
        return Err(HidppError::PayloadTooLong);
    }
    out[..HIDPP_REPORT_LONG_LENGTH].fill(0);
    out[0] = REPORT_ID_HIDPP_LONG;
    out[1] = device_index;
    out[2] = feature_index;
    out[3] = (sub_command & 0xF0) | (HIDPP_SW_ID & 0x0F);
    out[4..4 + params.len()].copy_from_slice(params);
    Ok(HIDPP_REPORT_LONG_LENGTH)
}

/// Encode the Root.GetFeature(featureId) lookup. Uses the short form
/// since the response fits in 7 bytes. Mirrors
/// `hidpp_root_get_feature` at `hid-logitech-hidpp.c:937`.
pub fn encode_get_feature(
    out: &mut [u8],
    device_index: u8,
    feature_id: u16,
) -> Result<usize, HidppError> {
    let params = [(feature_id >> 8) as u8, (feature_id & 0xFF) as u8];
    encode_short_fap(
        out,
        device_index,
        HIDPP_PAGE_ROOT_IDX,
        CMD_ROOT_GET_FEATURE,
        &params,
    )
}

/// Encode the Root.GetProtocolVersion ping. Carries the ping byte
/// (0x5A by Linux convention) in params[2]; the device echoes it back
/// in the response so the host can match request to reply.
pub fn encode_ping(
    out: &mut [u8],
    device_index: u8,
    ping_byte: u8,
) -> Result<usize, HidppError> {
    let params = [0, 0, ping_byte];
    encode_short_fap(
        out,
        device_index,
        HIDPP_PAGE_ROOT_IDX,
        CMD_ROOT_GET_PROTOCOL_VERSION,
        &params,
    )
}

/// Encode the Battery.GetBatteryLevelStatus command (page 0x1000
/// command 0x00). Caller has already resolved the battery feature
/// to a feature index via `encode_get_feature`.
pub fn encode_battery_get_status(
    out: &mut [u8],
    device_index: u8,
    feature_index: u8,
) -> Result<usize, HidppError> {
    encode_short_fap(
        out,
        device_index,
        feature_index,
        CMD_BATTERY_LEVEL_STATUS_GET_BATTERY_LEVEL_STATUS,
        &[],
    )
}

// ── Decode helpers ────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HidppFrame<'a> {
    pub report_id: u8,
    pub device_index: u8,
    pub feature_index: u8,
    /// Sub-command byte with the software-id nibble intact.
    pub sub_command: u8,
    pub params: &'a [u8],
}

/// Parse a HID++ short or long frame. Discriminates by the leading
/// report ID byte and slices out the appropriate parameter length.
pub fn decode_frame(report: &[u8]) -> Result<HidppFrame<'_>, HidppError> {
    if report.is_empty() {
        return Err(HidppError::ShortReport);
    }
    let (expected_len, payload_start, payload_end) = match report[0] {
        REPORT_ID_HIDPP_SHORT => (HIDPP_REPORT_SHORT_LENGTH, 4, HIDPP_REPORT_SHORT_LENGTH),
        REPORT_ID_HIDPP_LONG => (HIDPP_REPORT_LONG_LENGTH, 4, HIDPP_REPORT_LONG_LENGTH),
        _ => return Err(HidppError::NotHidppReport),
    };
    if report.len() < expected_len {
        return Err(HidppError::ShortReport);
    }
    Ok(HidppFrame {
        report_id: report[0],
        device_index: report[1],
        feature_index: report[2],
        sub_command: report[3],
        params: &report[payload_start..payload_end],
    })
}

/// Decode the Root.GetFeature response. Returns the feature index
/// assigned to the requested feature, or `None` if the device
/// reports "feature not supported" (index = 0).
pub fn decode_get_feature_response(report: &[u8]) -> Result<Option<u8>, HidppError> {
    let f = decode_frame(report)?;
    if f.feature_index != HIDPP_PAGE_ROOT_IDX {
        // Mismatched feature; caller invoked decode on the wrong reply.
        return Err(HidppError::NotHidppReport);
    }
    if f.params.is_empty() {
        return Err(HidppError::ShortReport);
    }
    let idx = f.params[0];
    if idx == 0 {
        Ok(None)
    } else {
        Ok(Some(idx))
    }
}

/// Decoded Battery.GetBatteryLevelStatus response.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BatteryReport {
    /// Current capacity, 0..=100 (percent).
    pub capacity: u8,
    /// Next discharge level the device will report when crossing
    /// another threshold (0..=100). The mileage feature uses this to
    /// produce hysteresis-free transitions.
    pub next_capacity: u8,
    pub status: BatteryStatus,
}

/// Decode a Battery.GetBatteryLevelStatus reply payload. Caller is
/// responsible for matching `feature_index` against the value
/// previously returned by `decode_get_feature_response`.
///
/// Layout per `hidpp20_batterylevel_map_status_capacity` at
/// `hid-logitech-hidpp.c:1200`: params[0] = capacity, [1] =
/// next_capacity, [2] = status.
pub fn decode_battery_response(report: &[u8]) -> Result<BatteryReport, HidppError> {
    let f = decode_frame(report)?;
    if f.params.len() < 3 {
        return Err(HidppError::ShortReport);
    }
    Ok(BatteryReport {
        capacity: f.params[0],
        next_capacity: f.params[1],
        status: BatteryStatus::from_byte(f.params[2]),
    })
}

/// Convert a capacity percentage into the kernel power-supply level
/// (`POWER_SUPPLY_CAPACITY_LEVEL_*`). Mirrors `hidpp_map_battery_level`
/// at `hid-logitech-hidpp.c:1185`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerSupplyLevel {
    Unknown,
    Critical,
    Low,
    Normal,
    High,
    Full,
}

pub const fn map_battery_level(capacity: i32) -> PowerSupplyLevel {
    if capacity < 11 {
        PowerSupplyLevel::Critical
    } else if capacity < 30 {
        PowerSupplyLevel::Low
    } else if capacity < 81 {
        PowerSupplyLevel::Normal
    } else {
        PowerSupplyLevel::Full
    }
}

// ── Device claim table (HID++ devices) ────────────────────────────

/// Match a device by HID++-protocol-supported reports rather than
/// just VID/PID — every Logitech wireless device that supports both
/// short + long reports is a HID++ candidate, regardless of model.
/// The exact feature support is then probed via Root.GetFeature.
pub fn claims_device(supported_reports: u8) -> bool {
    (supported_reports & HIDPP_REPORT_SHORT_SUPPORTED) != 0
        && (supported_reports & HIDPP_REPORT_LONG_SUPPORTED) != 0
}

/// Known device-identity hints — used by the supervisor logger to
/// pretty-print pair notifications, not for binding.
pub const HIDPP_KNOWN_DEVICES: &[(&str, u16, u16)] = &[
    // (name, vid, pid_or_bluetooth_id)
    ("MX Master 3 Anywhere",  0x046d, 0x4082),
    ("MX Master 3S",          0x046d, 0xb034),
    ("MX Keys",               0x046d, 0x408a),
    ("MX Vertical",           0x046d, 0x407b),
    ("G502 Hero",             0x046d, 0xc08b),
    ("K780 Multi-Device",     0x046d, 0x405b),
    ("M720 Triathlon",        0x046d, 0x405e),
    ("K400 Plus",             0x046d, 0x4024),
    ("M557",                  0x046d, 0xb010),
    ("MX Anywhere 2",         0x046d, 0x404a),
];

// ── Smokes ─────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Smoke 1: short report encode ──

    fn smoke_hidpp_encode_short() -> TestResult {
        let mut buf = [0xAAu8; 8];
        let n = match encode_short_fap(&mut buf, 0x05, 0x01, 0x00, &[]) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("short FAP encode failed"),
        };
        if n != HIDPP_REPORT_SHORT_LENGTH {
            return TestResult::Fail("short length mismatch");
        }
        if buf[0] != REPORT_ID_HIDPP_SHORT {
            return TestResult::Fail("report ID byte wrong");
        }
        if buf[1] != 0x05 {
            return TestResult::Fail("device_index wrong");
        }
        if buf[2] != 0x01 {
            return TestResult::Fail("feature_index wrong");
        }
        if buf[3] & 0x0F != HIDPP_SW_ID & 0x0F {
            return TestResult::Fail("software-id nibble wrong");
        }
        if buf[7] != 0xAA {
            return TestResult::Fail("encoder wrote past short report length");
        }
        // Overflow params.
        let big = [0u8; 4];
        if encode_short_fap(&mut buf, 0x05, 0x01, 0x00, &big).is_ok() {
            return TestResult::Fail("4-byte params should overflow a short report");
        }
        // Too small buffer.
        let mut small = [0u8; 4];
        if encode_short_fap(&mut small, 0x05, 0x01, 0x00, &[]).is_ok() {
            return TestResult::Fail("4-byte buf should reject");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_hidpp", smoke_hidpp_encode_short);

    // ── Smoke 2: long report encode ──

    fn smoke_hidpp_encode_long() -> TestResult {
        let mut buf = [0u8; 24];
        let params = [0xDE, 0xAD, 0xBE, 0xEF];
        let n = encode_long_fap(&mut buf, HIDPP_RECEIVER_INDEX, 0x07, 0x20, &params).unwrap();
        if n != HIDPP_REPORT_LONG_LENGTH {
            return TestResult::Fail("long length mismatch");
        }
        if buf[0] != REPORT_ID_HIDPP_LONG {
            return TestResult::Fail("report ID byte wrong");
        }
        if buf[1] != HIDPP_RECEIVER_INDEX {
            return TestResult::Fail("device_index wrong");
        }
        if buf[4..8] != params[..] {
            return TestResult::Fail("params not copied correctly");
        }
        // Bytes past params should be zero.
        for &b in &buf[8..HIDPP_REPORT_LONG_LENGTH] {
            if b != 0 {
                return TestResult::Fail("trailing params bytes not zeroed");
            }
        }
        // 16-byte params is max.
        let max_params = [0u8; 16];
        if encode_long_fap(&mut buf, 0xFF, 0x07, 0x20, &max_params).is_err() {
            return TestResult::Fail("16-byte params should fit in long");
        }
        // 17-byte params overflows.
        let big = [0u8; 17];
        if encode_long_fap(&mut buf, 0xFF, 0x07, 0x20, &big).is_ok() {
            return TestResult::Fail("17-byte params should overflow");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_hidpp", smoke_hidpp_encode_long);

    // ── Smoke 3: Root.GetFeature lookup encode ──

    fn smoke_hidpp_get_feature_encode() -> TestResult {
        let mut buf = [0u8; HIDPP_REPORT_SHORT_LENGTH];
        // Ask for the battery feature (0x1000) on device index 0xFF.
        encode_get_feature(&mut buf, HIDPP_RECEIVER_INDEX, HIDPP_PAGE_BATTERY_LEVEL_STATUS).unwrap();
        if buf[0] != REPORT_ID_HIDPP_SHORT {
            return TestResult::Fail("not a short report");
        }
        if buf[1] != HIDPP_RECEIVER_INDEX {
            return TestResult::Fail("device_index wrong");
        }
        if buf[2] != HIDPP_PAGE_ROOT_IDX {
            return TestResult::Fail("feature_index should be ROOT_IDX (0)");
        }
        if buf[3] & 0xF0 != CMD_ROOT_GET_FEATURE & 0xF0 {
            return TestResult::Fail("sub-command should be GET_FEATURE");
        }
        if buf[4] != 0x10 || buf[5] != 0x00 {
            return TestResult::Fail("feature ID bytes wrong (MSB/LSB)");
        }
        // Decode a synthetic reply: feature index = 0x05.
        let reply: &[u8] = &[REPORT_ID_HIDPP_SHORT, HIDPP_RECEIVER_INDEX, HIDPP_PAGE_ROOT_IDX, 0x00, 0x05, 0x00, 0x00];
        let got = decode_get_feature_response(reply).unwrap();
        if got != Some(0x05) {
            return TestResult::Fail("decoded feature index should be 5");
        }
        // Decode "not supported" — index = 0.
        let reply2: &[u8] = &[REPORT_ID_HIDPP_SHORT, HIDPP_RECEIVER_INDEX, HIDPP_PAGE_ROOT_IDX, 0x00, 0x00, 0x00, 0x00];
        let got = decode_get_feature_response(reply2).unwrap();
        if got.is_some() {
            return TestResult::Fail("zero index should decode as not-supported");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_hidpp", smoke_hidpp_get_feature_encode);

    // ── Smoke 4: battery feature 0x1000 response decode ──

    fn smoke_hidpp_battery_decode() -> TestResult {
        // Build a synthetic GET_BATTERY_LEVEL_STATUS reply for
        // device index 0x02, feature index 0x05 (whatever GetFeature
        // returned), capacity 73%, next_capacity 60%, status =
        // Discharging.
        let reply: &[u8] = &[
            REPORT_ID_HIDPP_SHORT,
            0x02,
            0x05,
            0x00,
            73, 60, 0, 0,
        ];
        let br = decode_battery_response(reply).unwrap();
        if br.capacity != 73 {
            return TestResult::Fail("capacity wrong");
        }
        if br.next_capacity != 60 {
            return TestResult::Fail("next_capacity wrong");
        }
        if br.status != BatteryStatus::Discharging {
            return TestResult::Fail("status should be Discharging");
        }
        // map_battery_level: 73% → Normal.
        if map_battery_level(br.capacity as i32) != PowerSupplyLevel::Normal {
            return TestResult::Fail("73% should map to Normal");
        }
        if map_battery_level(5) != PowerSupplyLevel::Critical {
            return TestResult::Fail("5% should map to Critical");
        }
        if map_battery_level(95) != PowerSupplyLevel::Full {
            return TestResult::Fail("95% should map to Full");
        }
        // Charge complete response.
        let reply2: &[u8] = &[
            REPORT_ID_HIDPP_SHORT,
            0x02,
            0x05,
            0x00,
            100, 0, 3, 0,
        ];
        let br2 = decode_battery_response(reply2).unwrap();
        if br2.status != BatteryStatus::ChargeComplete {
            return TestResult::Fail("status byte 3 should decode as ChargeComplete");
        }
        // Short report rejected.
        let short: &[u8] = &[REPORT_ID_HIDPP_SHORT, 0x02, 0x05, 0x00, 50];
        if decode_battery_response(short).is_ok() {
            return TestResult::Fail("too-short report should fail");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_hidpp", smoke_hidpp_battery_decode);

    // ── Smoke 5: device-claim by supported-reports bitmask ──

    fn smoke_hidpp_claims_device() -> TestResult {
        // Short+long supported — HID++ candidate.
        if !claims_device(HIDPP_REPORT_SHORT_SUPPORTED | HIDPP_REPORT_LONG_SUPPORTED) {
            return TestResult::Fail("short+long should claim");
        }
        // Short only — not a candidate.
        if claims_device(HIDPP_REPORT_SHORT_SUPPORTED) {
            return TestResult::Fail("short-only should not claim");
        }
        // Long only — not a candidate (HID++ 2.0 always needs both).
        if claims_device(HIDPP_REPORT_LONG_SUPPORTED) {
            return TestResult::Fail("long-only should not claim");
        }
        // Neither.
        if claims_device(0) {
            return TestResult::Fail("no reports should not claim");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_hidpp", smoke_hidpp_claims_device);
}
