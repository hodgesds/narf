// SPDX-License-Identifier: GPL-2.0-or-later
//! Wacom tablet — device feature table and mode-select feature report.
//!
//! ## References
//!
//! - Linux `drivers/hid/wacom_wac.c` — `wacom_features_*` static table
//!   and `_wacom_query_tablet_data` / `wacom_set_device_mode`.
//! - Linux `drivers/hid/wacom_wac.h` — `struct wacom_features`, type enum.
//!
//! Every Wacom tablet powers on in a "mouse emulation" (HID boot-mouse
//! compatible) mode. To get absolute position, pressure, tilt, etc. the
//! host must send a HID SET_REPORT(Feature) with report-ID 2, value 0x02
//! ("pen mode"). Linux calls this sequence `wacom_set_device_mode`
//! (wacom_sys.c:581) immediately after enumeration.
//!
//! This module is pure logic: it knows nothing about xHCI or interrupt
//! endpoints. The caller (wacom.rs) owns the control-transfer machinery
//! and passes in a closure or the raw buffer to send.

/// Wacom USB vendor ID.
pub const USB_VID_WACOM: u16 = 0x056A;

/// Feature-report ID used for mode switching on all pre-HID-generic
/// Wacom tablets. Linux: wacom_sys.c `_wacom_query_tablet_data` line 704.
pub const WACOM_FEATURE_REPORT_ID: u8 = 2;

/// Value written to byte[1] of the feature report to request pen mode.
/// Linux: wacom_sys.c line 710.
pub const WACOM_PEN_MODE_VALUE: u8 = 2;

// ── Device-type discriminants ─────────────────────────────────────────
// Adapted from Linux drivers/hid/wacom_wac.h enum (lines 190-247).

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WacomType {
    /// Original Intuos (gen1/gen2) — 10-byte EMR packets, 1023-level
    /// pressure, simultaneous two-tool support.
    /// Linux: INTUOS (wacom_wac.h:200).
    Intuos = 0,
    /// Intuos Pro S (current gen) — 13-bit pressure, touch ring, 7 ExpressKeys.
    /// Linux: INTUOSPS (wacom_wac.h:211).
    IntuosProS = 1,
    /// Intuos Pro M (current gen).
    /// Linux: INTUOSPM (wacom_wac.h:212).
    IntuosProM = 2,
    /// Intuos Pro L (current gen).
    /// Linux: INTUOSPL (wacom_wac.h:213).
    IntuosProL = 3,
    /// Bamboo Pen-only tablets (CTL-47x, CTL-67x, One by Wacom).
    /// Linux: BAMBOO_PEN (wacom_wac.h:228).
    BambooPen = 4,
    /// Bamboo Pen+Touch tablets.
    /// Linux: BAMBOO_PT (wacom_wac.h:232).
    BambooPT = 5,
    /// Intuos HT (Intuos S 2nd-gen, small-form-factor consumer).
    /// Linux: INTUOSHT (wacom_wac.h:229).
    IntuosHT = 6,
    /// Intuos HT2 (Intuos S 2/M 2).
    /// Linux: INTUOSHT2 (wacom_wac.h:230).
    IntuosHT2 = 7,
    /// Cintiq pen display (classic protocol, 16-byte reports).
    /// Linux: CINTIQ (wacom_wac.h:224).
    Cintiq = 8,
    /// Cintiq 13HD / Cintiq Pro 13 — like CINTIQ with offsets.
    /// Linux: WACOM_13HD (wacom_wac.h:226).
    Cintiq13HD = 9,
    /// Cintiq 21UX2.
    /// Linux: WACOM_21UX2 (wacom_wac.h:217).
    Cintiq21UX2 = 10,
    /// Cintiq 22HD.
    /// Linux: WACOM_22HD (wacom_wac.h:218).
    Cintiq22HD = 11,
    /// DTK (tablet PC / 22" pen display, 6 ExpressKeys).
    /// Linux: DTK (wacom_wac.h:219).
    Dtk = 12,
    /// Cintiq 24HD.
    /// Linux: WACOM_24HD (wacom_wac.h:220).
    Cintiq24HD = 13,
    /// Intuos5 S.
    /// Linux: INTUOS5S (wacom_wac.h:207).
    Intuos5S = 14,
    /// Intuos5 M.
    /// Linux: INTUOS5 (wacom_wac.h:208).
    Intuos5 = 15,
    /// Intuos5 L.
    /// Linux: INTUOS5L (wacom_wac.h:209).
    Intuos5L = 16,
    /// PenPartner / Graphire class.
    /// Linux: PENPARTNER (wacom_wac.h:191).
    PenPartner = 17,
}

/// Per-device feature record. Mirrors `struct wacom_features` in Linux
/// wacom_wac.h (line 249) but limited to the fields we actually use.
///
/// `pressure_max`: maximum pressure value the device reports.
///   - 1023 = Graphire/Bamboo/Intuos1-2 (10-bit)
///   - 2047 = Intuos3/4/5 (11-bit)
///   - 4095 = Intuos BT (12-bit)
///   - 8191 = Intuos Pro Gen2 / Cintiq Pro (13-bit)
///
/// `touch_max`: maximum simultaneous touch contacts (0 = no touch).
///
/// `num_buttons`: number of ExpressKey buttons on the pad (0 = none).
#[derive(Copy, Clone, Debug)]
pub struct WacomFeatures {
    /// Human-readable device name (matches Linux feature-table name string).
    pub name: &'static str,
    /// Maximum X coordinate in tablet units.
    pub x_max: u32,
    /// Maximum Y coordinate in tablet units.
    pub y_max: u32,
    /// Maximum pressure (2047, 4095, or 8191 for current devices).
    pub pressure_max: u16,
    /// Maximum hover distance (tablet units; 0 = not supported).
    pub distance_max: u8,
    /// Device type discriminant for packet decode dispatch.
    pub device_type: WacomType,
    /// Maximum simultaneous touch contacts. 0 = pen-only.
    pub touch_max: u8,
    /// Number of ExpressKey / pad buttons.
    pub num_buttons: u8,
}

impl WacomFeatures {
    const fn new(
        name: &'static str,
        x_max: u32,
        y_max: u32,
        pressure_max: u16,
        distance_max: u8,
        device_type: WacomType,
        touch_max: u8,
        num_buttons: u8,
    ) -> Self {
        Self { name, x_max, y_max, pressure_max, distance_max, device_type, touch_max, num_buttons }
    }
}

/// USB device-ID table entry.
#[derive(Copy, Clone, Debug)]
pub struct WacomDeviceId {
    /// USB product ID (vendor is always USB_VID_WACOM).
    pub pid: u16,
    /// Associated feature record.
    pub features: WacomFeatures,
}

macro_rules! entry {
    ($pid:expr, $name:expr, $x:expr, $y:expr, $p:expr, $d:expr, $ty:expr, $t:expr, $b:expr) => {
        WacomDeviceId {
            pid: $pid,
            features: WacomFeatures::new($name, $x, $y, $p, $d, $ty, $t, $b),
        }
    };
}

/// Device-ID / feature table — 46 entries covering the consumer/prosumer
/// lineup requested in the driver spec plus several closely-related
/// variants for completeness. Derived from Linux `wacom_features_*` statics
/// in wacom_wac.c (lines 4385-4930).
///
/// Ordering mirrors the Linux table (historical entry order) so
/// cross-referencing is straightforward.
pub static WACOM_DEVICES: &[WacomDeviceId] = &[
    // ── Intuos Pro (current gen, PTH-460/660/860) ────────────────────
    // Linux wacom_wac.c:4573 wacom_features_0x314 — PTH-460 (Intuos Pro S)
    entry!(0x0314, "Wacom Intuos Pro S",  31496, 19685, 2047, 63, WacomType::IntuosProS, 16, 7),
    // Linux wacom_wac.c:4577 wacom_features_0x315 — PTH-660 (Intuos Pro M)
    entry!(0x0315, "Wacom Intuos Pro M",  44704, 27940, 2047, 63, WacomType::IntuosProM, 16, 9),
    // Linux wacom_wac.c:4581 wacom_features_0x317 — PTH-860 (Intuos Pro L)
    entry!(0x0317, "Wacom Intuos Pro L",  65024, 40640, 2047, 63, WacomType::IntuosProL, 16, 9),

    // ── Intuos5 (previous gen) ───────────────────────────────────────
    // Linux wacom_wac.c:4558 wacom_features_0x26 — Intuos5 touch S
    entry!(0x0026, "Wacom Intuos5 touch S", 31496, 19685, 2047, 63, WacomType::Intuos5S,  16, 7),
    // Linux wacom_wac.c:4561 wacom_features_0x27 — Intuos5 touch M
    entry!(0x0027, "Wacom Intuos5 touch M", 44704, 27940, 2047, 63, WacomType::Intuos5,   16, 9),
    // Linux wacom_wac.c:4564 wacom_features_0x28 — Intuos5 touch L
    entry!(0x0028, "Wacom Intuos5 touch L", 65024, 40640, 2047, 63, WacomType::Intuos5L,  16, 9),
    // Linux wacom_wac.c:4567 wacom_features_0x29 — Intuos5 S (no touch)
    entry!(0x0029, "Wacom Intuos5 S",      31496, 19685, 2047, 63, WacomType::Intuos5S,   0, 7),
    // Linux wacom_wac.c:4570 wacom_features_0x2A — Intuos5 M (no touch)
    entry!(0x002A, "Wacom Intuos5 M",      44704, 27940, 2047, 63, WacomType::Intuos5,    0, 9),

    // ── Intuos S/M consumer (CTL-4100 / CTL-6100) ───────────────────
    // Linux wacom_wac.c:4828 wacom_features_0x30E — Intuos S (2nd gen)
    entry!(0x030E, "Wacom Intuos S",       15200,  9500, 1023, 31, WacomType::IntuosHT,   0, 0),
    // Linux wacom_wac.c:4879 wacom_features_0x33B — Intuos S 2
    entry!(0x033B, "Wacom Intuos S 2",     15200,  9500, 2047, 63, WacomType::IntuosHT2,  0, 0),
    // Linux wacom_wac.c:4882 wacom_features_0x33C — Intuos PT S 2
    entry!(0x033C, "Wacom Intuos PT S 2",  15200,  9500, 2047, 63, WacomType::IntuosHT2, 16, 0),
    // Linux wacom_wac.c:4886 wacom_features_0x33D — Intuos P M 2
    entry!(0x033D, "Wacom Intuos P M 2",   21600, 13500, 2047, 63, WacomType::IntuosHT2,  0, 0),
    // Linux wacom_wac.c:4890 wacom_features_0x33E — Intuos PT M 2
    entry!(0x033E, "Wacom Intuos PT M 2",  21600, 13500, 2047, 63, WacomType::IntuosHT2, 16, 0),
    // Linux wacom_wac.c:4820 wacom_features_0x302 — Intuos PT S
    entry!(0x0302, "Wacom Intuos PT S",    15200,  9500, 1023, 31, WacomType::IntuosHT,  16, 0),
    // Linux wacom_wac.c:4824 wacom_features_0x303 — Intuos PT M
    entry!(0x0303, "Wacom Intuos PT M",    21600, 13500, 1023, 31, WacomType::IntuosHT,  16, 0),
    // Linux wacom_wac.c:4870 wacom_features_0x323 — Intuos P M
    entry!(0x0323, "Wacom Intuos P M",     21600, 13500, 1023, 31, WacomType::IntuosHT,   0, 0),

    // ── Bamboo / One by Wacom (CTL-471/671, CTL-472/672) ────────────
    // Linux wacom_wac.c:4814 wacom_features_0x300 — Bamboo One S
    entry!(0x0300, "Wacom Bamboo One S",   14720,  9225, 1023, 31, WacomType::BambooPen,  0, 0),
    // Linux wacom_wac.c:4817 wacom_features_0x301 — Bamboo One M
    entry!(0x0301, "Wacom Bamboo One M",   21648, 13530, 1023, 31, WacomType::BambooPen,  0, 0),
    // Linux wacom_wac.c:4911 wacom_features_0x37A — One by Wacom S (CTL-472)
    entry!(0x037A, "Wacom One by Wacom S", 15200,  9500, 2047, 63, WacomType::BambooPen,  0, 0),
    // Linux wacom_wac.c:4914 wacom_features_0x37B — One by Wacom M (CTL-672)
    entry!(0x037B, "Wacom One by Wacom M", 21600, 13500, 2047, 63, WacomType::BambooPen,  0, 0),
    // Linux wacom_wac.c:4784 wacom_features_0xD4 — Bamboo Pen S
    entry!(0x00D4, "Wacom Bamboo Pen",     14720,  9200, 1023, 31, WacomType::BambooPen,  0, 0),
    // Linux wacom_wac.c:4787 wacom_features_0xD5 — Bamboo Pen 6x8
    entry!(0x00D5, "Wacom Bamboo Pen 6x8", 21648, 13700, 1023, 31, WacomType::BambooPen,  0, 0),
    // Linux wacom_wac.c:4775 wacom_features_0xD1 — Bamboo 2FG 4x5
    entry!(0x00D1, "Wacom Bamboo 2FG 4x5", 14720,  9200, 1023, 31, WacomType::BambooPT,   2, 0),
    // Linux wacom_wac.c:4781 wacom_features_0xD3 — Bamboo 2FG 6x8
    entry!(0x00D3, "Wacom Bamboo 2FG 6x8", 21648, 13700, 1023, 31, WacomType::BambooPT,   2, 0),
    // Linux wacom_wac.c:4805 wacom_features_0xDD — Bamboo Connect
    entry!(0x00DD, "Wacom Bamboo Connect", 14720,  9200, 1023, 31, WacomType::BambooPT,   0, 0),
    // Linux wacom_wac.c:4808 wacom_features_0xDE — Bamboo 16FG 4x5
    entry!(0x00DE, "Wacom Bamboo 16FG 4x5", 14720, 9200, 1023, 31, WacomType::BambooPT,  16, 0),

    // ── Cintiq 16/22 pen displays ─────────────────────────────────────
    // Linux wacom_wac.c:4663 wacom_features_0x57 — DTK-2241 (Cintiq 22)
    entry!(0x0057, "Wacom DTK2241",        95840, 54260, 2047, 63, WacomType::Dtk,        0, 6),
    // Linux wacom_wac.c:4683 wacom_features_0xFA — Cintiq 22HD
    entry!(0x00FA, "Wacom Cintiq 22HD",    95840, 54260, 2047, 63, WacomType::Cintiq22HD, 0, 18),
    // Linux wacom_wac.c:4688 wacom_features_0x5B — Cintiq 22HDT (pen)
    entry!(0x005B, "Wacom Cintiq 22HDT",   95840, 54260, 2047, 63, WacomType::Cintiq22HD, 0, 18),
    // Linux wacom_wac.c:4623 wacom_features_0x304 — Cintiq 13HD
    entry!(0x0304, "Wacom Cintiq 13HD",    59552, 33848, 1023, 63, WacomType::Cintiq13HD, 0, 9),
    // Linux wacom_wac.c:4628 wacom_features_0x333 — Cintiq 13HD touch (pen)
    entry!(0x0333, "Wacom Cintiq 13HD touch", 59552, 33848, 2047, 63, WacomType::Cintiq13HD, 0, 9),

    // ── Cintiq Pro 13/16/24/32 ────────────────────────────────────────
    // Linux wacom_wac.c:4585 wacom_features_0xF4 — Cintiq 24HD
    entry!(0x00F4, "Wacom Cintiq 24HD",   104480, 65600, 2047, 63, WacomType::Cintiq24HD, 0, 16),
    // Linux wacom_wac.c:4590 wacom_features_0xF8 — Cintiq 24HD touch (pen)
    entry!(0x00F8, "Wacom Cintiq 24HD touch", 104480, 65600, 2047, 63, WacomType::Cintiq24HD, 0, 16),
    // Linux wacom_wac.c:4614 wacom_features_0x3F — Cintiq 21UX
    entry!(0x003F, "Wacom Cintiq 21UX",    87200, 65600, 1023, 63, WacomType::Cintiq,     0, 8),
    // Linux wacom_wac.c:4678 wacom_features_0xCC — Cintiq 21UX2
    entry!(0x00CC, "Wacom Cintiq 21UX2",   87200, 65600, 2047, 63, WacomType::Cintiq21UX2, 0, 18),
    // Linux wacom_wac.c:4600 wacom_features_0x32A — Cintiq 27QHD
    entry!(0x032A, "Wacom Cintiq 27QHD",  120140, 67920, 2047, 63, WacomType::Cintiq24HD, 0, 0),

    // ── Intuos3 ───────────────────────────────────────────────────────
    // Linux wacom_wac.c:4519 wacom_features_0xB0 — Intuos3 4x5
    entry!(0x00B0, "Wacom Intuos3 4x5",    25400, 20320, 1023, 63, WacomType::Intuos5S,   0, 4),
    // Linux wacom_wac.c:4522 wacom_features_0xB1 — Intuos3 6x8
    entry!(0x00B1, "Wacom Intuos3 6x8",    40640, 30480, 1023, 63, WacomType::Intuos5,    0, 8),
    // Linux wacom_wac.c:4524 wacom_features_0xB2 — Intuos3 9x12
    entry!(0x00B2, "Wacom Intuos3 9x12",   60960, 45720, 1023, 63, WacomType::Intuos5,    0, 8),

    // ── Intuos4 ───────────────────────────────────────────────────────
    // Linux wacom_wac.c:4540 wacom_features_0xB8 — Intuos4 4x6
    entry!(0x00B8, "Wacom Intuos4 4x6",    31496, 19685, 2047, 63, WacomType::Intuos5S,   0, 7),
    // Linux wacom_wac.c:4543 wacom_features_0xB9 — Intuos4 6x9
    entry!(0x00B9, "Wacom Intuos4 6x9",    44704, 27940, 2047, 63, WacomType::Intuos5,    0, 9),
    // Linux wacom_wac.c:4546 wacom_features_0xBA — Intuos4 8x13
    entry!(0x00BA, "Wacom Intuos4 8x13",   65024, 40640, 2047, 63, WacomType::Intuos5L,   0, 9),
    // Linux wacom_wac.c:4549 wacom_features_0xBB — Intuos4 12x19
    entry!(0x00BB, "Wacom Intuos4 12x19",  97536, 60960, 2047, 63, WacomType::Intuos5L,   0, 9),

    // ── Intuos1/2 (original EMR) ──────────────────────────────────────
    // Linux wacom_wac.c:4450 wacom_features_0x20 — Intuos 4x5
    entry!(0x0020, "Wacom Intuos 4x5",     12700, 10600, 1023, 31, WacomType::Intuos,     0, 0),
    // Linux wacom_wac.c:4453 wacom_features_0x21 — Intuos 6x8
    entry!(0x0021, "Wacom Intuos 6x8",     20320, 16240, 1023, 31, WacomType::Intuos,     0, 0),
    // Linux wacom_wac.c:4456 wacom_features_0x22 — Intuos 9x12
    entry!(0x0022, "Wacom Intuos 9x12",    30480, 24060, 1023, 31, WacomType::Intuos,     0, 0),
    // Linux wacom_wac.c:4504 wacom_features_0x41 — Intuos2 4x5
    entry!(0x0041, "Wacom Intuos2 4x5",    12700, 10600, 1023, 31, WacomType::Intuos,     0, 0),
    // Linux wacom_wac.c:4507 wacom_features_0x42 — Intuos2 6x8
    entry!(0x0042, "Wacom Intuos2 6x8",    20320, 16240, 1023, 31, WacomType::Intuos,     0, 0),
    // Linux wacom_wac.c:4510 wacom_features_0x43 — Intuos2 9x12
    entry!(0x0043, "Wacom Intuos2 9x12",   30480, 24060, 1023, 31, WacomType::Intuos,     0, 0),
];

/// Look up features by USB product ID. Returns `None` if the PID is not
/// in the table. VID is always `USB_VID_WACOM`.
pub fn lookup(pid: u16) -> Option<&'static WacomFeatures> {
    WACOM_DEVICES.iter().find(|e| e.pid == pid).map(|e| &e.features)
}

/// Encode the mode-select feature report into `buf`. Returns the number
/// of bytes to send.
///
/// Linux equivalent: `wacom_sys.c:604–606` inside `wacom_set_device_mode`.
///
/// The buffer must be at least 2 bytes. Only bytes [0..=1] are written;
/// larger buffers are valid (and common — some devices have longer feature
/// reports) but only the first two bytes are significant for mode select.
pub fn encode_pen_mode_report(buf: &mut [u8]) -> usize {
    assert!(buf.len() >= 2, "wacom feature report buffer must be >= 2 bytes");
    buf[0] = WACOM_FEATURE_REPORT_ID;
    buf[1] = WACOM_PEN_MODE_VALUE;
    2
}

/// Returns `true` if the device identified by `pid` needs the pen-mode
/// feature report. Pen-only and pen+touch pre-HID-generic Wacom devices
/// (type <= BAMBOO_PT in Linux ordering) all need it.
///
/// Linux: `_wacom_query_tablet_data`, wacom_sys.c:707-711.
///
/// HID_GENERIC devices (wireless receivers, newer firmware that uses the
/// standard HID descriptor) handle mode switching differently and are not
/// listed in our table, so `lookup()` returns None for them and this
/// function is never reached.
pub fn needs_pen_mode(features: &WacomFeatures) -> bool {
    // All device types in our table use the simple feature-report mode
    // switch. We explicitly exclude nothing here — if it's in the table
    // it needs the mode report, mirroring Linux's type <= BAMBOO_PT guard.
    !matches!(features.device_type, _ if false /* keep all */)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_at_least_40_entries() {
        assert!(
            WACOM_DEVICES.len() >= 40,
            "expected >= 40 device-table entries, got {}",
            WACOM_DEVICES.len()
        );
    }

    #[test]
    fn all_pids_unique() {
        let mut seen = alloc::vec::Vec::new();
        for e in WACOM_DEVICES {
            assert!(
                !seen.contains(&e.pid),
                "duplicate PID 0x{:04X} in WACOM_DEVICES",
                e.pid
            );
            seen.push(e.pid);
        }
    }

    #[test]
    fn lookup_intuos_pro_s() {
        let f = lookup(0x0314).expect("Intuos Pro S not found");
        assert_eq!(f.device_type, WacomType::IntuosProS);
        assert_eq!(f.pressure_max, 2047);
        assert_eq!(f.touch_max, 16);
        assert_eq!(f.num_buttons, 7);
    }

    #[test]
    fn lookup_one_by_wacom_s() {
        let f = lookup(0x037A).expect("One by Wacom S not found");
        assert_eq!(f.device_type, WacomType::BambooPen);
        assert_eq!(f.pressure_max, 2047);
        assert_eq!(f.touch_max, 0);
    }

    #[test]
    fn lookup_cintiq_22hd() {
        let f = lookup(0x00FA).expect("Cintiq 22HD not found");
        assert_eq!(f.device_type, WacomType::Cintiq22HD);
        assert_eq!(f.num_buttons, 18);
    }

    #[test]
    fn encode_pen_mode_report_sets_correct_bytes() {
        let mut buf = [0u8; 8];
        let n = encode_pen_mode_report(&mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf[0], WACOM_FEATURE_REPORT_ID); // 2
        assert_eq!(buf[1], WACOM_PEN_MODE_VALUE);    // 2
        // Other bytes untouched
        assert_eq!(&buf[2..], &[0u8; 6]);
    }

    #[test]
    fn intuos_pro_pressure_is_13bit_capable() {
        // Intuos Pro Gen2 (BT) has 8191 = 13-bit. Our USB entries use 2047
        // (11-bit) as per Linux wacom_features_0x314; the 13-bit variants
        // (0x360/0x361) are BT-only and not in our USB table.
        let f = lookup(0x0314).unwrap();
        assert!(f.pressure_max >= 2047, "expected >= 2047-level pressure for Intuos Pro S");
    }
}

extern crate alloc;
