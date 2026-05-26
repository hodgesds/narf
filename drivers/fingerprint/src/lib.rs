//! Fingerprint-reader chip-class scaffold.
//!
//! Modern business laptops carry one of four families of USB
//! fingerprint reader chip:
//!
//! - **Synaptics Prometheus / VFS9500 / Match-In-Sensor** (VID
//!   `0x06CB`) — most-common silicon on Lenovo / Dell business
//!   class (T14, X1 Carbon, Latitude, Precision). The chip
//!   implements Synaptics's proprietary Match-In-Sensor protocol
//!   where the template is stored on-chip and the host only ever
//!   receives match/no-match deltas.
//!
//! - **Goodix GF318 / GF512 series** (VID `0x27C6`) — common on
//!   HP EliteBook, Dell Precision, ASUS ZenBook. Proprietary
//!   protocol, Match-on-Host shape (image-transfer + host-side
//!   matching).
//!
//! - **Validity / Synaptics older** (VID `0x138A`) — pre-merger
//!   Validity-branded readers (now Synaptics). Older Match-on-Host
//!   protocol. Still common on Lenovo ThinkPads from the
//!   E14/T480/X280 era.
//!
//! - **Elan** (VID `0x04F3`) — common on Acer / ASUS consumer
//!   laptops. Distinct vendor protocol.
//!
//! ## Why kernel-side is *just* a chip-class scaffold
//!
//! The cryptographic enrollment + matching protocols on every one
//! of these chips are vendor-proprietary, often signed, and
//! intentionally undocumented. The Linux model (`libfprint`,
//! BSD-licensed, lives in userspace) is the right shape: the
//! kernel claims the USB device, exposes a syscall surface that
//! delivers raw USB transfers to userspace, and userspace owns
//! every byte of the protocol layer.
//!
//! Stage-0 of that arc is this crate: a VID/PID match table + a
//! probe-and-log entry point. Stages 1+ wire in:
//!
//! 1. Interface-claim against `drivers/usb`'s `dispatch_after_address`
//!    flow so attached fingerprint devices land in a registry
//!    rather than falling through to `UnknownClass`.
//! 2. A cap-gated syscall / ioctl surface so userspace daemons
//!    (the eventual `libfprint`-equivalent) can issue raw USB
//!    transfers without re-bind privileges.
//! 3. Power-management hooks for the reader's suspend/resume
//!    state machine (Synaptics chips need specific
//!    suspend-detect / resume-arm flows or they lock up).
//!
//! ## What this stage does NOT do (deferred)
//!
//! - Does NOT speak any vendor protocol (Match-In-Sensor,
//!   Match-on-Host, Goodix's image-stream).
//! - Does NOT claim USB interfaces yet — the supervisor's
//!   `dispatch_after_address` falls through to `UnknownClass` after
//!   logging.
//! - Does NOT expose a userspace surface.
//!
//! ## References (public, non-GPL)
//!
//! - `libfprint` supported-devices list — BSD-licensed reference
//!   for VID/PID coverage. <https://libfprint.freedesktop.org/devices.html>
//! - USB 2.0 §9.6.1 (Device Descriptor) — VID at offset 8 (LE),
//!   PID at offset 10 (LE); bDeviceClass at +4; bNumConfigurations
//!   at +17. <https://www.usb.org/document-library/usb-20-specification>
//! - USB 2.0 §9.6.3 (Configuration Descriptor) — bNumInterfaces at
//!   offset 4 of the 9-byte config header.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

/// Which vendor + protocol family a matched device belongs to.
/// Used by the future userspace-surface stage to route to the
/// right vendor protocol handler; Stage-0 just emits the variant
/// name in the log line.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Family {
    /// Synaptics Prometheus / VFS9500 series — Match-In-Sensor
    /// (template + match both on-chip).
    SynapticsPrometheus,
    /// Synaptics older "Match-In-Sensor" series — VFS5011 /
    /// VFS5050 era, sub-Prometheus. Different USB endpoint shape
    /// from Prometheus despite the marketing overlap.
    SynapticsMisOlder,
    /// Goodix GF318 / GF512 series — Match-on-Host with on-chip
    /// secure enclave.
    Goodix,
    /// Validity (acquired by Synaptics in 2013 but still shipped
    /// under the Validity VID on older silicon). Match-on-Host.
    Validity,
    /// Elan (separate vendor from Synaptics / Goodix). Mostly
    /// consumer laptops.
    Elan,
}

impl Family {
    /// Short human-readable name used in the probe-log line.
    pub const fn label(self) -> &'static str {
        match self {
            Family::SynapticsPrometheus => "synaptics-prometheus",
            Family::SynapticsMisOlder => "synaptics-mis-older",
            Family::Goodix => "goodix",
            Family::Validity => "validity",
            Family::Elan => "elan",
        }
    }
}

/// One entry in the VID/PID match table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FingerprintDevice {
    pub vid: u16,
    pub pid: u16,
    pub family: Family,
    /// Marketing name / chip designator. Used in the probe log
    /// line so bring-up dmesg-style scrollback shows the exact
    /// silicon. Mirrors libfprint's per-device label.
    pub name: &'static str,
}

// Vendor IDs grouped for grep-by-vendor and to make the table
// blocks self-document.
pub const SYNAPTICS_VID: u16 = 0x06CB;
pub const GOODIX_VID: u16 = 0x27C6;
pub const VALIDITY_VID: u16 = 0x138A;
pub const ELAN_VID: u16 = 0x04F3;

/// Master VID/PID table covering the common laptop fingerprint
/// readers (Lenovo / Dell / HP / ASUS business class). Sourced
/// from libfprint's device list (BSD-licensed).
///
/// Coverage targets — all four vendors are represented because a
/// single laptop OEM frequently sources from multiple readers
/// across SKU revisions, and the goal is "any business laptop's
/// reader gets recognised by name at probe time."
pub const FINGERPRINT_DEVICES: &[FingerprintDevice] = &[
    // ── Synaptics Prometheus / VFS9500 / Match-In-Sensor ─────────
    FingerprintDevice {
        vid: SYNAPTICS_VID,
        pid: 0x00BD,
        family: Family::SynapticsPrometheus,
        name: "VFS9500 Prometheus",
    },
    FingerprintDevice {
        vid: SYNAPTICS_VID,
        pid: 0x00BE,
        family: Family::SynapticsPrometheus,
        name: "Prometheus (00BE)",
    },
    FingerprintDevice {
        vid: SYNAPTICS_VID,
        pid: 0x00BF,
        family: Family::SynapticsPrometheus,
        name: "Prometheus (00BF)",
    },
    FingerprintDevice {
        vid: SYNAPTICS_VID,
        pid: 0x00C2,
        family: Family::SynapticsPrometheus,
        name: "Prometheus (00C2)",
    },
    FingerprintDevice {
        vid: SYNAPTICS_VID,
        pid: 0x00C9,
        family: Family::SynapticsPrometheus,
        name: "Prometheus (00C9)",
    },
    // ── Synaptics older Match-In-Sensor (pre-Prometheus) ─────────
    FingerprintDevice {
        vid: SYNAPTICS_VID,
        pid: 0x00A2,
        family: Family::SynapticsMisOlder,
        name: "Match-In-Sensor (00A2)",
    },
    FingerprintDevice {
        vid: SYNAPTICS_VID,
        pid: 0x00B7,
        family: Family::SynapticsMisOlder,
        name: "Match-In-Sensor (00B7)",
    },
    // ── Goodix GF318 / GF512 series ─────────────────────────────
    FingerprintDevice {
        vid: GOODIX_VID,
        pid: 0x5117,
        family: Family::Goodix,
        name: "GF318 (5117)",
    },
    FingerprintDevice {
        vid: GOODIX_VID,
        pid: 0x55B4,
        family: Family::Goodix,
        name: "GF512 (55B4)",
    },
    FingerprintDevice {
        vid: GOODIX_VID,
        pid: 0x609C,
        family: Family::Goodix,
        name: "GF series (609C)",
    },
    FingerprintDevice {
        vid: GOODIX_VID,
        pid: 0x6584,
        family: Family::Goodix,
        name: "GF series (6584)",
    },
    // ── Validity / Synaptics older ──────────────────────────────
    FingerprintDevice {
        vid: VALIDITY_VID,
        pid: 0x0007,
        family: Family::Validity,
        name: "VFS101",
    },
    FingerprintDevice {
        vid: VALIDITY_VID,
        pid: 0x0011,
        family: Family::Validity,
        name: "VFS5011",
    },
    FingerprintDevice {
        vid: VALIDITY_VID,
        pid: 0x0090,
        family: Family::Validity,
        name: "VFS7500",
    },
    FingerprintDevice {
        vid: VALIDITY_VID,
        pid: 0x0091,
        family: Family::Validity,
        name: "VFS7552",
    },
    FingerprintDevice {
        vid: VALIDITY_VID,
        pid: 0x0097,
        family: Family::Validity,
        name: "VFS Validity (0097)",
    },
    FingerprintDevice {
        vid: VALIDITY_VID,
        pid: 0x00A2,
        family: Family::Validity,
        name: "VFS Validity (00A2)",
    },
    // ── Elan ───────────────────────────────────────────────────
    FingerprintDevice {
        vid: ELAN_VID,
        pid: 0x0903,
        family: Family::Elan,
        name: "Elan EFSA (0903)",
    },
    FingerprintDevice {
        vid: ELAN_VID,
        pid: 0x0907,
        family: Family::Elan,
        name: "Elan EFSA (0907)",
    },
    FingerprintDevice {
        vid: ELAN_VID,
        pid: 0x0C03,
        family: Family::Elan,
        name: "Elan ELAN-FP (0C03)",
    },
    FingerprintDevice {
        vid: ELAN_VID,
        pid: 0x0C32,
        family: Family::Elan,
        name: "Elan ELAN-FP (0C32)",
    },
    FingerprintDevice {
        vid: ELAN_VID,
        pid: 0x0C42,
        family: Family::Elan,
        name: "Elan ELAN-FP (0C42)",
    },
];

/// Look up a USB device by `(vid, pid)`. Returns the matching
/// table entry on hit, `None` otherwise. Linear scan — the table
/// is short (under 32 entries) and a hashmap would just add
/// startup cost.
pub fn match_vid_pid(vid: u16, pid: u16) -> Option<&'static FingerprintDevice> {
    FINGERPRINT_DEVICES.iter().find(|d| d.vid == vid && d.pid == pid)
}

// ── Device-descriptor parsing per USB 2.0 §9.6.1 / §9.6.3 ────────

/// USB 2.0 §9.6.1 Device Descriptor layout, ordered by offset:
///
/// ```text
///   +0  bLength             (always 18 for DEVICE)
///   +1  bDescriptorType     (1 = DEVICE)
///   +2  bcdUSB              (LE u16)
///   +4  bDeviceClass
///   +5  bDeviceSubClass
///   +6  bDeviceProtocol
///   +7  bMaxPacketSize0
///   +8  idVendor            (LE u16)
///   +10 idProduct           (LE u16)
///   +12 bcdDevice           (LE u16)
///   +14 iManufacturer
///   +15 iProduct
///   +16 iSerialNumber
///   +17 bNumConfigurations
/// ```
const DEV_DESC_OFFSET_ID_VENDOR: usize = 8;
const DEV_DESC_OFFSET_ID_PRODUCT: usize = 10;

/// `bNumInterfaces` lives at offset 4 of the 9-byte Configuration
/// Descriptor header (USB 2.0 §9.6.3).
const CFG_DESC_OFFSET_NUM_INTERFACES: usize = 4;

/// Extract `(idVendor, idProduct)` from an 18-byte (or longer) USB
/// Device Descriptor. Returns `None` if the buffer is too short to
/// hold both fields.
pub fn parse_vid_pid(device_desc: &[u8]) -> Option<(u16, u16)> {
    if device_desc.len() < DEV_DESC_OFFSET_ID_PRODUCT + 2 {
        return None;
    }
    let vid = u16::from_le_bytes([
        device_desc[DEV_DESC_OFFSET_ID_VENDOR],
        device_desc[DEV_DESC_OFFSET_ID_VENDOR + 1],
    ]);
    let pid = u16::from_le_bytes([
        device_desc[DEV_DESC_OFFSET_ID_PRODUCT],
        device_desc[DEV_DESC_OFFSET_ID_PRODUCT + 1],
    ]);
    Some((vid, pid))
}

/// Extract `bNumInterfaces` from a Configuration Descriptor header
/// (USB 2.0 §9.6.3). Returns `None` if the buffer is too short or
/// doesn't look like a 9-byte CONFIG header.
pub fn parse_num_interfaces(cfg_desc: &[u8]) -> Option<u8> {
    if cfg_desc.len() < CFG_DESC_OFFSET_NUM_INTERFACES + 1 {
        return None;
    }
    Some(cfg_desc[CFG_DESC_OFFSET_NUM_INTERFACES])
}

/// Counter of detected fingerprint readers — test-observable +
/// surfaced in the FB status panel in later stages.
static FINGERPRINT_PROBED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of fingerprint readers probe has matched against the
/// table since boot. Test-observable signal that the probe path ran.
pub fn probed_count() -> u32 {
    FINGERPRINT_PROBED_COUNT.load(Ordering::Acquire)
}

/// Stage-0 probe entry point. Given a USB Device Descriptor
/// (18 bytes per §9.6.1) and a Configuration Descriptor header
/// (the first 9 bytes), determine whether this is a known
/// fingerprint reader. On match, increments the probed counter
/// and emits one log line:
///
/// ```text
///   fingerprint: detected <family>:<pid> "<name>" (<N> interfaces)
/// ```
///
/// Returns the match entry on success so callers can route to
/// Stage-1+ binding logic later. `None` means "not a known
/// fingerprint reader" — callers should NOT treat that as a hard
/// error (it's the normal case for every other USB device).
pub fn probe_from_descriptors(
    device_desc: &[u8],
    cfg_desc: &[u8],
) -> Option<&'static FingerprintDevice> {
    let (vid, pid) = parse_vid_pid(device_desc)?;
    let entry = match_vid_pid(vid, pid)?;
    let num_ifaces = parse_num_interfaces(cfg_desc).unwrap_or(0);
    FINGERPRINT_PROBED_COUNT.fetch_add(1, Ordering::AcqRel);
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "fingerprint: detected {}:{:04x} \"{}\" ({} interfaces)",
            entry.family.label(),
            entry.pid,
            entry.name,
            num_ifaces
        );
    }
    Some(entry)
}

/// Stage::Device initcall. Stage-0 has no per-controller setup —
/// the match table is `const`, lookup is allocation-free, and the
/// probe entry point is a `pub fn`. We register one initcall just
/// to land the announce line in the boot log and to make the
/// `register_initcalls` symbol exist for `frame::bare_main`'s wire-up.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "fingerprint", || {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "fingerprint: match table ready ({} VID/PID entries across {} vendors)",
            FINGERPRINT_DEVICES.len(),
            4,
        );
        InitResult::Ok
    });
}

#[doc(hidden)]
/// Test-only reset hook so smokes can assert counter increments
/// without bleeding state between cases.
pub fn __reset_for_test() {
    FINGERPRINT_PROBED_COUNT.store(0, Ordering::Release);
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_match_table_covers_all_four_vendors() -> TestResult {
        let mut saw_syn_prom = false;
        let mut saw_syn_old = false;
        let mut saw_goodix = false;
        let mut saw_valid = false;
        let mut saw_elan = false;
        for d in FINGERPRINT_DEVICES.iter() {
            match d.family {
                Family::SynapticsPrometheus => saw_syn_prom = true,
                Family::SynapticsMisOlder => saw_syn_old = true,
                Family::Goodix => saw_goodix = true,
                Family::Validity => saw_valid = true,
                Family::Elan => saw_elan = true,
            }
        }
        if !(saw_syn_prom && saw_syn_old && saw_goodix && saw_valid && saw_elan) {
            return TestResult::Fail("one or more vendor families missing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/fingerprint", smoke_match_table_covers_all_four_vendors);

    fn smoke_match_synaptics_prometheus_bd() -> TestResult {
        let entry = match match_vid_pid(0x06CB, 0x00BD) {
            Some(e) => e,
            None => return TestResult::Fail("Synaptics 06CB:00BD not in table"),
        };
        if entry.family != Family::SynapticsPrometheus {
            return TestResult::Fail("Synaptics 00BD wrong family");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/fingerprint", smoke_match_synaptics_prometheus_bd);

    fn smoke_match_goodix_gf512() -> TestResult {
        let entry = match match_vid_pid(0x27C6, 0x55B4) {
            Some(e) => e,
            None => return TestResult::Fail("Goodix 27C6:55B4 not in table"),
        };
        if entry.family != Family::Goodix {
            return TestResult::Fail("Goodix 55B4 wrong family");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/fingerprint", smoke_match_goodix_gf512);

    fn smoke_match_validity_vfs5011() -> TestResult {
        let entry = match match_vid_pid(0x138A, 0x0011) {
            Some(e) => e,
            None => return TestResult::Fail("Validity 138A:0011 not in table"),
        };
        if entry.family != Family::Validity {
            return TestResult::Fail("Validity 0011 wrong family");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/fingerprint", smoke_match_validity_vfs5011);

    fn smoke_match_elan_0c42() -> TestResult {
        let entry = match match_vid_pid(0x04F3, 0x0C42) {
            Some(e) => e,
            None => return TestResult::Fail("Elan 04F3:0C42 not in table"),
        };
        if entry.family != Family::Elan {
            return TestResult::Fail("Elan 0C42 wrong family");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/fingerprint", smoke_match_elan_0c42);

    fn smoke_match_rejects_random_vid_pid() -> TestResult {
        // Intel ax210 wifi VID — should not be a fingerprint reader.
        if match_vid_pid(0x8086, 0x2725).is_some() {
            return TestResult::Fail("non-fingerprint VID/PID matched");
        }
        // Same fingerprint VID but unknown PID.
        if match_vid_pid(0x06CB, 0xFFFF).is_some() {
            return TestResult::Fail("unknown Synaptics PID matched");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/fingerprint", smoke_match_rejects_random_vid_pid);

    fn smoke_parse_vid_pid_extracts_from_device_descriptor() -> TestResult {
        // 18-byte device descriptor with VID=0x06CB PID=0x00BD.
        // LE encoding per USB 2.0 §9.6.1.
        let dev_desc = [
            18, 1,           // bLength, bDescriptorType
            0x00, 0x02,      // bcdUSB = 2.00
            0xFF, 0xFF, 0xFF, // class triple (vendor-specific is typical for fp)
            64,              // bMaxPacketSize0
            0xCB, 0x06,      // idVendor = 0x06CB (LE)
            0xBD, 0x00,      // idProduct = 0x00BD (LE)
            0x00, 0x01,      // bcdDevice = 0x0100
            1, 2, 3,         // i-strings
            1,               // bNumConfigurations
        ];
        let (vid, pid) = match parse_vid_pid(&dev_desc) {
            Some(p) => p,
            None => return TestResult::Fail("descriptor parse returned None"),
        };
        if vid != 0x06CB {
            return TestResult::Fail("VID mismatch");
        }
        if pid != 0x00BD {
            return TestResult::Fail("PID mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/fingerprint",
        smoke_parse_vid_pid_extracts_from_device_descriptor
    );

    fn smoke_parse_vid_pid_rejects_short_descriptor() -> TestResult {
        let truncated = [18u8, 1, 0, 2, 0, 0, 0, 64, 0xCB, 0x06]; // 10 bytes
        if parse_vid_pid(&truncated).is_some() {
            return TestResult::Fail("short descriptor must be rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/fingerprint",
        smoke_parse_vid_pid_rejects_short_descriptor
    );

    fn smoke_parse_num_interfaces_extracts_from_cfg_header() -> TestResult {
        // 9-byte CONFIG descriptor header with bNumInterfaces = 2.
        let cfg = [
            9, 0x02,    // bLength, bDescriptorType=CONFIG
            18, 0,      // wTotalLength
            2,          // bNumInterfaces
            1,          // bConfigurationValue
            0, 0xC0, 50,
        ];
        match parse_num_interfaces(&cfg) {
            Some(2) => TestResult::Pass,
            _ => TestResult::Fail("bNumInterfaces parse wrong"),
        }
    }
    kernel_test_in!(
        "drivers/fingerprint",
        smoke_parse_num_interfaces_extracts_from_cfg_header
    );

    fn smoke_probe_full_flow_matches_and_increments_counter() -> TestResult {
        __reset_for_test();
        // Synthesise a Goodix GF512 (27C6:55B4) device descriptor +
        // config header.
        let dev_desc = [
            18, 1,
            0x00, 0x02,
            0xFF, 0xFF, 0xFF,
            64,
            0xC6, 0x27,      // VID 0x27C6
            0xB4, 0x55,      // PID 0x55B4
            0x00, 0x01,
            1, 2, 3,
            1,
        ];
        let cfg = [
            9, 0x02,
            18, 0,
            1,               // bNumInterfaces
            1,
            0, 0xC0, 50,
        ];
        let before = probed_count();
        let m = match probe_from_descriptors(&dev_desc, &cfg) {
            Some(m) => m,
            None => return TestResult::Fail("probe failed to match Goodix descriptor"),
        };
        if m.family != Family::Goodix {
            return TestResult::Fail("matched entry has wrong family");
        }
        if probed_count() != before + 1 {
            return TestResult::Fail("probed_count not incremented");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/fingerprint",
        smoke_probe_full_flow_matches_and_increments_counter
    );

    fn smoke_probe_non_fingerprint_returns_none() -> TestResult {
        __reset_for_test();
        // Intel ax210 wifi descriptor — not a fingerprint reader.
        let dev_desc = [
            18, 1,
            0x00, 0x02,
            0xFF, 0xFF, 0xFF,
            64,
            0x86, 0x80,      // VID 0x8086
            0x25, 0x27,      // PID 0x2725
            0x00, 0x01,
            1, 2, 3,
            1,
        ];
        let cfg = [
            9, 0x02,
            18, 0,
            1,
            1,
            0, 0xC0, 50,
        ];
        if probe_from_descriptors(&dev_desc, &cfg).is_some() {
            return TestResult::Fail("non-fingerprint device must not match");
        }
        if probed_count() != 0 {
            return TestResult::Fail("counter must not increment on no-match");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/fingerprint",
        smoke_probe_non_fingerprint_returns_none
    );

    fn smoke_match_table_size_matches_brief() -> TestResult {
        // Brief specifies: Synaptics 7 + Goodix 4 + Validity 6 + Elan 5 = 22.
        if FINGERPRINT_DEVICES.len() != 22 {
            return TestResult::Fail("match table size drifted from brief");
        }
        // Per-vendor counts must match the brief or the smoke breaks.
        let count = |fam: Family| {
            FINGERPRINT_DEVICES
                .iter()
                .filter(|d| d.family == fam)
                .count()
        };
        if count(Family::SynapticsPrometheus) != 5 {
            return TestResult::Fail("Synaptics Prometheus count drift");
        }
        if count(Family::SynapticsMisOlder) != 2 {
            return TestResult::Fail("Synaptics MIS-older count drift");
        }
        if count(Family::Goodix) != 4 {
            return TestResult::Fail("Goodix count drift");
        }
        if count(Family::Validity) != 6 {
            return TestResult::Fail("Validity count drift");
        }
        if count(Family::Elan) != 5 {
            return TestResult::Fail("Elan count drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/fingerprint",
        smoke_match_table_size_matches_brief
    );

    fn smoke_match_table_no_duplicate_vid_pid_pairs() -> TestResult {
        // Linear de-dup check — table small enough not to need anything
        // smarter.
        for (i, a) in FINGERPRINT_DEVICES.iter().enumerate() {
            for b in FINGERPRINT_DEVICES.iter().skip(i + 1) {
                if a.vid == b.vid && a.pid == b.pid {
                    return TestResult::Fail("duplicate VID/PID in table");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/fingerprint",
        smoke_match_table_no_duplicate_vid_pid_pairs
    );

    fn smoke_family_labels_are_kebab_case() -> TestResult {
        // Labels should be filename-safe / log-grep-safe. Reject any
        // upper-case ASCII or whitespace.
        for fam in [
            Family::SynapticsPrometheus,
            Family::SynapticsMisOlder,
            Family::Goodix,
            Family::Validity,
            Family::Elan,
        ] {
            let s = fam.label();
            for ch in s.chars() {
                if ch.is_ascii_uppercase() || ch.is_whitespace() {
                    return TestResult::Fail("family label must be lowercase + no whitespace");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/fingerprint",
        smoke_family_labels_are_kebab_case
    );
}
