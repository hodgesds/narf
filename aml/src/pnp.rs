//! PnP device query: match devices by `_HID`, filter by `_STA`,
//! decode `_CRS` resources.
//!
//! The namespace builder already knows every `Device` node and its
//! `_HID` (string or EISA-integer form) plus `_CRS` evaluation
//! ([`crate::prt_crs::evaluate_crs_for`], `Name` and `Method` forms).
//! This module combines those into the one query PnP consumers need:
//! "give me every device with this HID and the I/O base + IRQ the
//! firmware assigned it".
//!
//! Reference: ACPI 6.5 §5.6.7 (`_HID` / EISA IDs), §6.1 (`_STA`
//! status; bit 0 = present — a device whose `_STA` reports the
//! present bit clear is not enumerated), §6.4 (`_CRS` resource
//! templates). Linux consumer reference for the serial case:
//! `drivers/tty/serial/8250/8250_acpi.c`; Linux's ACPI core
//! (`acpi_bus_get_status` / `acpi_bus_check_add`) likewise skips
//! devices whose present bit is clear, and assumes a device with
//! no `_STA` at all is present. `_STA` is evaluated via
//! [`crate::prt_crs::evaluate_sta_for`] (`Method` returning an
//! integer, or `Name` holding an integer).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::resource::ResourceItem;

/// One PnP device's firmware-declared resources.
///
/// Only devices with an I/O base in `_CRS` are returned (see
/// [`pnp_devices`]); `irq` is `None` when `_CRS` carries no IRQ
/// descriptor (polled device).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PnpDevice {
    /// Full namespace path (e.g. `\_SB.COM1`).
    pub path: String,
    /// I/O-port base from the first `Io` / `FixedIo` descriptor.
    pub io_base: Option<u16>,
    /// IRQ line from the first `Irq` / `ExtendedIrq` descriptor.
    pub irq: Option<u8>,
}

/// Find every device whose `_HID` equals `hid` and decode its `_CRS`
/// into I/O base + IRQ.
///
/// Devices whose `_STA` reports not-present (present bit 0 clear)
/// are skipped, as are devices without an I/O base in `_CRS` — no
/// `_CRS` at all, an unevaluatable `_CRS`, or a `_CRS` with no I/O
/// descriptor. Devices with no `_STA` at all keep today's behavior
/// (present); so does a device whose `_STA` exists but cannot be
/// evaluated — see [`device_present`].
///
/// Returns an empty `Vec` when the namespace hasn't been built yet
/// (graceful no-op for early-boot callers); never panics.
///
/// IRQ decoding: for a small `Irq` descriptor the lowest set bit of
/// the mask wins; for `ExtendedIrq` the first GSI that fits in a
/// `u8` wins.
pub fn pnp_devices(hid: &str) -> Vec<PnpDevice> {
    let mut out = Vec::new();
    for dev in crate::find_all_devices_by_hid(hid) {
        if !device_present(&dev.path) {
            continue;
        }
        let Ok(items) = crate::prt_crs::evaluate_crs_for(&dev.path) else {
            continue;
        };
        let Some(io_base) = io_base_of(&items) else {
            continue;
        };
        out.push(PnpDevice {
            path: dev.path,
            io_base: Some(io_base),
            irq: irq_of(&items),
        });
    }
    out
}

/// Whether the device at `device_path` is present per `_STA`
/// (ACPI 6.5 §6.1, bit 0).
///
/// No `_STA` object → present: the spec mandates that a device
/// without `_STA` is assumed present, enabled, shown, and
/// functioning, and Linux's `acpi_bus_get_status` makes the same
/// assumption. An `_STA` that exists but cannot be evaluated
/// (evaluator limitation, malformed return) is likewise treated
/// as present rather than silently dropping a device the
/// evaluator could not assess — the serial consumer already
/// tolerates absent hardware (its `init()` fails and the port
/// is skipped), so the fail-open direction only risks a
/// redundant probe, never a lost device.
fn device_present(device_path: &str) -> bool {
    match crate::prt_crs::evaluate_sta_for(device_path) {
        Ok(sta) => sta & crate::prt_crs::STA_DEVICE_PRESENT != 0,
        Err(_) => true,
    }
}

/// First `Io` (`min`) / `FixedIo` (`base`) descriptor in `_CRS`.
fn io_base_of(items: &[ResourceItem]) -> Option<u16> {
    for item in items {
        match item {
            ResourceItem::Io { min, .. } => return Some(*min),
            ResourceItem::FixedIo { base, .. } => return Some(*base),
            _ => {}
        }
    }
    None
}

/// First `Irq` (lowest set mask bit) / `ExtendedIrq` (first fitting GSI).
fn irq_of(items: &[ResourceItem]) -> Option<u8> {
    for item in items {
        match item {
            ResourceItem::Irq { mask, .. } => {
                if *mask != 0 {
                    return Some(mask.trailing_zeros() as u8);
                }
            }
            ResourceItem::ExtendedIrq { gsis, .. } => {
                for &gsi in gsis {
                    if let Ok(irq) = u8::try_from(gsi) {
                        return Some(irq);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

// ── Smokes ──────────────────────────────────────────────────────────────
//
// Fake-AML fixtures built with the same helpers as
// `strict_tests` (`package`/`device`): 2-byte PkgLength form.
// EISA encodings per ACPI 6.5 §5.6.7 (verified against
// `eisa_id_from_u32`): PNP0501 = 0x0105_D041.

/// 2-byte PkgLength form: `opcode | len | payload`.
fn pkg(opcode: &[u8], payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 2;
    assert!(length < 4096);
    let mut bytes = opcode.to_vec();
    bytes.push(0x40 | (length as u8 & 15));
    bytes.push((length >> 4) as u8);
    bytes.extend_from_slice(payload);
    bytes
}

/// `DeviceOp(name) { body }`.
fn device(name: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut payload = name.to_vec();
    payload.extend_from_slice(body);
    pkg(&[0x5B, 0x82], &payload)
}

/// `Name(_HID, <EISA integer>)` — the form real firmware uses
/// (QEMU: `Name (_HID, EisaId ("PNP0501"))`).
fn hid_name_eisa(eisa: u32) -> Vec<u8> {
    let mut v = alloc::vec![0x08, b'_', b'H', b'I', b'D', 0x0C];
    v.extend_from_slice(&eisa.to_le_bytes());
    v
}

/// `Name(_HID, "<string>")`.
fn hid_name_string(s: &str) -> Vec<u8> {
    let mut v = alloc::vec![0x08, b'_', b'H', b'I', b'D', 0x0D];
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

/// `Name(_CRS, Buffer(<size>) { <res_bytes> })`.
/// BufferOp PkgLength covers size-TermArg (2) + bytes + itself (1).
fn crs_name(res_bytes: &[u8]) -> Vec<u8> {
    let pkg_len = res_bytes.len() + 3;
    assert!(pkg_len < 0x40);
    let mut v = alloc::vec![0x08, b'_', b'C', b'R', b'S', 0x11];
    v.push(pkg_len as u8);
    v.push(0x0A); // BytePrefix: size TermArg
    v.push(res_bytes.len() as u8);
    v.extend_from_slice(res_bytes);
    v
}

/// COM-port resource template: IO desc (base) + IRQ desc (mask) + EndTag.
fn com_resources(base: u16, irq_mask: u16) -> Vec<u8> {
    alloc::vec![
        0x47,
        0x01, // IO desc, Decode16
        (base & 0xFF) as u8,
        (base >> 8) as u8,
        (base & 0xFF) as u8,
        (base >> 8) as u8,
        0x08,
        0x08, // alignment, length
        0x22, // IRQ desc
        (irq_mask & 0xFF) as u8,
        (irq_mask >> 8) as u8,
        0x79,
        0x00, // EndTag
    ]
}

/// COM-port template with a FixedIo descriptor instead of Io.
fn com_resources_fixed_io(base: u16, irq_mask: u16) -> Vec<u8> {
    alloc::vec![
        0x4B, // FixedIo desc
        (base & 0xFF) as u8,
        (base >> 8) as u8,
        0x08, // length
        0x22, // IRQ desc
        (irq_mask & 0xFF) as u8,
        (irq_mask >> 8) as u8,
        0x79,
        0x00, // EndTag
    ]
}

/// COM-port template with an ExtendedIrq descriptor instead of Irq.
fn com_resources_ext_irq(base: u16, gsi: u32) -> Vec<u8> {
    alloc::vec![
        0x47,
        0x01, // IO desc, Decode16
        (base & 0xFF) as u8,
        (base >> 8) as u8,
        (base & 0xFF) as u8,
        (base >> 8) as u8,
        0x08,
        0x08, // alignment, length
        0x89,
        0x06,
        0x00, // ExtendedIrq, payload len 6
        0x00, // flags
        0x01, // count
        (gsi & 0xFF) as u8,
        ((gsi >> 8) & 0xFF) as u8,
        ((gsi >> 16) & 0xFF) as u8,
        ((gsi >> 24) & 0xFF) as u8,
        0x79,
        0x00, // EndTag
    ]
}

/// Fake namespace with two PNP0501 UARTs (Io+Irq, FixedIo+Irq,
/// plus an ExtendedIrq one), a non-PNP0501 decoy, and a PNP0501
/// device with no `_CRS` at all.
fn fake_pnp0501_namespace() -> Vec<u8> {
    let mut body = Vec::new();
    let mut com1 = hid_name_eisa(0x0105_D041);
    com1.extend_from_slice(&crs_name(&com_resources(0x3F8, 0x0010)));
    body.extend_from_slice(&device(b"COM1", &com1));
    let mut com2 = hid_name_eisa(0x0105_D041);
    com2.extend_from_slice(&crs_name(&com_resources_fixed_io(0x2F8, 0x0008)));
    body.extend_from_slice(&device(b"COM2", &com2));
    let mut com4 = hid_name_eisa(0x0105_D041);
    com4.extend_from_slice(&crs_name(&com_resources_ext_irq(0x2E8, 4)));
    body.extend_from_slice(&device(b"COM4", &com4));
    let mut kbd = hid_name_string("PNP0303");
    kbd.extend_from_slice(&crs_name(&com_resources(0x0060, 0x0002)));
    body.extend_from_slice(&device(b"KBD0", &kbd));
    body.extend_from_slice(&device(b"COM3", &hid_name_eisa(0x0105_D041)));
    body
}

/// `pnp_devices("PNP0501")` finds all three UARTs with the right
/// base/irq, ignores the PNP0303 decoy, and drops the `_CRS`-less
/// PNP0501 device.
fn smoke_pnp_devices_finds_pnp0501() -> TestResult {
    crate::__reset_for_test();
    if crate::__parse_body_for_test(&fake_pnp0501_namespace(), "\\").is_err() {
        return TestResult::Fail("pnp: fake namespace parse failed");
    }
    let devs = pnp_devices("PNP0501");
    if devs.len() != 3 {
        return TestResult::Fail("pnp: expected 3 PNP0501 devices");
    }
    let expect: [(&str, u16, u8); 3] = [
        ("\\COM1", 0x3F8, 4),
        ("\\COM2", 0x2F8, 3),
        ("\\COM4", 0x2E8, 4),
    ];
    for (path, base, irq) in expect {
        let Some(d) = devs.iter().find(|d| d.path == path) else {
            return TestResult::Fail("pnp: expected device missing");
        };
        if d.io_base != Some(base) || d.irq != Some(irq) {
            return TestResult::Fail("pnp: base/irq mismatch");
        }
    }
    // The HID filter works both ways: the decoy is findable by its
    // own HID, so its absence from the PNP0501 result is a real
    // filter verdict, not a parse failure.
    let decoys = pnp_devices("PNP0303");
    if decoys.len() != 1 || decoys[0].path != "\\KBD0" {
        return TestResult::Fail("pnp: decoy not found by its own HID");
    }
    TestResult::Pass
}
kernel_test_in!("aml/pnp", smoke_pnp_devices_finds_pnp0501);

/// Empty / not-yet-built namespace: graceful empty result, no panic.
fn smoke_pnp_devices_empty_namespace() -> TestResult {
    crate::__reset_for_test();
    if !pnp_devices("PNP0501").is_empty() {
        return TestResult::Fail("pnp: empty namespace should yield no devices");
    }
    TestResult::Pass
}
kernel_test_in!("aml/pnp", smoke_pnp_devices_empty_namespace);

/// `Method(_STA, 0, NotSerialized) { Return(<imm>) }`.
/// Single-byte PkgLength form (total < 64): 1 (PkgLength) + 4
/// (name) + 1 (flags) + body (`ReturnOp` + immediate).
fn sta_method(imm: &[u8]) -> Vec<u8> {
    let mut body = alloc::vec![0xA4]; // ReturnOp
    body.extend_from_slice(imm);
    let pkg_len = 1 + 4 + 1 + body.len();
    let mut v = alloc::vec![0x14, pkg_len as u8, b'_', b'S', b'T', b'A', 0x00];
    v.extend_from_slice(&body);
    v
}

/// `Name(_STA, <integer literal>)`.
fn sta_name(imm: &[u8]) -> Vec<u8> {
    let mut v = alloc::vec![0x08, b'_', b'S', b'T', b'A'];
    v.extend_from_slice(imm);
    v
}

/// Fake namespace for the `_STA` filter: COM1 (Method `_STA`
/// returning 0x0F — present) and COM3 (Name `_STA` holding 0x0F —
/// present) are kept; COM2 (Method `_STA` returning 0) and COM4
/// (Name `_STA` holding 0) are dropped; COM6 (Method `_STA`
/// returning 0x0E — enabled/UI/functioning but present bit clear)
/// is dropped, pinning the "bit 0 only" rule; COM5 (no `_STA` at
/// all) is kept, pinning the assumed-present default.
fn fake_pnp0501_sta_namespace() -> Vec<u8> {
    let mut body = Vec::new();
    let mut com1 = hid_name_eisa(0x0105_D041);
    com1.extend_from_slice(&crs_name(&com_resources(0x3F8, 0x0010)));
    com1.extend_from_slice(&sta_method(&[0x0A, 0x0F])); // Return(Byte 0x0F)
    body.extend_from_slice(&device(b"COM1", &com1));
    let mut com2 = hid_name_eisa(0x0105_D041);
    com2.extend_from_slice(&crs_name(&com_resources(0x2F8, 0x0008)));
    com2.extend_from_slice(&sta_method(&[0x00])); // Return(Zero)
    body.extend_from_slice(&device(b"COM2", &com2));
    let mut com3 = hid_name_eisa(0x0105_D041);
    com3.extend_from_slice(&crs_name(&com_resources(0x2E8, 0x0010)));
    com3.extend_from_slice(&sta_name(&[0x0A, 0x0F])); // Name(_STA, 0x0F)
    body.extend_from_slice(&device(b"COM3", &com3));
    let mut com4 = hid_name_eisa(0x0105_D041);
    com4.extend_from_slice(&crs_name(&com_resources(0x3E8, 0x0008)));
    com4.extend_from_slice(&sta_name(&[0x00])); // Name(_STA, Zero)
    body.extend_from_slice(&device(b"COM4", &com4));
    let mut com5 = hid_name_eisa(0x0105_D041);
    com5.extend_from_slice(&crs_name(&com_resources(0x2E0, 0x0008)));
    body.extend_from_slice(&device(b"COM5", &com5));
    let mut com6 = hid_name_eisa(0x0105_D041);
    com6.extend_from_slice(&crs_name(&com_resources(0x2F0, 0x0008)));
    com6.extend_from_slice(&sta_method(&[0x0A, 0x0E])); // Return(Byte 0x0E)
    body.extend_from_slice(&device(b"COM6", &com6));
    body
}

/// `pnp_devices("PNP0501")` honors `_STA`: only the present
/// devices (COM1, COM3, COM5) are returned.
fn smoke_pnp_devices_honors_sta() -> TestResult {
    crate::__reset_for_test();
    if crate::__parse_body_for_test(&fake_pnp0501_sta_namespace(), "\\").is_err() {
        return TestResult::Fail("pnp: fake _STA namespace parse failed");
    }
    let devs = pnp_devices("PNP0501");
    if devs.len() != 3 {
        return TestResult::Fail("pnp: expected 3 present PNP0501 devices");
    }
    let expect: [(&str, u16, u8); 3] = [
        ("\\COM1", 0x3F8, 4),
        ("\\COM3", 0x2E8, 4),
        ("\\COM5", 0x2E0, 3),
    ];
    for (path, base, irq) in expect {
        let Some(d) = devs.iter().find(|d| d.path == path) else {
            return TestResult::Fail("pnp: expected present device missing");
        };
        if d.io_base != Some(base) || d.irq != Some(irq) {
            return TestResult::Fail("pnp: present device base/irq mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("aml/pnp", smoke_pnp_devices_honors_sta);
