//! `parse_devids` wire-layout smokes.
//!
//! `struct virtio_input_devids` is four little-endian u16s — bustype,
//! vendor, product, version (VirtIO §5.8, `virtio_input.h`) — and the
//! bustype is the device's own field, not a hardcoded BUS_VIRTUAL.
//! Reading the quartet one field early (vendor from the bustype slot)
//! shifts every identity the device publishes (EVIOCGID, sysfs/proc,
//! by-id names); these pin the true offsets against the QEMU
//! virtio-input ids and the absent-selector fallback.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::parse_devids;
use narf_input::evdev::{bus, InputId};

/// QEMU virtio-input device ids as raw little-endian config bytes:
/// bustype BUS_VIRTUAL (0x06), vendor 0x0627, product 0x0001,
/// version 0x0001.
const QEMU_DEVIDS: [u8; 8] = [0x06, 0x00, 0x27, 0x06, 0x01, 0x00, 0x01, 0x00];

/// The published InputId for the QEMU device is the wire quartet
/// field-for-field — in particular vendor is 0x0627 from bytes
/// [2..4], not the bustype 0x0006 sitting in bytes [0..2].
fn smoke_devids_parse_qemu_field_for_field() -> TestResult {
    let id = parse_devids(&QEMU_DEVIDS);
    if id.bustype != 0x06 {
        return TestResult::Fail("bustype not read from bytes [0..2]");
    }
    if id.vendor != 0x0627 {
        return TestResult::Fail("vendor not read from bytes [2..4]");
    }
    if id.product != 0x0001 {
        return TestResult::Fail("product not read from bytes [4..6]");
    }
    if id.version != 0x0001 {
        return TestResult::Fail("version not read from bytes [6..8]");
    }
    if id != InputId::new(0x06, 0x0627, 0x0001, 0x0001) {
        return TestResult::Fail("devids quartet mismatch");
    }
    TestResult::Pass
}

/// A device that does not publish ids (short or absent selector)
/// falls back to the synthetic identity. A 6-byte payload — the old
/// (vendor, product, version) read shape — must NOT be parsed as
/// ids; the full 8-byte quartet is required.
fn smoke_devids_absent_selector_falls_back_virtual() -> TestResult {
    let fallback = InputId::new(bus::VIRTUAL, 0, 0, 0);
    if parse_devids(&[]) != fallback {
        return TestResult::Fail("empty payload did not fall back to BUS_VIRTUAL/zeros");
    }
    if parse_devids(&QEMU_DEVIDS[..6]) != fallback {
        return TestResult::Fail("short payload did not fall back to BUS_VIRTUAL/zeros");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/virtio/input_pci",
    smoke_devids_parse_qemu_field_for_field
);
kernel_test_in!(
    "drivers/virtio/input_pci",
    smoke_devids_absent_selector_falls_back_virtual
);
