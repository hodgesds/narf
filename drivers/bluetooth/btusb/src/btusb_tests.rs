//! Kernel smokes for the USB Bluetooth (btusb) driver.
//!
//! Moved verbatim from `narf-drivers-usb`'s `tests.rs` when btusb became its
//! own dual-build crate; the test group names (`drivers/usb/btusb`) are
//! unchanged so existing `--subsystem` filters keep selecting them.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

// ── btusb ──────────────────────────────────────────────────────────

/// The USB-IF Wireless Controllers class triple for a Bluetooth
/// programming interface (Vol 4 Part B + USB-IF v1.0).
fn smoke_btusb_class_triple_constants() -> TestResult {
    use crate::btusb::{USB_CLASS_WIRELESS, USB_PROTOCOL_BLUETOOTH, USB_SUBCLASS_RF};
    if USB_CLASS_WIRELESS != 0xE0 || USB_SUBCLASS_RF != 0x01 || USB_PROTOCOL_BLUETOOTH != 0x01 {
        return TestResult::Fail("btusb class triple drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_class_triple_constants);

/// Build a synthetic Configuration Descriptor declaring a
/// 0xE0/0x01/0x01 interface with the three required endpoints —
/// interrupt-IN, bulk-IN, bulk-OUT — and check that `find_bt_endpoints`
/// extracts them in the right order. Wire layout per USB 2.0
/// §9.6.3 / §9.6.5 / §9.6.6 — the same shape btusb sees on attach.
fn smoke_btusb_find_endpoints_minimal_descriptor() -> TestResult {
    use crate::btusb::find_bt_endpoints;
    use crate::xhci::EndpointKind;

    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 3, 0xE0, 0x01, 0x01, 0]);
    // EP1 IN, interrupt — event endpoint (mps=16, bInterval=1).
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    // EP2 IN, bulk — ACL-IN (mps=64).
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    // EP2 OUT, bulk — ACL-OUT (mps=64).
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;

    let eps = match find_bt_endpoints(&cfg) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("find_bt_endpoints did not match"),
    };
    if eps.interface != 0 || eps.config_value != 1 {
        return TestResult::Fail("interface / configValue mismatch");
    }
    if eps.event_in.ep_addr != 0x81 || !matches!(eps.event_in.kind, EndpointKind::InterruptIn) {
        return TestResult::Fail("event-IN mis-identified");
    }
    if eps.acl_in.ep_addr != 0x82 || !matches!(eps.acl_in.kind, EndpointKind::BulkIn) {
        return TestResult::Fail("ACL-IN mis-identified");
    }
    if eps.acl_out.ep_addr != 0x02 || !matches!(eps.acl_out.kind, EndpointKind::BulkOut) {
        return TestResult::Fail("ACL-OUT mis-identified");
    }
    if eps.event_in.max_packet != 16 || eps.acl_in.max_packet != 64 {
        return TestResult::Fail("max-packet sizes did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_find_endpoints_minimal_descriptor
);

/// A configuration descriptor with a non-Bluetooth interface (e.g.
/// HID 0x03/0x01/0x01) must NOT match — returns `NotBluetooth`.
fn smoke_btusb_find_endpoints_rejects_non_bluetooth_interface() -> TestResult {
    use crate::btusb::{find_bt_endpoints, BtUsbError};
    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 1, 0x03, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x08, 0x00, 0x0A]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;
    match find_bt_endpoints(&cfg) {
        Err(BtUsbError::NotBluetooth) => TestResult::Pass,
        Ok(_) => TestResult::Fail("matched a non-Bluetooth interface"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_find_endpoints_rejects_non_bluetooth_interface
);

/// A Bluetooth interface missing its bulk-OUT endpoint must be
/// rejected — Stage 0 requires all three (event-IN + bulk-IN +
/// bulk-OUT) to build a usable transport.
fn smoke_btusb_find_endpoints_rejects_missing_bulk_out() -> TestResult {
    use crate::btusb::{find_bt_endpoints, BtUsbError};
    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 2, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;
    match find_bt_endpoints(&cfg) {
        Err(BtUsbError::NotBluetooth) => TestResult::Pass,
        Ok(_) => TestResult::Fail("matched without bulk-OUT"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_find_endpoints_rejects_missing_bulk_out
);

/// On QEMU's default TCG x86_64 there's no USB Bluetooth controller,
/// so `attached_count` should be 0 after the supervisor's enumeration
/// passes.
fn smoke_btusb_no_bluetooth_on_qemu() -> TestResult {
    if crate::btusb::attached_count() != 0 {
        return TestResult::Fail("btusb registry should be empty on QEMU TCG");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_no_bluetooth_on_qemu);

/// Build a synthetic Configuration Descriptor for a Bluetooth USB
/// adapter in the shape real adapters use (USB 2.0 §9.6.3 / §9.6.5 /
/// §9.6.6; Vol 4 Part B §2.1): interface 0 alt 0 carries the base
/// three endpoints (interrupt-IN events, bulk-IN/OUT ACL); each
/// further alternate adds an isoch IN/OUT pair at the SAME endpoint
/// addresses (0x83 IN / 0x03 OUT) with a growing `wMaxPacketSize`.
///
/// The sizes are test vectors chosen to exercise alternate
/// selection (9 / 17 / 25 bytes, including the 3-byte SCO header),
/// not a capture from a specific device.
fn btusb_cfg_with_sco_alts() -> alloc::vec::Vec<u8> {
    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    // Interface 0, alt 0, 3 endpoints — no isoch endpoints.
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 3, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    // Interface 0, alt 1, 5 endpoints — isoch pair, mps 9.
    cfg.extend_from_slice(&[9, 0x04, 0, 1, 5, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x83, 0x01, 0x09, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x03, 0x01, 0x09, 0x00, 0x01]);
    // Interface 0, alt 2, 5 endpoints — isoch pair, mps 17.
    cfg.extend_from_slice(&[9, 0x04, 0, 2, 5, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x83, 0x01, 0x11, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x03, 0x01, 0x11, 0x00, 0x01]);
    // Interface 0, alt 3, 5 endpoints — isoch pair, mps 25.
    cfg.extend_from_slice(&[9, 0x04, 0, 3, 5, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x83, 0x01, 0x19, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x03, 0x01, 0x19, 0x00, 0x01]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;
    cfg
}

/// `find_bt_endpoints` records the SCO isoch endpoints of every
/// alternate setting — addresses, kinds, max-packet sizes — while
/// the base three endpoints still resolve from alt 0, and
/// alternate selection picks the smallest sufficient budget (or
/// the largest, for the bind-time choice).
fn smoke_btusb_find_endpoints_records_sco_alts() -> TestResult {
    use crate::btusb::find_bt_endpoints;
    use crate::xhci::EndpointKind;

    let cfg = btusb_cfg_with_sco_alts();
    let eps = match find_bt_endpoints(&cfg) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("find_bt_endpoints did not match SCO descriptor"),
    };
    if eps.event_in.ep_addr != 0x81 || eps.acl_in.ep_addr != 0x82 || eps.acl_out.ep_addr != 0x02 {
        return TestResult::Fail("base endpoints mis-identified under SCO alts");
    }
    if eps.sco_alt_count() != 3 || !eps.has_sco() {
        return TestResult::Fail("expected 3 SCO alternates");
    }
    for (idx, (want_alt, want_mps)) in [(1u8, 9u16), (2, 17), (3, 25)].iter().enumerate() {
        let Some(alt) = eps.sco_alts[idx] else {
            return TestResult::Fail("missing SCO alternate");
        };
        if alt.alt_setting != *want_alt {
            return TestResult::Fail("SCO alternate number mismatch");
        }
        let (Some(sco_in), Some(sco_out)) = (alt.sco_in, alt.sco_out) else {
            return TestResult::Fail("SCO alternate missing a direction");
        };
        if sco_in.ep_addr != 0x83 || !matches!(sco_in.kind, EndpointKind::IsochIn) {
            return TestResult::Fail("SCO-IN mis-identified");
        }
        if sco_out.ep_addr != 0x03 || !matches!(sco_out.kind, EndpointKind::IsochOut) {
            return TestResult::Fail("SCO-OUT mis-identified");
        }
        if sco_in.max_packet != *want_mps || sco_out.max_packet != *want_mps {
            return TestResult::Fail("SCO max-packet did not round-trip");
        }
        if !alt.is_complete() || alt.packet_budget() != Some(*want_mps) {
            return TestResult::Fail("SCO alternate budget mismatch");
        }
    }
    // Smallest sufficient alternate for each payload size
    // (packet = payload + 3-byte SCO header).
    if eps.sco_alt_for_payload(6).map(|a| a.alt_setting) != Some(1) {
        return TestResult::Fail("6-byte SCO payload did not select alt 1");
    }
    if eps.sco_alt_for_payload(14).map(|a| a.alt_setting) != Some(2) {
        return TestResult::Fail("14-byte SCO payload did not select alt 2");
    }
    if eps.sco_alt_for_payload(22).map(|a| a.alt_setting) != Some(3) {
        return TestResult::Fail("22-byte SCO payload did not select alt 3");
    }
    if eps.sco_alt_for_payload(23).is_some() {
        return TestResult::Fail("oversize SCO payload selected an alternate");
    }
    // Bind-time choice: largest budget.
    if eps.best_sco_alt().map(|a| a.alt_setting) != Some(3) {
        return TestResult::Fail("bind-time SCO alternate is not alt 3");
    }
    if eps.best_sco_alt().and_then(|a| a.packet_budget()) != Some(25) {
        return TestResult::Fail("bind-time SCO budget mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_find_endpoints_records_sco_alts
);

/// The minimal Stage-0 descriptor (alt 0 only) still resolves, with
/// an empty SCO table: a device with no isoch endpoints binds for
/// ACL/events, and SCO is refused at the transport, not at discovery.
fn smoke_btusb_find_endpoints_no_sco_alts() -> TestResult {
    use crate::btusb::find_bt_endpoints;

    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 3, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;

    let eps = match find_bt_endpoints(&cfg) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("find_bt_endpoints did not match"),
    };
    if eps.sco_alt_count() != 0 || eps.has_sco() {
        return TestResult::Fail("alt-0-only descriptor reported SCO alternates");
    }
    if eps.best_sco_alt().is_some() || eps.sco_alt_for_payload(0).is_some() {
        return TestResult::Fail("no-SCO descriptor selected an alternate");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_find_endpoints_no_sco_alts);

/// A half-populated alternate (isoch-OUT but no isoch-IN) is
/// recorded so diagnostics can show what the device offered, but
/// is never selectable — SCO is bidirectional.
fn smoke_btusb_sco_partial_alt_not_selectable() -> TestResult {
    use crate::btusb::find_bt_endpoints;

    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 3, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    // Interface 0, alt 1 — isoch-OUT only, no isoch-IN.
    cfg.extend_from_slice(&[9, 0x04, 0, 1, 4, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    cfg.extend_from_slice(&[7, 0x05, 0x03, 0x01, 0x09, 0x00, 0x01]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;

    let eps = match find_bt_endpoints(&cfg) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("find_bt_endpoints did not match"),
    };
    if eps.sco_alt_count() != 1 {
        return TestResult::Fail("partial SCO alternate not recorded");
    }
    if eps.has_sco() || eps.best_sco_alt().is_some() || eps.sco_alt_for_payload(0).is_some() {
        return TestResult::Fail("half-populated SCO alternate treated as usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_sco_partial_alt_not_selectable
);

/// A transport with no isoch endpoints refuses every SCO operation
/// with `Unsupported` — without touching the xHC. The old code
/// answered `Ok(())` on `send_sco` by routing SCO to bulk-OUT.
fn smoke_btusb_sco_transport_fails_closed_without_isoch() -> TestResult {
    use crate::btusb::__test_transport_without_sco;
    use narf_bluetooth::transport::{HciTransport, TransportError};

    let t = __test_transport_without_sco(0, 1);
    if t.sco_available() || t.sco_alt_setting().is_some() {
        return TestResult::Fail("no-SCO transport reported SCO available");
    }
    if t.send_sco(&[0x01, 0x00, 0x02, 0x11, 0x22]) != Err(TransportError::Unsupported) {
        return TestResult::Fail("send_sco without isoch endpoints did not fail closed");
    }
    if t.recv_sco() != Err(TransportError::Unsupported) {
        return TestResult::Fail("recv_sco without isoch endpoints did not fail closed");
    }
    if t.select_sco_alt_setting(0) != Err(TransportError::Unsupported) {
        return TestResult::Fail("alt selection without isoch endpoints did not fail closed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_sco_transport_fails_closed_without_isoch
);

/// Scripted SCO conversation against the fixture descriptor: an
/// outbound `ScoData` packet is encoded, checked against the
/// selected alternate's isoch budget, and the same wire bytes are
/// decoded as the inbound packet — the send/recv framing the isoch
/// endpoints carry, without live hardware.
fn smoke_btusb_sco_packet_conversation() -> TestResult {
    use crate::btusb::find_bt_endpoints;
    use narf_bluetooth::hci::ScoData;

    let cfg = btusb_cfg_with_sco_alts();
    let eps = match find_bt_endpoints(&cfg) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("find_bt_endpoints did not match SCO descriptor"),
    };
    // Outbound: 6 payload bytes on handle 1, correct status.
    let mut payload: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    payload.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let out = ScoData {
        handle: 0x0001,
        packet_status: 0,
        data: payload,
    };
    let encoded = out.encode();
    if encoded.len() != 9 || encoded[0] != 0x01 || encoded[1] != 0x00 || encoded[2] != 0x06 {
        return TestResult::Fail("SCO packet header did not encode");
    }
    // Smallest fitting alternate is alt 1 (budget 9); the 9-byte
    // packet fits exactly, and the bind-time (largest) alternate
    // fits it with room.
    let Some(alt1) = eps.sco_alt_for_payload(6) else {
        return TestResult::Fail("no alternate fits the outbound SCO packet");
    };
    if alt1.alt_setting != 1 {
        return TestResult::Fail("outbound SCO packet picked the wrong alternate");
    }
    if encoded.len() > alt1.packet_budget().unwrap_or(0) as usize {
        return TestResult::Fail("outbound SCO packet exceeds its alternate's budget");
    }
    if encoded.len()
        > eps
            .best_sco_alt()
            .and_then(|a| a.packet_budget())
            .unwrap_or(0) as usize
    {
        return TestResult::Fail("outbound SCO packet exceeds the bind-time budget");
    }
    // Inbound: the same wire bytes arrive on isoch-IN; decode them.
    let inbound = match ScoData::decode(&encoded) {
        Some(p) => p,
        None => return TestResult::Fail("inbound SCO packet did not decode"),
    };
    if inbound.handle != 0x0001 || inbound.packet_status != 0 || inbound.data != out.data {
        return TestResult::Fail("inbound SCO packet contents mismatch");
    }
    // Oversize: a 23-byte payload needs 26 bytes on the wire and
    // fits no alternate — refused, never truncated.
    if eps.sco_alt_for_payload(23).is_some() {
        return TestResult::Fail("oversize SCO packet selected an alternate");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_sco_packet_conversation);

/// WCN6855 vendor version data is a fixed 20-byte little-endian record. The
/// multi-NVM flag combines chip/platform bytes into the board-specific suffix.
fn smoke_btusb_qca_version_and_board_id() -> TestResult {
    use crate::btusb_qca::QcaVersion;

    let mut raw = [0u8; 20];
    raw[0..4].copy_from_slice(&0x0013_0201u32.to_le_bytes());
    raw[4..8].copy_from_slice(&7u32.to_le_bytes());
    raw[8..12].copy_from_slice(&0x400C_1211u32.to_le_bytes());
    raw[12] = 0x01;
    raw[13] = 0x0A;
    raw[14..16].copy_from_slice(&0x8000u16.to_le_bytes());
    let Some(version) = QcaVersion::decode(&raw) else {
        return TestResult::Fail("WCN6855 version record did not decode");
    };
    if version.rom_version != 0x0013_0201 || version.board_id() != 0x010A {
        return TestResult::Fail("WCN6855 version or board ID decoded incorrectly");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_qca_version_and_board_id);

/// Runtime NVM selection includes both the GlobalFoundries variant and the
/// board ID, while the rampatch is selected only by ROM version.
fn smoke_btusb_qca_firmware_names() -> TestResult {
    use crate::btusb_qca::{firmware_names, QcaVersion};

    let names = firmware_names(QcaVersion {
        rom_version: 0x0013_0201,
        ram_version: 0x400C_1211,
        chip_id: 0x01,
        platform_id: 0x0A,
        flag: 0x8000,
        ..QcaVersion::default()
    });
    if names.rampatch != "qca/rampatch_usb_00130201.bin" {
        return TestResult::Fail("WCN6855 rampatch name is wrong");
    }
    if names.nvm != "qca/nvm_usb_00130201_gf_010a.bin" {
        return TestResult::Fail("WCN6855 NVM name is wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_qca_firmware_names);

/// The rampatch header embeds high/low ROM halves followed by the patch
/// revision. Reject a stale patch even when its ROM identity matches.
fn smoke_btusb_qca_rampatch_validation() -> TestResult {
    use crate::btusb_qca::{validate_rampatch_image, QcaError, QcaVersion};

    let version = QcaVersion {
        rom_version: 0x0013_0201,
        patch_version: 6,
        ..QcaVersion::default()
    };
    let mut image = [0u8; 40];
    image[16..18].copy_from_slice(&0x0013u16.to_le_bytes());
    image[18..20].copy_from_slice(&0x0201u16.to_le_bytes());
    image[20..22].copy_from_slice(&7u16.to_le_bytes());
    if validate_rampatch_image(&image, version).is_err() {
        return TestResult::Fail("valid WCN6855 rampatch header rejected");
    }
    image[20..22].copy_from_slice(&6u16.to_le_bytes());
    if validate_rampatch_image(&image, version) != Err(QcaError::FirmwareInvalid) {
        return TestResult::Fail("stale WCN6855 rampatch accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_qca_rampatch_validation);

/// HCI Command Complete retains its leading Status byte. Keep the USB
/// Stage-0 parser aligned with the shared Bluetooth controller parser.
fn smoke_btusb_local_version_skips_status() -> TestResult {
    use crate::btusb::{
        apply_bd_addr_return, apply_buffer_size_return, controller_info_from_version_return,
    };

    let ret = [
        0x00, // Status
        0x0C, // HCI version 5.3
        0x10, 0x00, // HCI revision 0x0010
        0x0C, // LMP version
        0xD7, 0x00, // Qualcomm company ID 0x00d7
        0x34, 0x12, // LMP subversion 0x1234
    ];
    let info = match controller_info_from_version_return(&ret) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("valid Read Local Version response rejected"),
    };
    if info.hci_version != 0x0C
        || info.hci_revision != 0x0010
        || info.manufacturer != 0x00D7
        || info.lmp_subversion != 0x1234
    {
        return TestResult::Fail("Read Local Version response shifted by status byte");
    }
    let mut info = info;
    if apply_bd_addr_return(&mut info, &[0, 1, 2, 3, 4, 5, 6]).is_err()
        || info.bd_addr != [1, 2, 3, 4, 5, 6]
    {
        return TestResult::Fail("Read BD_ADDR response decoded incorrectly");
    }
    if apply_buffer_size_return(&mut info, &[0, 0x40, 0x01, 0x20, 0x10, 0, 8, 0]).is_err()
        || info.acl_data_mtu != 0x0140
        || info.sco_data_mtu != 0x20
        || info.acl_total_num != 16
        || info.sco_total_num != 8
    {
        return TestResult::Fail("Read Buffer Size response decoded incorrectly");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_local_version_skips_status);

/// The transport's SCO paths are called from inside executor polls —
/// the HCI pump task's `pump_once` calls `recv_sco` every step — where
/// the halting `block_on` panics ("called from inside executor poll").
/// They poll a staged iso TD or bridge with `block_on_spin`, as the ACL
/// paths do, so each returns inside a task poll. The device is absent
/// (an idle slot), so every transfer fails fast.
fn smoke_btusb_sco_paths_run_inside_an_executor_poll() -> TestResult {
    use crate::btusb::__test_transport_with_sco;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_bluetooth::hci::Event;
    use narf_bluetooth::transport::HciTransport;

    let Some(c) = crate::xhci::first_controller() else {
        return TestResult::Skip("no xHCI controller");
    };
    let slot = c.max_slots();
    if c.device_generation(slot).is_some() {
        return TestResult::Skip("no idle slot");
    }
    let t = Arc::new(__test_transport_with_sco(c.id(), slot));
    // A SCO link is up, so `recv_sco` stages an iso-IN TD.
    t.__test_note_event(&Event {
        code: 0x2c,
        params: alloc::vec![0, 0x40, 0x00, 1, 2, 3, 4, 5, 6, 0x02, 0, 0, 0, 0, 0, 0, 0],
    });
    let done = Arc::new(AtomicUsize::new(0));
    {
        let t = t.clone();
        let done = done.clone();
        let _ = narf_scheduler::spawn(async move {
            let _ = t.recv_sco();
            let _ = t.send_sco(&[0x40, 0x00, 1, 0xAA]);
            // Switching down to alt 2 issues SET_INTERFACE.
            let _ = t.select_sco_alt_setting(0);
            done.store(1, Ordering::Release);
        });
    }
    let finished = narf_scheduler::responsive_spin_until(
        || {
            let _ = narf_scheduler::poll_one_round();
            done.load(Ordering::Acquire) == 1
        },
        narf_time::Deadline::after_ms(3_000),
    );
    if !finished {
        return TestResult::Fail("SCO transport calls did not return inside an executor poll");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb/sco",
    smoke_btusb_sco_paths_run_inside_an_executor_poll
);
