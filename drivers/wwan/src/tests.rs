// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/tests.rs — WWAN Stage-0/1 smoke tests

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    WwanPortKind,
    iosm::{IOSM_PCI_DEVICES, IPC_DOORBELL_CH_OFFSET, INTEL_CP_DEVICE_7560_ID, INTEL_CP_DEVICE_7360_ID, PCI_VENDOR_INTEL},
    mbim::{
        self, MbimHeader, MbimMessageType,
        MBIM_HEADER_SIZE, MBIM_OPEN, MBIM_COMMAND_MSG, MBIM_OPEN_MSG_LEN,
    },
    qmi::{QmiHeader, QMUX_IF_TYPE, QMUX_FLAGS_SENDER_HOST, QMUX_HEADER_SIZE, QMI_SVC_CTL},
};

// ─── Smoke 1: MBIM message header encode (type + length + tx-id) ─────────────
//
// MBIM 1.0 §10.3.1: MessageType, MessageLength, TransactionId are all
// little-endian u32.  An MBIM_OPEN header with length=16, tx_id=1 must
// produce exact bytes:
//   [01 00 00 00]  MessageType = 0x0000_0001
//   [10 00 00 00]  MessageLength = 16
//   [01 00 00 00]  TransactionId = 1

fn smoke_mbim_header_encode() -> TestResult {
    let hdr = MbimHeader {
        message_type:   MbimMessageType::Open,
        message_length: 16,
        transaction_id: 1,
    };
    let wire = hdr.encode();

    // Check MessageType bytes
    if wire[0..4] != [0x01, 0x00, 0x00, 0x00] {
        return TestResult::Fail("MessageType bytes mismatch");
    }
    // Check MessageLength bytes
    if wire[4..8] != [0x10, 0x00, 0x00, 0x00] {
        return TestResult::Fail("MessageLength bytes mismatch (expected 16 LE)");
    }
    // Check TransactionId bytes
    if wire[8..12] != [0x01, 0x00, 0x00, 0x00] {
        return TestResult::Fail("TransactionId bytes mismatch");
    }
    if wire.len() != MBIM_HEADER_SIZE {
        return TestResult::Fail("encoded length is not 12");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_header_encode);

// ─── Smoke 2: MBIM_OPEN command shape ────────────────────────────────────────
//
// build_open() must return a 16-byte packet whose first 4 bytes are
// MBIM_OPEN (0x0000_0001, LE), bytes 4..8 are 0x10000000 (16 LE), and
// bytes 12..16 carry the MaxControlTransfer value (4096 = 0x1000 LE).

fn smoke_mbim_open_shape() -> TestResult {
    let pkt = mbim::build_open(/*tx_id=*/1, /*max_ctrl_xfer=*/4096);

    if pkt.len() != MBIM_OPEN_MSG_LEN as usize {
        return TestResult::Fail("MBIM_OPEN packet is not 16 bytes");
    }

    // MessageType = MBIM_OPEN = 0x0000_0001 LE
    let msg_type = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
    if msg_type != MBIM_OPEN {
        return TestResult::Fail("MessageType is not MBIM_OPEN");
    }

    // MessageLength = 16
    let msg_len = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if msg_len != 16 {
        return TestResult::Fail("MessageLength should be 16");
    }

    // MaxControlTransfer = 4096 = 0x00001000 LE
    let max_xfer = u32::from_le_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    if max_xfer != 4096 {
        return TestResult::Fail("MaxControlTransfer mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_open_shape);

// ─── Smoke 3: QMI control message header encode (svc + flags + tx-id + msg-id + tlv-count) ─

fn smoke_qmi_ctl_header_encode() -> TestResult {
    let hdr = QmiHeader {
        if_type:    QMUX_IF_TYPE,
        length:     (QMUX_HEADER_SIZE - 1) as u16, // 11
        flags:      QMUX_FLAGS_SENDER_HOST,
        service_id: QMI_SVC_CTL,
        client_id:  0x00,
        tx_id:      0x0042,
        msg_id:     0x0021, // QMI_CTL_GET_VERSION_INFO
        tlv_length: 0x0000,
    };
    let wire = hdr.encode();

    if wire.len() != QMUX_HEADER_SIZE {
        return TestResult::Fail("encoded length is not 12");
    }
    if wire[0] != QMUX_IF_TYPE {
        return TestResult::Fail("if_type byte mismatch");
    }
    if wire[3] != QMUX_FLAGS_SENDER_HOST {
        return TestResult::Fail("flags byte mismatch");
    }
    if wire[4] != QMI_SVC_CTL {
        return TestResult::Fail("service_id mismatch");
    }
    if wire[5] != 0x00 {
        return TestResult::Fail("client_id mismatch");
    }

    let tx_id = u16::from_le_bytes([wire[6], wire[7]]);
    if tx_id != 0x0042 {
        return TestResult::Fail("tx_id mismatch");
    }

    let msg_id = u16::from_le_bytes([wire[8], wire[9]]);
    if msg_id != 0x0021 {
        return TestResult::Fail("msg_id mismatch");
    }

    let tlv_len = u16::from_le_bytes([wire[10], wire[11]]);
    if tlv_len != 0 {
        return TestResult::Fail("tlv_length should be 0");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_qmi_ctl_header_encode);

// ─── Smoke 4: WwanPortKind enum exhaustive match ──────────────────────────────
//
// Verifies that every variant of WwanPortKind is matchable and maps to an
// expected string tag.  If a new variant is added without updating this test
// the compiler will produce an unreachable-pattern or non-exhaustive error.

fn smoke_port_kind_exhaustive() -> TestResult {
    let kinds = [
        WwanPortKind::AtCmd,
        WwanPortKind::Mbim,
        WwanPortKind::Qmi,
        WwanPortKind::Data,
    ];
    let expected_names = ["AtCmd", "Mbim", "Qmi", "Data"];

    for (kind, expected) in kinds.iter().zip(expected_names.iter()) {
        // Exhaustive match — compiler errors if a variant is missing.
        let name = match kind {
            WwanPortKind::AtCmd => "AtCmd",
            WwanPortKind::Mbim  => "Mbim",
            WwanPortKind::Qmi   => "Qmi",
            WwanPortKind::Data  => "Data",
        };
        if name != *expected {
            return TestResult::Fail("WwanPortKind name mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_port_kind_exhaustive);

// ─── Smoke 5: IOSM PCI device-ID table (Intel 7560 / 7360) ───────────────────
//
// Asserts the static table contains the two known Intel XMM device IDs and
// that the vendor field is PCI_VENDOR_INTEL (0x8086).

fn smoke_iosm_pci_device_ids() -> TestResult {
    if IOSM_PCI_DEVICES.len() < 2 {
        return TestResult::Fail("IOSM_PCI_DEVICES must have at least 2 entries");
    }

    let has_7560 = IOSM_PCI_DEVICES.iter().any(|d| {
        d.vendor == PCI_VENDOR_INTEL && d.device == INTEL_CP_DEVICE_7560_ID
    });
    if !has_7560 {
        return TestResult::Fail("XMM 7560 (0x7560) missing from IOSM_PCI_DEVICES");
    }

    let has_7360 = IOSM_PCI_DEVICES.iter().any(|d| {
        d.vendor == PCI_VENDOR_INTEL && d.device == INTEL_CP_DEVICE_7360_ID
    });
    if !has_7360 {
        return TestResult::Fail("XMM 7360 (0x7360) missing from IOSM_PCI_DEVICES");
    }

    // Sanity: doorbell offset must be 32 (BIT(5)).
    if IPC_DOORBELL_CH_OFFSET != 32 {
        return TestResult::Fail("IPC_DOORBELL_CH_OFFSET should be 32");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_iosm_pci_device_ids);

// ─── Bonus: MBIM header decode round-trip ────────────────────────────────────

fn smoke_mbim_header_roundtrip() -> TestResult {
    let original = MbimHeader {
        message_type:   MbimMessageType::CommandDone,
        message_length: 100,
        transaction_id: 0xDEAD_BEEF,
    };
    let wire = original.encode();
    let decoded = match MbimHeader::decode(&wire) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("decode failed"),
    };
    if decoded != original {
        return TestResult::Fail("header round-trip mismatch");
    }
    // Also verify MbimMessageType::from_raw round-trips through MBIM_COMMAND_MSG.
    if MbimMessageType::from_raw(MBIM_COMMAND_MSG).to_raw() != MBIM_COMMAND_MSG {
        return TestResult::Fail("MbimMessageType::CommandMsg raw round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_header_roundtrip);

// ─── Bonus: QMI header decode round-trip ─────────────────────────────────────

fn smoke_qmi_header_roundtrip() -> TestResult {
    let original = QmiHeader {
        if_type:    QMUX_IF_TYPE,
        length:     11,
        flags:      QMUX_FLAGS_SENDER_HOST,
        service_id: 0x01, // WDS
        client_id:  0x05,
        tx_id:      0x1234,
        msg_id:     0x0020,
        tlv_length: 0,
    };
    let wire = original.encode();
    let decoded = match QmiHeader::decode(&wire) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("QMI header decode failed"),
    };
    if decoded != original {
        return TestResult::Fail("QMI header round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_qmi_header_roundtrip);
