// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/nfc/src/tests.rs — NCI Stage-0 smoke tests

use alloc::{vec, vec::Vec};
use core::cell::RefCell;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    core_reset, rf_discover, CoreInitResponse, NciHeader, NciMessage, NfcError, NfcTransport,
    RfDiscoverEntry, NCI_GID_CORE, NCI_GID_RF_MGMT, NCI_MT_CMD, NCI_MT_NTF, NCI_MT_RSP,
    NCI_NFC_A_PASSIVE_POLL_MODE, NCI_NFC_B_PASSIVE_POLL_MODE, NCI_OID_CORE_INIT,
    NCI_OID_CORE_RESET, NCI_OID_RF_DISCOVER, NCI_RESET_RESET_CONFIG, NCI_STATUS_OK,
};

// ─── Loopback transport ───────────────────────────────────────────────────────

/// Simple loopback transport for tests.
/// `write()` discards bytes; `read()` drains from a pre-loaded queue.
#[allow(dead_code)]
struct LoopbackTransport {
    rx_queue: RefCell<Vec<u8>>,
}

#[allow(dead_code)]
impl LoopbackTransport {
    fn new() -> Self {
        Self {
            rx_queue: RefCell::new(Vec::new()),
        }
    }

    fn enqueue(&self, bytes: &[u8]) {
        self.rx_queue.borrow_mut().extend_from_slice(bytes);
    }
}

impl NfcTransport for LoopbackTransport {
    fn write(&self, _bytes: &[u8]) -> Result<(), NfcError> {
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, NfcError> {
        let mut q = self.rx_queue.borrow_mut();
        let n = buf.len().min(q.len());
        let drained: Vec<u8> = q.drain(..n).collect();
        buf[..n].copy_from_slice(&drained);
        Ok(n)
    }

    fn irq_high(&self) -> bool {
        !self.rx_queue.borrow().is_empty()
    }
}

// ─── Smoke 1: NCI header encode — MT/PBF/GID byte at offset 0 ─────────────

fn smoke_nci_header_encode() -> TestResult {
    // CORE_RESET_CMD: MT=CMD(1), PBF=false, GID=CORE(0), OID=0x00, len=1
    // byte 0: (0b001 << 5) | 0 | 0 = 0x20
    let hdr = NciHeader {
        mt: NCI_MT_CMD,
        pbf: false,
        gid: NCI_GID_CORE,
        oid: NCI_OID_CORE_RESET,
        length: 1,
    };
    let wire = hdr.encode();
    if wire[0] != 0x20 {
        return TestResult::Fail("byte 0 (MT|PBF|GID) mismatch");
    }
    if wire[1] != NCI_OID_CORE_RESET {
        return TestResult::Fail("byte 1 (OID) mismatch");
    }
    if wire[2] != 1 {
        return TestResult::Fail("byte 2 (length) mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nfc", smoke_nci_header_encode);

// ─── Smoke 2: NCI header decode round-trip ────────────────────────────────

fn smoke_nci_header_roundtrip() -> TestResult {
    // MT=NTF(3), PBF=true, GID=RF_MGMT(1), OID=RF_DISCOVER(3), len=0x42
    // byte 0: (0b011<<5)|(1<<4)|0b0001 = 0x60|0x10|0x01 = 0x71
    let original = NciHeader {
        mt: NCI_MT_NTF,
        pbf: true,
        gid: NCI_GID_RF_MGMT,
        oid: NCI_OID_RF_DISCOVER,
        length: 0x42,
    };
    let wire = original.encode();
    if wire[0] != 0x71 {
        return TestResult::Fail("byte 0 encoding incorrect (expected 0x71)");
    }
    let decoded = match NciHeader::decode(&wire) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("decode failed"),
    };
    if decoded != original {
        return TestResult::Fail("header round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nfc", smoke_nci_header_roundtrip);

// ─── Smoke 3: CORE_RESET command encoder ─────────────────────────────────

fn smoke_core_reset_encoder() -> TestResult {
    let msg = core_reset(NCI_RESET_RESET_CONFIG);
    if msg.mt != NCI_MT_CMD {
        return TestResult::Fail("wrong MT");
    }
    if msg.gid != NCI_GID_CORE {
        return TestResult::Fail("wrong GID");
    }
    if msg.oid != NCI_OID_CORE_RESET {
        return TestResult::Fail("wrong OID");
    }
    if msg.payload != vec![NCI_RESET_RESET_CONFIG] {
        return TestResult::Fail("wrong payload");
    }
    let wire = msg.encode();
    if wire.len() != 4 {
        return TestResult::Fail("wire length should be 4");
    }
    if wire[0] != 0x20 {
        return TestResult::Fail("byte 0: expected 0x20 (MT=CMD, PBF=0, GID=CORE)");
    }
    if wire[2] != 1 {
        return TestResult::Fail("byte 2: payload len should be 1");
    }
    if wire[3] != NCI_RESET_RESET_CONFIG {
        return TestResult::Fail("payload[0]: wrong reset_type");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nfc", smoke_core_reset_encoder);

// ─── Smoke 4: CORE_INIT response decode ──────────────────────────────────
//
// NCI 1.0 §4.1.4 CORE_INIT_RSP minimum payload (12 bytes):
//   [0]    Status
//   [1-4]  NFCC Features  (byte 1 = NCI version, e.g. 0x10 for v1.0)
//   [5]    Max Logical Connections
//   [6-7]  Max Routing Table Size
//   [8]    Max Ctrl Pkt Payload Size
//   [9-10] Max Size for Large Parameters
//   [11]   Manufacturer ID
//   [12..] Manufacturer Specific Info

fn smoke_core_init_response_decode() -> TestResult {
    let payload: Vec<u8> = vec![
        NCI_STATUS_OK, // [0]  Status
        0x10,          // [1]  NCI version 1.0
        0x00,          // [2]
        0x00,          // [3]
        0x00,          // [4]  end of NFCC Features
        0x03,          // [5]  Max Logical Connections
        0x00,
        0x01, // [6-7] Max Routing Table Size
        0xFF, // [8]  Max Ctrl Pkt Payload Size
        0x00,
        0x00, // [9-10] Max Size for Large Parameters
        0xAB, // [11] Manufacturer ID
        0xDE,
        0xAD, // [12-13] Manufacturer Specific Info
    ];
    let msg = NciMessage {
        mt: NCI_MT_RSP,
        pbf: false,
        gid: NCI_GID_CORE,
        oid: NCI_OID_CORE_INIT,
        payload,
    };
    let rsp = match CoreInitResponse::from_message(&msg) {
        Ok(r) => r,
        Err(_e) => return TestResult::Fail("CORE_INIT_RSP decode failed"),
    };
    if rsp.status != NCI_STATUS_OK {
        return TestResult::Fail("status not OK");
    }
    if rsp.nci_version != 0x10 {
        return TestResult::Fail("nci_version mismatch (expected 0x10 for v1.0)");
    }
    if rsp.manufacturer_id != 0xAB {
        return TestResult::Fail("manufacturer_id mismatch");
    }
    if rsp.manufacturer_specific != vec![0xDE, 0xAD] {
        return TestResult::Fail("manufacturer_specific mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nfc", smoke_core_init_response_decode);

// ─── Smoke 5: RF_DISCOVER command encoder ────────────────────────────────
//
// byte 0 for RF_MGMT CMD: MT=CMD(1)<<5 | GID=RF_MGMT(1) = 0x20|0x01 = 0x21

fn smoke_rf_discover_encoder() -> TestResult {
    let entries = vec![
        RfDiscoverEntry {
            rf_tech_mode: NCI_NFC_A_PASSIVE_POLL_MODE,
            frequency: 1,
        },
        RfDiscoverEntry {
            rf_tech_mode: NCI_NFC_B_PASSIVE_POLL_MODE,
            frequency: 1,
        },
    ];
    let msg = rf_discover(&entries);
    if msg.mt != NCI_MT_CMD {
        return TestResult::Fail("wrong MT");
    }
    if msg.gid != NCI_GID_RF_MGMT {
        return TestResult::Fail("wrong GID");
    }
    if msg.oid != NCI_OID_RF_DISCOVER {
        return TestResult::Fail("wrong OID");
    }
    if msg.payload.len() != 5 {
        return TestResult::Fail("payload length should be 5");
    }
    if msg.payload[0] != 2 {
        return TestResult::Fail("num_entries should be 2");
    }
    if msg.payload[1] != NCI_NFC_A_PASSIVE_POLL_MODE {
        return TestResult::Fail("entry[0] tech_mode mismatch");
    }
    if msg.payload[3] != NCI_NFC_B_PASSIVE_POLL_MODE {
        return TestResult::Fail("entry[1] tech_mode mismatch");
    }
    let wire = msg.encode();
    if wire[0] != 0x21 {
        return TestResult::Fail("byte 0: expected 0x21 (MT=CMD|GID=RF_MGMT)");
    }
    if wire[2] != 5 {
        return TestResult::Fail("wire payload length field should be 5");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nfc", smoke_rf_discover_encoder);
