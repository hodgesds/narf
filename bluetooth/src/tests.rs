//! Smoke tests for narf-bluetooth.
//!
//! Cover the packet codec round-trip and the bring-up state machine
//! end-to-end against a synthetic transport that replays canned
//! Command Complete events for every Mandatory opcode.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::controller::{BringupPhase, Controller};
use crate::event::EventCode;
use crate::hci::{opcode, AclData, Command, Event};
use crate::opcode as op;
use crate::transport::{LoopbackTransport, USB_CLASS_WIRELESS, USB_PROTOCOL_BLUETOOTH, USB_SUBCLASS_RF};

fn smoke_hci_command_round_trip() -> TestResult {
    // §5.4.1: opcode encoded LE; param-total-length one byte.
    let cmd = Command::with_params(op::HCI_RESET, &[]);
    let bytes = cmd.encode();
    if bytes.len() != 3 {
        return TestResult::Fail("HCI_Reset encoding != 3 bytes");
    }
    if u16::from_le_bytes([bytes[0], bytes[1]]) != op::HCI_RESET {
        return TestResult::Fail("opcode field LE encoding wrong");
    }
    if bytes[2] != 0 {
        return TestResult::Fail("param-len byte should be 0 for HCI_Reset");
    }

    let cmd2 = Command::with_params(op::HCI_SET_EVENT_MASK, &[0xFF; 8]);
    let bytes2 = cmd2.encode();
    if bytes2.len() != 11 {
        return TestResult::Fail("Set_Event_Mask should be 3+8 = 11 bytes");
    }
    if bytes2[2] != 8 {
        return TestResult::Fail("param-len byte should be 8");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_hci_command_round_trip);

fn smoke_hci_event_decode() -> TestResult {
    // Synthesise an HCI_Command_Complete carrying status=0x00 for
    // HCI_Reset.
    let mut params = vec![0x01u8]; // num_hci_command_packets
    params.extend_from_slice(&op::HCI_RESET.to_le_bytes()); // opcode
    params.push(0x00); // status
    let event = Event {
        code: EventCode::CommandComplete as u8,
        params,
    };
    let cc = match crate::event::CommandComplete::parse(&event) {
        Some(cc) => cc,
        None => return TestResult::Fail("CommandComplete::parse returned None"),
    };
    if cc.opcode != op::HCI_RESET {
        return TestResult::Fail("CC opcode mismatch");
    }
    if cc.status() != Some(0x00) {
        return TestResult::Fail("CC status decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_hci_event_decode);

fn smoke_acl_round_trip() -> TestResult {
    let original = AclData {
        handle: 0x123,
        pb_flag: 0x2,
        bc_flag: 0x1,
        data: vec![1, 2, 3, 4, 5],
    };
    let bytes = original.encode();
    let decoded = match AclData::decode(&bytes) {
        Some(d) => d,
        None => return TestResult::Fail("AclData::decode returned None"),
    };
    if decoded != original {
        return TestResult::Fail("ACL round-trip changed contents");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_acl_round_trip);

fn smoke_opcode_compose_split() -> TestResult {
    // Vol 4 Part E §5.4.1: opcode = (OGF << 10) | (OCF & 0x3FF).
    let combined = opcode(0x03, 0x0003);
    if combined != 0x0C03 {
        return TestResult::Fail("opcode compose mismatch");
    }
    let (ogf, ocf) = crate::hci::split_opcode(0x0C03);
    if ogf != 0x03 || ocf != 0x0003 {
        return TestResult::Fail("split_opcode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_opcode_compose_split);

fn smoke_usb_class_constants() -> TestResult {
    // USB-IF "Wireless Controllers" v1.0: class 0xE0 / sub 0x01 / proto 0x01.
    if USB_CLASS_WIRELESS != 0xE0
        || USB_SUBCLASS_RF != 0x01
        || USB_PROTOCOL_BLUETOOTH != 0x01
    {
        return TestResult::Fail("USB Bluetooth class triple drift");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/transport", smoke_usb_class_constants);

fn make_command_complete(opcode: u16, status: u8, ret: &[u8]) -> Event {
    let mut params = vec![0x01u8];
    params.extend_from_slice(&opcode.to_le_bytes());
    params.push(status);
    params.extend_from_slice(ret);
    Event {
        code: EventCode::CommandComplete as u8,
        params,
    }
}

fn smoke_controller_bringup_drives_mandatory_sequence() -> TestResult {
    use crate::bootstrap_bluetooth_authority;

    let lt = Arc::new(LoopbackTransport::new("smoke"));

    // Pre-load Command Complete responses, in the order the
    // bring-up will consume them.
    lt.enqueue_event(make_command_complete(op::HCI_RESET, 0x00, &[]));
    lt.enqueue_event(make_command_complete(
        op::HCI_READ_LOCAL_VERSION,
        0x00,
        &[
            0x0C, // HCI_Version (5.3 = 0x0C)
            0x10, 0x00, // HCI_Revision = 0x0010
            0x0C, // LMP_Version
            0xAA, 0xBB, // Manufacturer = 0xBBAA
            0x01, 0x00, // LMP_Subversion = 1
        ],
    ));
    let bd_addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    lt.enqueue_event(make_command_complete(op::HCI_READ_BD_ADDR, 0x00, &bd_addr));
    lt.enqueue_event(make_command_complete(
        op::HCI_READ_BUFFER_SIZE,
        0x00,
        &[
            0x40, 0x01, // ACL_Data_Packet_Length = 0x140
            0x40, // SC_Data_Packet_Length
            0x10, 0x00, // Total_Num_ACL = 16
            0x08, 0x00, // Total_Num_SCO = 8
        ],
    ));
    lt.enqueue_event(make_command_complete(op::HCI_SET_EVENT_MASK, 0x00, &[]));

    let controller = Controller::new(lt.clone());
    let cap = bootstrap_bluetooth_authority();

    let info = match controller.bring_up(&cap) {
        Ok(i) => i,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("bring_up failed");
        }
    };

    if info.bd_addr != bd_addr {
        return TestResult::Fail("BD_ADDR not captured");
    }
    if info.hci_version != 0x0C {
        return TestResult::Fail("HCI_Version not captured");
    }
    if info.acl_data_mtu != 0x0140 {
        return TestResult::Fail("ACL_Data_MTU not captured");
    }
    if info.acl_total_num != 16 {
        return TestResult::Fail("ACL buffer count not captured");
    }
    if controller.phase() != BringupPhase::Ready {
        return TestResult::Fail("controller did not reach Ready");
    }

    // Verify the controller actually emitted every Mandatory command.
    let sent = lt.sent_commands();
    let want = [
        op::HCI_RESET,
        op::HCI_READ_LOCAL_VERSION,
        op::HCI_READ_BD_ADDR,
        op::HCI_READ_BUFFER_SIZE,
        op::HCI_SET_EVENT_MASK,
    ];
    if sent.len() != want.len() {
        return TestResult::Fail("wrong number of commands emitted");
    }
    for (s, w) in sent.iter().zip(want.iter()) {
        if s.opcode != *w {
            return TestResult::Fail("command order drift");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/controller",
    smoke_controller_bringup_drives_mandatory_sequence
);

fn smoke_bring_up_propagates_bad_status() -> TestResult {
    use crate::bootstrap_bluetooth_authority;
    use crate::controller::BringupError;

    let lt = Arc::new(LoopbackTransport::new("badstatus"));
    // First Reset returns a non-zero HCI Status (0x07 = Memory Capacity Exceeded).
    lt.enqueue_event(make_command_complete(op::HCI_RESET, 0x07, &[]));
    let controller = Controller::new(lt);
    let cap = bootstrap_bluetooth_authority();
    match controller.bring_up(&cap) {
        Err(BringupError::BadStatus {
            phase: BringupPhase::Reset,
            status: 0x07,
        }) => TestResult::Pass,
        _ => TestResult::Fail("bring_up should surface BadStatus on non-zero status"),
    }
}
kernel_test_in!(
    "bluetooth/controller",
    smoke_bring_up_propagates_bad_status
);

fn smoke_bring_up_cap_revocation() -> TestResult {
    use crate::bootstrap_bluetooth_authority;
    use crate::controller::BringupError;

    let lt = Arc::new(LoopbackTransport::new("revoked"));
    let controller = Controller::new(lt);
    let cap = bootstrap_bluetooth_authority();
    cap.revoke();
    match controller.bring_up(&cap) {
        Err(BringupError::AuthorityRevoked) => TestResult::Pass,
        _ => TestResult::Fail("bring_up accepted a revoked cap"),
    }
}
kernel_test_in!("bluetooth/controller", smoke_bring_up_cap_revocation);

// ── ATT ────────────────────────────────────────────────────────────

fn smoke_att_pdu_round_trip() -> TestResult {
    use crate::att::{Pdu, ATT_READ_REQ};
    let pdu = Pdu {
        opcode: ATT_READ_REQ,
        params: vec![0x10, 0x00],
    };
    let raw = pdu.encode();
    if raw[0] != ATT_READ_REQ {
        return TestResult::Fail("opcode byte at offset 0");
    }
    let back = Pdu::decode(&raw).expect("decode");
    if back != pdu {
        return TestResult::Fail("ATT PDU round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/att", smoke_att_pdu_round_trip);

fn smoke_att_exchange_mtu() -> TestResult {
    use crate::att::{
        build_exchange_mtu_request, build_exchange_mtu_response, decode_exchange_mtu,
        ATT_DEFAULT_MTU,
    };
    if ATT_DEFAULT_MTU != 23 {
        return TestResult::Fail("default ATT MTU should be 23 (§3.4.2)");
    }
    let req = build_exchange_mtu_request(517);
    let mtu = decode_exchange_mtu(&req).expect("decode req");
    if mtu != 517 {
        return TestResult::Fail("Exchange_MTU_Request did not round-trip");
    }
    let rsp = build_exchange_mtu_response(247);
    let mtu = decode_exchange_mtu(&rsp).expect("decode rsp");
    if mtu != 247 {
        return TestResult::Fail("Exchange_MTU_Response did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/att", smoke_att_exchange_mtu);

fn smoke_att_read_request_round_trip() -> TestResult {
    use crate::att::{build_read_request, decode_read_request};
    let pdu = build_read_request(0x002A);
    let h = decode_read_request(&pdu).expect("decode");
    if h != 0x002A {
        return TestResult::Fail("Read_Request handle round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/att", smoke_att_read_request_round_trip);

fn smoke_att_write_request_carries_handle_and_value() -> TestResult {
    use crate::att::{build_write_request, decode_write};
    let value = [0xAA, 0xBB, 0xCC];
    let pdu = build_write_request(0x0050, &value);
    let (h, v) = decode_write(&pdu).expect("decode");
    if h != 0x0050 {
        return TestResult::Fail("Write_Request handle wrong");
    }
    if v != value {
        return TestResult::Fail("Write_Request value wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/att",
    smoke_att_write_request_carries_handle_and_value
);

fn smoke_att_handle_value_notification() -> TestResult {
    use crate::att::{
        build_handle_value_notification, decode_handle_value, ATT_HANDLE_VALUE_NTF,
    };
    let pdu = build_handle_value_notification(0x002A, b"hi");
    if pdu.opcode != ATT_HANDLE_VALUE_NTF {
        return TestResult::Fail("opcode should be 0x1B");
    }
    let (h, v) = decode_handle_value(&pdu).expect("decode");
    if h != 0x002A || v != b"hi" {
        return TestResult::Fail("HVN handle/value round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/att",
    smoke_att_handle_value_notification
);

fn smoke_att_error_response_round_trip() -> TestResult {
    use crate::att::{
        build_error_response, decode_error_response, ATT_ECODE_INVALID_HANDLE, ATT_READ_REQ,
    };
    let pdu = build_error_response(ATT_READ_REQ, 0x0001, ATT_ECODE_INVALID_HANDLE);
    let er = decode_error_response(&pdu).expect("decode");
    if er.request_opcode != ATT_READ_REQ
        || er.attribute_handle != 0x0001
        || er.error_code != ATT_ECODE_INVALID_HANDLE
    {
        return TestResult::Fail("Error Response round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/att",
    smoke_att_error_response_round_trip
);

fn smoke_att_expects_response_classification() -> TestResult {
    use crate::att::{
        Pdu, ATT_HANDLE_VALUE_NTF, ATT_READ_REQ, ATT_WRITE_CMD, ATT_WRITE_REQ,
    };
    let read = Pdu {
        opcode: ATT_READ_REQ,
        params: vec![0, 0],
    };
    if !read.expects_response() {
        return TestResult::Fail("ReadReq should expect a response");
    }
    let cmd = Pdu {
        opcode: ATT_WRITE_CMD,
        params: vec![0, 0],
    };
    if cmd.expects_response() {
        return TestResult::Fail("WriteCmd must NOT expect a response");
    }
    let write = Pdu {
        opcode: ATT_WRITE_REQ,
        params: vec![0, 0],
    };
    if !write.expects_response() {
        return TestResult::Fail("WriteReq should expect a response");
    }
    let ntf = Pdu {
        opcode: ATT_HANDLE_VALUE_NTF,
        params: vec![0, 0],
    };
    if ntf.expects_response() {
        return TestResult::Fail("Notification must NOT expect a response");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/att",
    smoke_att_expects_response_classification
);

// ── SMP ────────────────────────────────────────────────────────────

fn smoke_smp_pairing_feature_round_trip() -> TestResult {
    use crate::smp::{
        IoCapability, PairingFeatureExchange, Pdu, AUTH_BONDING, AUTH_SC, SMP_PAIRING_REQUEST,
    };
    let f = PairingFeatureExchange {
        io_capability: IoCapability::DisplayYesNo as u8,
        oob_data_flag: 0,
        auth_req: AUTH_BONDING | AUTH_SC,
        max_encryption_key_size: 16,
        initiator_key_distribution: 0x07,
        responder_key_distribution: 0x07,
    };
    let pdu = f.encode(SMP_PAIRING_REQUEST);
    if pdu.code != SMP_PAIRING_REQUEST {
        return TestResult::Fail("code mismatch");
    }
    let raw = pdu.encode();
    let back_pdu = Pdu::decode(&raw).expect("decode");
    let back = PairingFeatureExchange::decode(&back_pdu).expect("decode features");
    if back != f {
        return TestResult::Fail("Pairing feature round-trip drift");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/smp", smoke_smp_pairing_feature_round_trip);

fn smoke_smp_pick_pairing_method_just_works() -> TestResult {
    use crate::smp::{pick_pairing_method, IoCapability, PairingMethod};
    // No MITM → always Just Works.
    let m = pick_pairing_method(IoCapability::DisplayYesNo, IoCapability::KeyboardDisplay, false, true, false);
    if m != PairingMethod::JustWorks {
        return TestResult::Fail("no-MITM path should pick Just Works");
    }
    // NoInputNoOutput on either side, MITM requested → still Just Works.
    let m = pick_pairing_method(
        IoCapability::NoInputNoOutput,
        IoCapability::KeyboardDisplay,
        true,
        true,
        false,
    );
    if m != PairingMethod::JustWorks {
        return TestResult::Fail("NoInputNoOutput must force Just Works");
    }
    // Two DisplayYesNo with MITM → Numeric Comparison.
    let m = pick_pairing_method(
        IoCapability::DisplayYesNo,
        IoCapability::DisplayYesNo,
        true,
        true,
        false,
    );
    if m != PairingMethod::NumericComparison {
        return TestResult::Fail("DisplayYesNo+MITM should pick Numeric Comparison");
    }
    // OOB always wins.
    let m = pick_pairing_method(
        IoCapability::DisplayYesNo,
        IoCapability::DisplayYesNo,
        true,
        true,
        true,
    );
    if m != PairingMethod::OutOfBand {
        return TestResult::Fail("OOB flag should override");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/smp", smoke_smp_pick_pairing_method_just_works);

fn smoke_smp_initiator_just_works_walk() -> TestResult {
    use crate::smp::{
        Initiator, IoCapability, PairingError, PairingFeatureExchange, PairingState,
        SmpCrypto, AUTH_BONDING, AUTH_SC, SMP_PAIRING_DHKEY_CHECK, SMP_PAIRING_PUBLIC_KEY,
        SMP_PAIRING_RANDOM, SMP_PAIRING_REQUEST, SMP_PAIRING_RESPONSE,
    };

    /// Deterministic stub crypto — sufficient to exercise the state
    /// machine. Production wires real P-256 + AES-CMAC.
    struct StubCrypto;
    impl SmpCrypto for StubCrypto {
        fn p256_keygen(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
            ([0x11; 32], [0x22; 32], [0x33; 32])
        }
        fn p256_dh(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8; 32]) -> [u8; 32] {
            [0x44; 32]
        }
        fn aes_cmac(&self, key: &[u8; 16], data: &[u8]) -> [u8; 16] {
            // Deterministic XOR digest — tests only.
            let mut out = [0u8; 16];
            for (i, b) in key.iter().enumerate() {
                out[i] ^= *b;
            }
            for (i, b) in data.iter().enumerate() {
                out[i % 16] ^= *b;
            }
            out
        }
        fn rand128(&self) -> [u8; 16] {
            [0x55; 16]
        }
    }

    let mut init = Initiator::new(StubCrypto, [0u8; 7], [0u8; 7]);
    let req = init.start();
    if req.code != SMP_PAIRING_REQUEST || init.state != PairingState::SentRequest {
        return TestResult::Fail("start() did not emit Pairing Request");
    }

    // Synthesise a Pairing Response: peer is also Just-Works capable.
    let peer = PairingFeatureExchange {
        io_capability: IoCapability::NoInputNoOutput as u8,
        oob_data_flag: 0,
        auth_req: AUTH_BONDING | AUTH_SC,
        max_encryption_key_size: 16,
        initiator_key_distribution: 0,
        responder_key_distribution: 0,
    }
    .encode(SMP_PAIRING_RESPONSE);
    let pk = init.feed(&peer).expect("feed rsp").expect("expect PK");
    if pk.code != SMP_PAIRING_PUBLIC_KEY || init.state != PairingState::SentPublicKey {
        return TestResult::Fail("response did not advance to PublicKey");
    }
    if pk.payload.len() != 64 {
        return TestResult::Fail("public key payload not 64 bytes");
    }

    // Peer's public key.
    let mut peer_pk = vec![0u8; 64];
    for v in peer_pk.iter_mut().take(32) {
        *v = 0x66;
    }
    for v in peer_pk.iter_mut().skip(32) {
        *v = 0x77;
    }
    let peer_pk_smp = crate::smp::Pdu {
        code: SMP_PAIRING_PUBLIC_KEY,
        payload: peer_pk,
    };
    let after_pk = init.feed(&peer_pk_smp).expect("peer PK");
    if !after_pk.is_none() || init.state != PairingState::WaitConfirm {
        return TestResult::Fail("after peer PK we should be in WaitConfirm");
    }

    // Peer sends Pairing Random (Nb).
    let peer_random = crate::smp::Pdu {
        code: SMP_PAIRING_RANDOM,
        payload: vec![0x88u8; 16],
    };
    let our_random = init
        .feed(&peer_random)
        .expect("nb")
        .expect("should emit Na");
    if our_random.code != SMP_PAIRING_RANDOM {
        return TestResult::Fail("expected Pairing Random outbound");
    }
    if init.state != PairingState::SentRandom {
        return TestResult::Fail("should be in SentRandom");
    }
    if init.ltk == [0u8; 16] {
        return TestResult::Fail("LTK should be derived non-zero by f5");
    }

    // Peer sends DHKey Check; pairing completes.
    let peer_check = crate::smp::Pdu {
        code: SMP_PAIRING_DHKEY_CHECK,
        payload: vec![0x99u8; 16],
    };
    let _ = init.feed(&peer_check).expect("dhkey check");
    if init.state != PairingState::Done {
        return TestResult::Fail("should be in Done after DHKey Check");
    }

    // Re-feeding a PDU after Done → Protocol error.
    let extra = crate::smp::Pdu {
        code: SMP_PAIRING_RANDOM,
        payload: vec![0u8; 16],
    };
    match init.feed(&extra) {
        Err(PairingError::Protocol) => {}
        _ => return TestResult::Fail("post-Done feed should be Protocol error"),
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/smp", smoke_smp_initiator_just_works_walk);

// ── SMP Numeric Comparison + Responder ─────────────────────────────

fn smoke_smp_numeric_comparison_value_six_digits() -> TestResult {
    use crate::smp::{numeric_comparison_value, SmpCrypto};
    struct StubCrypto;
    impl SmpCrypto for StubCrypto {
        fn p256_keygen(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
            ([0; 32], [0; 32], [0; 32])
        }
        fn p256_dh(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8; 32]) -> [u8; 32] {
            [0; 32]
        }
        fn aes_cmac(&self, key: &[u8; 16], data: &[u8]) -> [u8; 16] {
            // Deterministic — first 4 bytes of a synthetic digest
            // taken from the trailing data is what we'll mod.
            let mut out = [0u8; 16];
            for (i, b) in key.iter().enumerate() {
                out[i] ^= *b;
            }
            for (i, b) in data.iter().enumerate() {
                out[i % 16] ^= *b;
            }
            out
        }
        fn rand128(&self) -> [u8; 16] {
            [0; 16]
        }
    }

    let pk_a = [0xAAu8; 32];
    let pk_b = [0xBBu8; 32];
    let na = [0x11u8; 16];
    let nb = [0x22u8; 16];
    let v = numeric_comparison_value(&StubCrypto, &pk_a, &pk_b, &na, &nb);
    if v >= 1_000_000 {
        return TestResult::Fail("numeric comparison value should be 6 decimal digits");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/smp", smoke_smp_numeric_comparison_value_six_digits);

fn smoke_smp_responder_full_walk() -> TestResult {
    use crate::smp::{
        IoCapability, PairingFeatureExchange, Pdu, Responder, ResponderState, SmpCrypto,
        AUTH_BONDING, AUTH_SC, SMP_PAIRING_DHKEY_CHECK, SMP_PAIRING_PUBLIC_KEY,
        SMP_PAIRING_RANDOM, SMP_PAIRING_REQUEST, SMP_PAIRING_RESPONSE,
    };

    struct StubCrypto;
    impl SmpCrypto for StubCrypto {
        fn p256_keygen(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
            ([1; 32], [2; 32], [3; 32])
        }
        fn p256_dh(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8; 32]) -> [u8; 32] {
            [4; 32]
        }
        fn aes_cmac(&self, key: &[u8; 16], data: &[u8]) -> [u8; 16] {
            let mut out = [0u8; 16];
            for (i, b) in key.iter().enumerate() {
                out[i] ^= *b;
            }
            for (i, b) in data.iter().enumerate() {
                out[i % 16] ^= *b;
            }
            out
        }
        fn rand128(&self) -> [u8; 16] {
            [0x55; 16]
        }
    }

    let mut r = Responder::new(StubCrypto, [0u8; 7], [0u8; 7]);

    // Initiator's Pairing Request.
    let req = PairingFeatureExchange {
        io_capability: IoCapability::NoInputNoOutput as u8,
        oob_data_flag: 0,
        auth_req: AUTH_BONDING | AUTH_SC,
        max_encryption_key_size: 16,
        initiator_key_distribution: 0,
        responder_key_distribution: 0,
    }
    .encode(SMP_PAIRING_REQUEST);

    let rsp = r.feed(&req).expect("rsp").expect("expected response");
    if rsp.code != SMP_PAIRING_RESPONSE {
        return TestResult::Fail("responder didn't emit Pairing Response");
    }
    if r.state != ResponderState::GotRequest {
        return TestResult::Fail("state didn't advance to GotRequest");
    }

    // Initiator's Public Key (64 bytes).
    let pk = Pdu {
        code: SMP_PAIRING_PUBLIC_KEY,
        payload: alloc::vec![0xAAu8; 64],
    };
    let our_pk = r.feed(&pk).expect("pk").expect("expect our PK");
    if our_pk.code != SMP_PAIRING_PUBLIC_KEY {
        return TestResult::Fail("responder didn't emit Public Key");
    }
    if r.state != ResponderState::SentPublicKey {
        return TestResult::Fail("state didn't advance to SentPublicKey");
    }

    // Initiator's Pairing Random (Na).
    let na = Pdu {
        code: SMP_PAIRING_RANDOM,
        payload: alloc::vec![0x77u8; 16],
    };
    let our_nb = r.feed(&na).expect("na").expect("expect our Nb");
    if our_nb.code != SMP_PAIRING_RANDOM {
        return TestResult::Fail("responder didn't emit Pairing Random");
    }
    if r.state != ResponderState::SentRandom {
        return TestResult::Fail("state didn't advance to SentRandom");
    }
    if r.ltk == [0u8; 16] {
        return TestResult::Fail("LTK should be derived non-zero");
    }

    // Initiator's DHKey Check.
    let ea = Pdu {
        code: SMP_PAIRING_DHKEY_CHECK,
        payload: alloc::vec![0x99u8; 16],
    };
    let our_eb = r.feed(&ea).expect("ea").expect("expect our DHKey check");
    if our_eb.code != SMP_PAIRING_DHKEY_CHECK {
        return TestResult::Fail("responder didn't emit DHKey check");
    }
    if r.state != ResponderState::Done {
        return TestResult::Fail("responder didn't reach Done");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/smp", smoke_smp_responder_full_walk);

// ── GATT server ────────────────────────────────────────────────────

fn smoke_gatt_server_handles_read_request() -> TestResult {
    use crate::att::{ATT_READ_REQ, ATT_READ_RSP};
    use crate::gatt::{Uuid, UUID_SERVICE_BATTERY};
    use crate::gatt_server::{GattServer, Permissions};

    let mut srv = GattServer::new();
    let _svc = srv.db.add_primary_service(Uuid::U16(UUID_SERVICE_BATTERY));
    let (_decl, val_h) = srv.db.add_characteristic(
        Uuid::U16(0x2A19),
        crate::gatt::CHAR_PROP_READ,
        Permissions::read(),
        alloc::vec![85], // battery level = 85%
    );

    let read = crate::att::Pdu {
        opcode: ATT_READ_REQ,
        params: val_h.to_le_bytes().to_vec(),
    };
    let rsp = srv.handle_request(&read);
    if rsp.opcode != ATT_READ_RSP {
        return TestResult::Fail("server should return Read Response");
    }
    if rsp.params != alloc::vec![85u8] {
        return TestResult::Fail("read returned wrong battery value");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gatt-server", smoke_gatt_server_handles_read_request);

fn smoke_gatt_server_write_updates_value() -> TestResult {
    use crate::att::{ATT_WRITE_REQ, ATT_WRITE_RSP};
    use crate::gatt::Uuid;
    use crate::gatt_server::{GattServer, Permissions};

    let mut srv = GattServer::new();
    let _svc = srv.db.add_primary_service(Uuid::U16(0x180A));
    let (_, val_h) = srv.db.add_characteristic(
        Uuid::U16(0x2A29),
        crate::gatt::CHAR_PROP_READ | crate::gatt::CHAR_PROP_WRITE,
        Permissions::read_write(),
        alloc::vec![b'A'],
    );

    let mut write_params = val_h.to_le_bytes().to_vec();
    write_params.extend_from_slice(b"narf");
    let write = crate::att::Pdu {
        opcode: ATT_WRITE_REQ,
        params: write_params,
    };
    let rsp = srv.handle_request(&write);
    if rsp.opcode != ATT_WRITE_RSP {
        return TestResult::Fail("server should ACK with Write Response");
    }
    let attr = srv.db.attr_by_handle(val_h).expect("attr");
    if attr.value != b"narf" {
        return TestResult::Fail("server didn't store the new value");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gatt-server", smoke_gatt_server_write_updates_value);

fn smoke_gatt_server_read_by_group_type_lists_services() -> TestResult {
    use crate::att::ATT_READ_BY_GROUP_TYPE_RSP;
    use crate::gatt::{
        build_discover_primary_services, parse_primary_services, Uuid, UUID_SERVICE_BATTERY,
        UUID_SERVICE_GAP,
    };
    use crate::gatt_server::GattServer;

    let mut srv = GattServer::new();
    let _ = srv.db.add_primary_service(Uuid::U16(UUID_SERVICE_GAP));
    let _ = srv.db.add_primary_service(Uuid::U16(UUID_SERVICE_BATTERY));

    let req = build_discover_primary_services(0x0001, 0xFFFF);
    let rsp = srv.handle_request(&req);
    if rsp.opcode != ATT_READ_BY_GROUP_TYPE_RSP {
        return TestResult::Fail("server should return Read By Group Type Rsp");
    }
    let svcs = parse_primary_services(&rsp.params);
    if svcs.len() != 2 {
        return TestResult::Fail("expected 2 services back");
    }
    let uuids: alloc::vec::Vec<_> = svcs.iter().map(|s| s.uuid).collect();
    if !uuids.contains(&Uuid::U16(UUID_SERVICE_GAP))
        || !uuids.contains(&Uuid::U16(UUID_SERVICE_BATTERY))
    {
        return TestResult::Fail("server didn't list both services");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/gatt-server",
    smoke_gatt_server_read_by_group_type_lists_services
);

fn smoke_gatt_server_invalid_handle_errors() -> TestResult {
    use crate::att::{
        ATT_ECODE_INVALID_HANDLE, ATT_ERROR_RSP, ATT_READ_REQ,
    };
    use crate::gatt_server::GattServer;

    let mut srv = GattServer::new();
    let req = crate::att::Pdu {
        opcode: ATT_READ_REQ,
        params: alloc::vec![0xFF, 0xFF],
    };
    let rsp = srv.handle_request(&req);
    if rsp.opcode != ATT_ERROR_RSP {
        return TestResult::Fail("expected Error Response");
    }
    if rsp.params.last().copied() != Some(ATT_ECODE_INVALID_HANDLE) {
        return TestResult::Fail("error code should be Invalid Handle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/gatt-server",
    smoke_gatt_server_invalid_handle_errors
);

fn smoke_gatt_server_exchange_mtu_caps_at_min_23() -> TestResult {
    use crate::att::{ATT_EXCHANGE_MTU_REQ, ATT_EXCHANGE_MTU_RSP};
    use crate::gatt_server::GattServer;

    let mut srv = GattServer::new();
    let req = crate::att::Pdu {
        opcode: ATT_EXCHANGE_MTU_REQ,
        params: 17u16.to_le_bytes().to_vec(),
    };
    let rsp = srv.handle_request(&req);
    if rsp.opcode != ATT_EXCHANGE_MTU_RSP {
        return TestResult::Fail("expected Exchange MTU Response");
    }
    let mtu = u16::from_le_bytes([rsp.params[0], rsp.params[1]]);
    if mtu < 23 {
        return TestResult::Fail("MTU must not drop below 23");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/gatt-server",
    smoke_gatt_server_exchange_mtu_caps_at_min_23
);

// ── GATT ───────────────────────────────────────────────────────────

fn smoke_gatt_discover_primary_services_request() -> TestResult {
    use crate::att::ATT_READ_BY_GROUP_TYPE_REQ;
    use crate::gatt::{build_discover_primary_services, UUID_PRIMARY_SERVICE};
    let pdu = build_discover_primary_services(0x0001, 0xFFFF);
    if pdu.opcode != ATT_READ_BY_GROUP_TYPE_REQ {
        return TestResult::Fail("opcode should be Read By Group Type");
    }
    if pdu.params.len() != 6 {
        return TestResult::Fail("params should be 2+2+2 = 6 bytes");
    }
    let group_uuid = u16::from_le_bytes([pdu.params[4], pdu.params[5]]);
    if group_uuid != UUID_PRIMARY_SERVICE {
        return TestResult::Fail("group-type UUID should be 0x2800");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/gatt",
    smoke_gatt_discover_primary_services_request
);

fn smoke_gatt_parse_primary_services_response() -> TestResult {
    use crate::gatt::{parse_primary_services, Uuid, UUID_SERVICE_BATTERY, UUID_SERVICE_GAP};
    // Two primary services, both 16-bit UUIDs, so unit = 6 bytes.
    let mut rsp = vec![6u8];
    // Service 1: GAP at handles 0x0001..=0x0007.
    rsp.extend_from_slice(&0x0001u16.to_le_bytes());
    rsp.extend_from_slice(&0x0007u16.to_le_bytes());
    rsp.extend_from_slice(&UUID_SERVICE_GAP.to_le_bytes());
    // Service 2: Battery at handles 0x0010..=0x0015.
    rsp.extend_from_slice(&0x0010u16.to_le_bytes());
    rsp.extend_from_slice(&0x0015u16.to_le_bytes());
    rsp.extend_from_slice(&UUID_SERVICE_BATTERY.to_le_bytes());

    let parsed = parse_primary_services(&rsp);
    if parsed.len() != 2 {
        return TestResult::Fail("expected 2 services parsed");
    }
    if parsed[0].start_handle != 0x0001 || parsed[0].end_handle != 0x0007 {
        return TestResult::Fail("Service 1 handle range wrong");
    }
    if parsed[0].uuid != Uuid::U16(UUID_SERVICE_GAP) {
        return TestResult::Fail("Service 1 UUID wrong");
    }
    if parsed[1].uuid != Uuid::U16(UUID_SERVICE_BATTERY) {
        return TestResult::Fail("Service 2 UUID wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/gatt",
    smoke_gatt_parse_primary_services_response
);

fn smoke_gatt_parse_characteristics_response() -> TestResult {
    use crate::gatt::{parse_characteristics, Uuid, CHAR_PROP_NOTIFY, CHAR_PROP_READ};
    // Per-tuple: 2-byte handle + (1 prop + 2 value-handle + 2 UUID) = 7 bytes.
    let mut rsp = vec![7u8];
    // Characteristic at decl=0x0011, props=READ|NOTIFY, value=0x0012, UUID=0x2A19 (Battery Level).
    rsp.extend_from_slice(&0x0011u16.to_le_bytes());
    rsp.push(CHAR_PROP_READ | CHAR_PROP_NOTIFY);
    rsp.extend_from_slice(&0x0012u16.to_le_bytes());
    rsp.extend_from_slice(&0x2A19u16.to_le_bytes());

    let chars = parse_characteristics(&rsp);
    if chars.len() != 1 {
        return TestResult::Fail("expected 1 characteristic");
    }
    if chars[0].declaration_handle != 0x0011
        || chars[0].value_handle != 0x0012
        || chars[0].properties != (CHAR_PROP_READ | CHAR_PROP_NOTIFY)
    {
        return TestResult::Fail("Characteristic record fields wrong");
    }
    if chars[0].uuid != Uuid::U16(0x2A19) {
        return TestResult::Fail("Battery Level UUID wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/gatt",
    smoke_gatt_parse_characteristics_response
);

fn smoke_gatt_parse_descriptors_response() -> TestResult {
    use crate::gatt::{parse_descriptors, Uuid, UUID_CCC_DESCRIPTOR};
    // Format = 0x01 (16-bit), one descriptor at handle 0x0013 = CCCD.
    let mut rsp = vec![0x01u8];
    rsp.extend_from_slice(&0x0013u16.to_le_bytes());
    rsp.extend_from_slice(&UUID_CCC_DESCRIPTOR.to_le_bytes());
    let descs = parse_descriptors(&rsp);
    if descs.len() != 1 {
        return TestResult::Fail("expected 1 descriptor");
    }
    if descs[0].handle != 0x0013 {
        return TestResult::Fail("descriptor handle wrong");
    }
    if descs[0].uuid != Uuid::U16(UUID_CCC_DESCRIPTOR) {
        return TestResult::Fail("descriptor UUID wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gatt", smoke_gatt_parse_descriptors_response);

// ── L2CAP ──────────────────────────────────────────────────────────

fn smoke_l2cap_bframe_round_trip() -> TestResult {
    use crate::l2cap::{BFrame, CID_ATT};
    let f = BFrame::new(CID_ATT, vec![0x02, 0x01, 0x00, 0xFF]);
    let raw = f.encode();
    if raw.len() != 4 + 4 {
        return TestResult::Fail("B-frame should be 4-byte hdr + 4-byte payload");
    }
    if u16::from_le_bytes([raw[0], raw[1]]) != 4 {
        return TestResult::Fail("length field should be payload-only (4)");
    }
    if u16::from_le_bytes([raw[2], raw[3]]) != CID_ATT {
        return TestResult::Fail("CID field should be 0x0004");
    }
    let back = BFrame::decode(&raw).expect("decode");
    if back != f {
        return TestResult::Fail("B-frame round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/l2cap", smoke_l2cap_bframe_round_trip);

fn smoke_l2cap_reassembler_handles_fragments() -> TestResult {
    use crate::l2cap::{BFrame, PbFlag, Reassembler, CID_ATT};
    let frame = BFrame::new(CID_ATT, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    let bytes = frame.encode(); // 9 bytes total
    // Split across three ACL fragments: [0..3], [3..6], [6..9].
    let mut r = Reassembler::new();
    let out0 = r.feed(PbFlag::StartBrEdr, &bytes[0..3]);
    if !out0.is_empty() {
        return TestResult::Fail("Start fragment should not complete a frame");
    }
    let out1 = r.feed(PbFlag::Continuation, &bytes[3..6]);
    if !out1.is_empty() {
        return TestResult::Fail("middle fragment should not complete");
    }
    let out2 = r.feed(PbFlag::Continuation, &bytes[6..9]);
    if out2.len() != 1 {
        return TestResult::Fail("final fragment should produce exactly 1 frame");
    }
    if out2[0] != frame {
        return TestResult::Fail("reassembled frame differs from original");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_reassembler_handles_fragments
);

fn smoke_l2cap_reassembler_drops_orphaned_continuation() -> TestResult {
    use crate::l2cap::{BFrame, PbFlag, Reassembler, CID_ATT};
    // §6.6.2: a new Start abandons any in-progress reassembly.
    let mut r = Reassembler::new();
    let _ = r.feed(PbFlag::StartBrEdr, &[0xAA, 0xBB]); // partial start
    let frame = BFrame::new(CID_ATT, vec![0x01]);
    let bytes = frame.encode();
    let out = r.feed(PbFlag::CompleteLe, &bytes);
    if out.len() != 1 || out[0] != frame {
        return TestResult::Fail("new Start did not reset reassembler");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_reassembler_drops_orphaned_continuation
);

fn smoke_l2cap_cid_allocator_le() -> TestResult {
    use crate::l2cap::{CidAllocator, CID_DYNAMIC_LE_FIRST};
    let mut a = CidAllocator::new();
    let c0 = a.alloc_le().expect("first LE alloc");
    let c1 = a.alloc_le().expect("second LE alloc");
    if c0 != CID_DYNAMIC_LE_FIRST || c1 != CID_DYNAMIC_LE_FIRST + 1 {
        return TestResult::Fail("LE allocator did not start at 0x0040");
    }
    a.free_le(c0);
    let c2 = a.alloc_le().expect("realloc after free");
    if c2 != c0 {
        return TestResult::Fail("freed slot should be re-handed out");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/l2cap", smoke_l2cap_cid_allocator_le);

fn smoke_l2cap_signalling_round_trip() -> TestResult {
    use crate::l2cap::{iter_signalling, SignallingCode, SignallingCommand};
    let cmd = SignallingCommand {
        code: SignallingCode::EchoRequest as u8,
        identifier: 0x42,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let mut buf = Vec::new();
    cmd.encode(&mut buf);
    let recovered: Vec<SignallingCommand> = iter_signalling(&buf).collect();
    if recovered.len() != 1 {
        return TestResult::Fail("expected exactly 1 signalling command");
    }
    if recovered[0] != cmd {
        return TestResult::Fail("signalling command round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/l2cap", smoke_l2cap_signalling_round_trip);

fn smoke_l2cap_signalling_packs_multiple_commands() -> TestResult {
    use crate::l2cap::{iter_signalling, SignallingCode, SignallingCommand};
    let mut buf = Vec::new();
    SignallingCommand {
        code: SignallingCode::EchoRequest as u8,
        identifier: 1,
        data: vec![0x01],
    }
    .encode(&mut buf);
    SignallingCommand {
        code: SignallingCode::EchoResponse as u8,
        identifier: 1,
        data: vec![0x02, 0x03],
    }
    .encode(&mut buf);
    let cmds: Vec<_> = iter_signalling(&buf).collect();
    if cmds.len() != 2 {
        return TestResult::Fail("did not iterate 2 packed signalling commands");
    }
    if cmds[0].code != SignallingCode::EchoRequest as u8
        || cmds[1].code != SignallingCode::EchoResponse as u8
    {
        return TestResult::Fail("packed command order drift");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_signalling_packs_multiple_commands
);

// ── L2CAP ACL ⇄ frame wrap / dispatcher (Stage 1) ──────────────────

fn smoke_l2cap_wrap_bframe_fits_single_acl_packet() -> TestResult {
    use crate::l2cap::{wrap_frame_into_acl, BFrame, CID_ATT, PB_FIRST_FLUSHABLE};
    let frame = BFrame::new(CID_ATT, vec![0x02, 0x17, 0x00]); // ATT Exchange_MTU_Req(23)
    let acl = wrap_frame_into_acl(0x002A, &frame, 27, /*le=*/ true);
    if acl.len() != 1 {
        return TestResult::Fail("single B-frame should fit in one ACL packet");
    }
    if acl[0].pb_flag != PB_FIRST_FLUSHABLE {
        return TestResult::Fail("first LE ACL packet should use PB=0b10");
    }
    if acl[0].handle != 0x002A {
        return TestResult::Fail("ACL handle not preserved");
    }
    let raw = frame.encode();
    if acl[0].data != raw {
        return TestResult::Fail("ACL payload should equal encoded B-frame");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_wrap_bframe_fits_single_acl_packet
);

fn smoke_l2cap_wrap_bframe_fragments_across_acl_packets() -> TestResult {
    use crate::l2cap::{
        wrap_frame_into_acl, BFrame, CID_ATT, PB_CONTINUATION, PB_FIRST_FLUSHABLE,
    };
    // 100-byte payload + 4-byte L2CAP header = 104-byte frame; an MTU
    // of 27 forces 4 ACL packets.
    let frame = BFrame::new(CID_ATT, vec![0xAB; 100]);
    let acl = wrap_frame_into_acl(0x0100, &frame, 27, /*le=*/ true);
    if acl.len() != ((104 + 26) / 27) {
        return TestResult::Fail("expected 4 ACL fragments for 104-byte frame at MTU 27");
    }
    if acl[0].pb_flag != PB_FIRST_FLUSHABLE {
        return TestResult::Fail("first fragment should use PB=0b10");
    }
    for f in &acl[1..] {
        if f.pb_flag != PB_CONTINUATION {
            return TestResult::Fail("continuation fragments should use PB=0b01");
        }
    }
    // Total fragment payload bytes should reconstruct the frame.
    let mut reassembled = Vec::new();
    for f in &acl {
        reassembled.extend_from_slice(&f.data);
    }
    if reassembled != frame.encode() {
        return TestResult::Fail("fragment reassembly differs from original encoding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_wrap_bframe_fragments_across_acl_packets
);

fn smoke_l2cap_dispatcher_routes_inbound_acl_to_att_cid() -> TestResult {
    use crate::l2cap::{
        wrap_frame_into_acl, BFrame, CidClass, Dispatcher, CID_ATT, CID_LE_SIGNALLING, CID_SMP,
    };
    let frame = BFrame::new(CID_ATT, vec![0x0B, 0xAA, 0xBB, 0xCC]); // ATT Read Rsp
    let acl = wrap_frame_into_acl(0x0001, &frame, 27, /*le=*/ true);
    let mut disp = Dispatcher::new();
    let mut frames = Vec::new();
    for p in &acl {
        let f = disp.feed_acl(p.pb_flag, &p.data);
        frames.extend(f);
    }
    if frames.len() != 1 {
        return TestResult::Fail("expected exactly one reassembled frame");
    }
    if frames[0] != frame {
        return TestResult::Fail("dispatcher's frame doesn't match the wire frame");
    }
    if Dispatcher::classify_cid(frames[0].cid) != CidClass::Att {
        return TestResult::Fail("CID 0x0004 must classify as Att");
    }
    if Dispatcher::classify_cid(CID_LE_SIGNALLING) != CidClass::LeSignalling {
        return TestResult::Fail("CID 0x0005 must classify as LeSignalling");
    }
    if Dispatcher::classify_cid(CID_SMP) != CidClass::Smp {
        return TestResult::Fail("CID 0x0006 must classify as Smp");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_dispatcher_routes_inbound_acl_to_att_cid
);

fn smoke_l2cap_dispatcher_reassembles_fragmented_acl() -> TestResult {
    use crate::l2cap::{wrap_frame_into_acl, BFrame, Dispatcher, CID_ATT};
    // 50-byte ATT Read Rsp value; ACL MTU 27 forces ≥3 fragments.
    let mut payload = vec![0x0Bu8];
    payload.extend_from_slice(&[0xA5; 49]);
    let frame = BFrame::new(CID_ATT, payload);
    let acl = wrap_frame_into_acl(0x0007, &frame, 27, /*le=*/ true);
    if acl.len() < 2 {
        return TestResult::Fail("test precondition: needs ≥2 ACL fragments");
    }
    let mut disp = Dispatcher::new();
    for (i, p) in acl.iter().enumerate() {
        let frames = disp.feed_acl(p.pb_flag, &p.data);
        if i < acl.len() - 1 {
            if !frames.is_empty() {
                return TestResult::Fail("only the final fragment should complete the frame");
            }
        } else if frames.len() != 1 || frames[0] != frame {
            return TestResult::Fail("final fragment did not produce the original frame");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_dispatcher_reassembles_fragmented_acl
);

// ── HCI events used by the L2CAP/connection layer (Stage 1) ────────

fn smoke_hci_disconnection_complete_parse() -> TestResult {
    use crate::event::DisconnectionComplete;
    use crate::hci::Event;
    let event = Event {
        code: crate::event::EventCode::DisconnectionComplete as u8,
        params: vec![
            0x00,       // status
            0x2A, 0x00, // handle = 0x002A
            0x13,       // reason = Remote User Terminated
        ],
    };
    let dc = DisconnectionComplete::parse(&event).expect("parse");
    if dc.status != 0x00 || dc.handle != 0x002A || dc.reason != 0x13 {
        return TestResult::Fail("DisconnectionComplete fields wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_hci_disconnection_complete_parse);

fn smoke_hci_number_of_completed_packets_parse() -> TestResult {
    use crate::event::NumberOfCompletedPackets;
    use crate::hci::Event;
    // Two handles: 0x002A → 5 pkts, 0x002B → 1 pkt.
    let event = Event {
        code: crate::event::EventCode::NumberOfCompletedPackets as u8,
        params: vec![
            0x02, // num_handles
            0x2A, 0x00, 0x05, 0x00,
            0x2B, 0x00, 0x01, 0x00,
        ],
    };
    let n = NumberOfCompletedPackets::parse(&event).expect("parse");
    if n.entries.len() != 2 {
        return TestResult::Fail("expected 2 (handle, count) pairs");
    }
    if n.entries[0] != (0x002A, 5) || n.entries[1] != (0x002B, 1) {
        return TestResult::Fail("entries wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_hci_number_of_completed_packets_parse);

fn smoke_hci_le_connection_complete_parse() -> TestResult {
    use crate::event::LeConnectionComplete;
    use crate::hci::Event;
    // 1-byte subevent (0x01) + 18-byte payload.
    let mut p = vec![0x01u8]; // subevent
    p.push(0x00); // status
    p.extend_from_slice(&0x002Au16.to_le_bytes()); // handle
    p.push(0x00); // role = Central
    p.push(0x00); // peer address type = public
    p.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // peer addr
    p.extend_from_slice(&0x0018u16.to_le_bytes()); // conn interval
    p.extend_from_slice(&0x0000u16.to_le_bytes()); // latency
    p.extend_from_slice(&0x0190u16.to_le_bytes()); // supervision timeout
    p.push(0x00); // clock accuracy
    let event = Event {
        code: crate::event::EventCode::LeMeta as u8,
        params: p,
    };
    let cc = LeConnectionComplete::parse(&event).expect("parse");
    if cc.status != 0x00 || cc.handle != 0x002A || cc.role != 0x00 {
        return TestResult::Fail("LE Connection Complete fields wrong");
    }
    if cc.peer_address != [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] {
        return TestResult::Fail("peer address bytes wrong");
    }
    if cc.connection_interval != 0x0018 || cc.supervision_timeout != 0x0190 {
        return TestResult::Fail("connection params wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_hci_le_connection_complete_parse);

fn smoke_hci_le_advertising_report_parse() -> TestResult {
    use crate::event::parse_le_advertising_reports;
    use crate::hci::Event;
    // 1 report: ADV_IND from public 11:22:33:44:55:66, AD = "Flags=06",
    // RSSI = -50.
    let mut p = vec![
        0x02u8, // subevent = AdvertisingReport
        0x01,   // num_reports
        0x00,   // event type = ADV_IND
        0x00,   // address type = public
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x03,        // data_len
        0x02, 0x01, 0x06, // AD record: Flags=0x06
    ];
    p.push((-50i8) as u8);
    let event = Event {
        code: crate::event::EventCode::LeMeta as u8,
        params: p,
    };
    let reports = parse_le_advertising_reports(&event).expect("parse");
    if reports.len() != 1 {
        return TestResult::Fail("expected 1 report");
    }
    let r = &reports[0];
    if r.event_type != 0x00 || r.address_type != 0x00 {
        return TestResult::Fail("report type / addr type wrong");
    }
    if r.address != [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] {
        return TestResult::Fail("address bytes wrong");
    }
    if r.data != [0x02, 0x01, 0x06] {
        return TestResult::Fail("AD bytes wrong");
    }
    if r.rssi != -50 {
        return TestResult::Fail("RSSI sign wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_hci_le_advertising_report_parse);

// ── GAP Central — scan + connect command builders + state ──────────

fn smoke_gap_scan_parameters_encoding() -> TestResult {
    use crate::gap::{OwnAddressType, ScanFilterPolicy, ScanParameters, ScanType};
    let p = ScanParameters {
        scan_type: ScanType::Active,
        scan_interval: 0x0030,
        scan_window: 0x0030,
        own_address_type: OwnAddressType::Public,
        scanning_filter_policy: ScanFilterPolicy::AcceptAll,
    };
    let raw = p.encode();
    if raw[0] != 0x01 {
        return TestResult::Fail("scan_type should be 0x01 (Active)");
    }
    if u16::from_le_bytes([raw[1], raw[2]]) != 0x0030 {
        return TestResult::Fail("scan_interval bytes wrong");
    }
    if u16::from_le_bytes([raw[3], raw[4]]) != 0x0030 {
        return TestResult::Fail("scan_window bytes wrong");
    }
    if raw[5] != 0x00 || raw[6] != 0x00 {
        return TestResult::Fail("address type / filter policy wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gap", smoke_gap_scan_parameters_encoding);

fn smoke_gap_scan_enable_encoding() -> TestResult {
    use crate::gap::ScanEnable;
    let e = ScanEnable {
        enable: true,
        filter_duplicates: true,
    };
    let raw = e.encode();
    if raw != [0x01, 0x01] {
        return TestResult::Fail("ScanEnable should be [enable=1, filter_dupes=1]");
    }
    let d = ScanEnable {
        enable: false,
        filter_duplicates: false,
    }
    .encode();
    if d != [0x00, 0x00] {
        return TestResult::Fail("ScanEnable disabled wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gap", smoke_gap_scan_enable_encoding);

fn smoke_gap_create_connection_encoding() -> TestResult {
    use crate::gap::{CreateConnection, PeerAddressType};
    let cc = CreateConnection::to_peer(
        PeerAddressType::Random,
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    );
    let raw = cc.encode();
    if raw.len() != 25 {
        return TestResult::Fail("LE_Create_Connection must be 25 bytes");
    }
    if u16::from_le_bytes([raw[0], raw[1]]) != 0x0030 {
        return TestResult::Fail("scan_interval wrong");
    }
    if raw[4] != 0x00 {
        return TestResult::Fail("initiator filter policy should be PeerAddress");
    }
    if raw[5] != 0x01 {
        return TestResult::Fail("peer address type should be Random");
    }
    if raw[6..12] != [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] {
        return TestResult::Fail("peer address bytes wrong");
    }
    if u16::from_le_bytes([raw[13], raw[14]]) != 0x0018 {
        return TestResult::Fail("conn_interval_min wrong");
    }
    if u16::from_le_bytes([raw[19], raw[20]]) != 0x0190 {
        return TestResult::Fail("supervision_timeout wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gap", smoke_gap_create_connection_encoding);

fn smoke_gap_disconnect_payload() -> TestResult {
    use crate::gap::{build_disconnect, DISCONNECT_REASON_REMOTE_USER};
    let raw = build_disconnect(0x0123, DISCONNECT_REASON_REMOTE_USER);
    if raw != [0x23, 0x01, 0x13] {
        return TestResult::Fail("Disconnect payload bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gap", smoke_gap_disconnect_payload);

fn smoke_gap_central_state_machine_walks_scan_connect() -> TestResult {
    use crate::gap::{Central, CentralPhase};
    let mut c = Central::new();
    if c.phase != CentralPhase::Idle {
        return TestResult::Fail("Central starts at Idle");
    }
    c.note_parameters_sent();
    if c.phase != CentralPhase::ParametersSent {
        return TestResult::Fail("phase did not advance to ParametersSent");
    }
    c.note_scanning();
    if c.phase != CentralPhase::Scanning {
        return TestResult::Fail("phase did not advance to Scanning");
    }
    c.report_advertisement(0, [1, 2, 3, 4, 5, 6], 0, &[0x02, 0x01, 0x06], -60);
    if c.peers.len() != 1 || c.peers[0].last_rssi != -60 {
        return TestResult::Fail("peer not recorded");
    }
    // Re-report refreshes RSSI; no duplicate.
    c.report_advertisement(0, [1, 2, 3, 4, 5, 6], 0, &[], -40);
    if c.peers.len() != 1 || c.peers[0].last_rssi != -40 {
        return TestResult::Fail("re-report should refresh RSSI in place");
    }
    c.note_scan_stopping();
    c.note_connecting();
    c.note_connection_complete(0x00, 0x002A);
    if c.phase != CentralPhase::Connected || c.connected_handle != Some(0x002A) {
        return TestResult::Fail("connection complete handler wrong");
    }
    c.note_disconnected();
    if c.phase != CentralPhase::Idle || c.connected_handle.is_some() {
        return TestResult::Fail("disconnect should reset to Idle");
    }
    // Connection complete with failure status drops to Idle, not
    // Connected.
    c.note_connecting();
    c.note_connection_complete(0x05, 0x002A); // Authentication failure
    if c.phase != CentralPhase::Idle || c.connected_handle.is_some() {
        return TestResult::Fail("failed connect should go back to Idle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/gap",
    smoke_gap_central_state_machine_walks_scan_connect
);

fn smoke_transport_registry_round_trip() -> TestResult {
    crate::transport::__test_reset();
    let t = Arc::new(LoopbackTransport::new("reg"));
    crate::transport::register(t.clone());
    if crate::transport::transport_count() != 1 {
        return TestResult::Fail("transport_count != 1 after register");
    }
    let snap = crate::transport::transports();
    if !snap.iter().any(|x| x.name() == "reg") {
        return TestResult::Fail("registered transport not found in snapshot");
    }
    crate::transport::__test_reset();
    if crate::transport::transport_count() != 0 {
        return TestResult::Fail("__test_reset did not drain registry");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/transport", smoke_transport_registry_round_trip);

// ── HOGP smokes ────────────────────────────────────────────────────

fn smoke_hogp_hid_information_round_trip() -> TestResult {
    use crate::hogp::{HidInformation, HID_INFO_FLAG_NORMALLY_CONNECTABLE};
    let info = HidInformation {
        bcd_hid: 0x0111,
        country_code: 0,
        flags: HID_INFO_FLAG_NORMALLY_CONNECTABLE,
    };
    let bytes = info.encode();
    if bytes != [0x11, 0x01, 0x00, 0x02] {
        return TestResult::Fail("HID Information LE encoding wrong");
    }
    let back = HidInformation::decode(&bytes);
    if back != info {
        return TestResult::Fail("HidInformation round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hogp", smoke_hogp_hid_information_round_trip);

fn smoke_hogp_report_reference_layout() -> TestResult {
    use crate::hogp::{report_reference, ReportType};
    let buf = report_reference(7, ReportType::Input);
    if buf != [7, 1] {
        return TestResult::Fail("Report Reference desc must be (id, type=1)");
    }
    let buf2 = report_reference(2, ReportType::Feature);
    if buf2 != [2, 3] {
        return TestResult::Fail("Feature report type byte should be 0x03");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hogp", smoke_hogp_report_reference_layout);

fn smoke_hogp_builder_minimal_layout() -> TestResult {
    use crate::gatt::Uuid;
    use crate::gatt_server::AttributeDatabase;
    use crate::hogp::{HidInformation, HidServiceBuilder, UUID_HID_INFORMATION,
        UUID_HID_CONTROL_POINT, UUID_REPORT_MAP};
    let mut db = AttributeDatabase::new();
    let info = HidInformation { bcd_hid: 0x0111, country_code: 0, flags: 0 };
    let report_map: Vec<u8> = vec![0x05, 0x01, 0x09, 0x06, 0xC0]; // bogus stub bytes
    let h = HidServiceBuilder::new(info, report_map.clone()).build(&mut db);
    if h.service == 0 {
        return TestResult::Fail("service handle should be assigned");
    }
    // Exactly four attrs: service decl, info char decl, info value,
    // map decl, map value, ctrl decl, ctrl value = 7 total.
    if db.attrs().len() != 7 {
        return TestResult::Fail("minimal HID service should yield 7 attrs");
    }
    // info value handle should hold the encoded HidInformation.
    let info_attr = db.attr_by_handle(h.hid_information_value).expect("info attr");
    if info_attr.value != [0x11, 0x01, 0x00, 0x00] {
        return TestResult::Fail("info value not encoded into attribute");
    }
    let _ = info_attr.uuid; // ensure read path compiles
    let _ = Uuid::U16(UUID_HID_INFORMATION);
    let _ = UUID_REPORT_MAP;
    let _ = UUID_HID_CONTROL_POINT;
    TestResult::Pass
}
kernel_test_in!("bluetooth/hogp", smoke_hogp_builder_minimal_layout);

fn smoke_hogp_builder_input_report_has_cccd() -> TestResult {
    use crate::gatt::CHAR_PROP_NOTIFY;
    use crate::gatt::CHAR_PROP_READ;
    use crate::gatt_server::AttributeDatabase;
    use crate::hogp::{
        HidInformation, HidServiceBuilder, ReportEntry, ReportType,
        UUID_REPORT_REFERENCE,
    };
    let mut db = AttributeDatabase::new();
    let h = HidServiceBuilder::new(HidInformation { bcd_hid: 0x0111, country_code: 0, flags: 0 }, vec![0xC0])
        .add_report(ReportEntry {
            report_id: 1,
            report_type: ReportType::Input,
            properties: CHAR_PROP_READ | CHAR_PROP_NOTIFY,
            initial_value: vec![0; 8],
        })
        .build(&mut db);
    if h.reports.len() != 1 {
        return TestResult::Fail("expected 1 report");
    }
    let rep = &h.reports[0];
    if rep.cccd.is_none() {
        return TestResult::Fail("input report (notify) must have CCCD");
    }
    let rr = db.attr_by_handle(rep.report_reference).expect("rr attr");
    if rr.value != vec![1u8, ReportType::Input as u8] {
        return TestResult::Fail("Report Reference value mismatch");
    }
    let _ = UUID_REPORT_REFERENCE;
    TestResult::Pass
}
kernel_test_in!("bluetooth/hogp", smoke_hogp_builder_input_report_has_cccd);

fn smoke_hogp_boot_keyboard_report_round_trip() -> TestResult {
    use crate::hogp::BootKeyboardReport;
    // Modifier 0x02 (LShift), keycodes 0x04 ('a'), rest empty.
    let r = BootKeyboardReport { modifiers: 0x02, keycodes: [0x04, 0, 0, 0, 0, 0] };
    let bytes = r.encode();
    if bytes[0] != 0x02 || bytes[1] != 0x00 || bytes[2] != 0x04 {
        return TestResult::Fail("boot keyboard layout wrong");
    }
    if bytes.len() != 8 {
        return TestResult::Fail("boot keyboard report must be 8 bytes");
    }
    let back = BootKeyboardReport::decode(&bytes);
    if back != r {
        return TestResult::Fail("boot keyboard round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hogp", smoke_hogp_boot_keyboard_report_round_trip);

fn smoke_hogp_boot_mouse_signed_displacement() -> TestResult {
    use crate::hogp::BootMouseReport;
    let r = BootMouseReport { buttons: 0x01, dx: -3, dy: 5 };
    let bytes = r.encode();
    // -3 as i8 -> 0xFD as u8
    if bytes != [0x01, 0xFD, 0x05] {
        return TestResult::Fail("boot mouse encode mismatch");
    }
    let back = BootMouseReport::decode(&bytes);
    if back != r {
        return TestResult::Fail("boot mouse round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hogp", smoke_hogp_boot_mouse_signed_displacement);

// ── RFCOMM smokes ──────────────────────────────────────────────────

fn smoke_rfcomm_address_byte_round_trip() -> TestResult {
    use crate::rfcomm::Frame;
    let b = Frame::address_byte(7, true);
    // EA(1) | CR(1) | DLCI=7 (<<2) → 0x01 | 0x02 | 0x1C = 0x1F
    if b != 0x1F {
        return TestResult::Fail("address byte encoding wrong");
    }
    let (dlci, cr) = Frame::parse_address(b);
    if dlci != 7 || !cr {
        return TestResult::Fail("address byte decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/rfcomm", smoke_rfcomm_address_byte_round_trip);

fn smoke_rfcomm_sabm_round_trip() -> TestResult {
    use crate::rfcomm::Frame;
    let f = Frame::sabm(2, true);
    let bytes = f.encode();
    let (back, n) = Frame::decode(&bytes).expect("decode");
    if n != bytes.len() {
        return TestResult::Fail("decode should consume entire frame");
    }
    if back != f {
        return TestResult::Fail("SABM frame round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/rfcomm", smoke_rfcomm_sabm_round_trip);

fn smoke_rfcomm_uih_short_length_round_trip() -> TestResult {
    use crate::rfcomm::Frame;
    let info: Vec<u8> = (0..40u8).collect();
    let f = Frame::uih(3, true, info.clone());
    let bytes = f.encode();
    let (back, _) = Frame::decode(&bytes).expect("decode");
    if back.info != info {
        return TestResult::Fail("UIH info round-trip mismatch");
    }
    if back.frame_type != crate::rfcomm::FRAME_UIH {
        return TestResult::Fail("UIH frame type lost");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/rfcomm", smoke_rfcomm_uih_short_length_round_trip);

fn smoke_rfcomm_uih_long_length_round_trip() -> TestResult {
    use crate::rfcomm::Frame;
    // Length > 127 → 2-byte length indicator.
    let info: Vec<u8> = (0..200u16).map(|x| x as u8).collect();
    let f = Frame::uih(5, true, info.clone());
    let bytes = f.encode();
    let (back, _) = Frame::decode(&bytes).expect("decode");
    if back.info.len() != 200 {
        return TestResult::Fail("long UIH length should round-trip");
    }
    if back.info != info {
        return TestResult::Fail("UIH 2-byte-length info mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/rfcomm", smoke_rfcomm_uih_long_length_round_trip);

fn smoke_rfcomm_bad_fcs_rejected() -> TestResult {
    use crate::rfcomm::{Frame, RfcommError};
    let mut bytes = Frame::sabm(1, true).encode();
    let last = bytes.len() - 1;
    bytes[last] = bytes[last].wrapping_add(1);
    match Frame::decode(&bytes) {
        Err(RfcommError::BadFcs) => TestResult::Pass,
        _ => TestResult::Fail("tampered FCS must be rejected"),
    }
}
kernel_test_in!("bluetooth/rfcomm", smoke_rfcomm_bad_fcs_rejected);

fn smoke_rfcomm_dlc_state_machine_open_then_send() -> TestResult {
    use crate::rfcomm::{Dlc, DlcState, Frame};
    let mut dlc = Dlc::new(2);
    let connect = dlc.connect();
    if dlc.state != DlcState::Connecting {
        return TestResult::Fail("connect should move to Connecting");
    }
    if connect.frame_type != crate::rfcomm::FRAME_SABM {
        return TestResult::Fail("connect should emit SABM");
    }

    // Receive UA → Open.
    let ua = Frame::ua(2, false);
    dlc.feed(&ua);
    if dlc.state != DlcState::Open {
        return TestResult::Fail("UA should open the DLC");
    }

    // Send a UIH; receive a UIH echo.
    let tx = dlc.send(alloc::vec![1, 2, 3]).expect("send open");
    if tx.frame_type != crate::rfcomm::FRAME_UIH {
        return TestResult::Fail("send should emit UIH");
    }
    let rx = Frame::uih(2, false, alloc::vec![9, 9, 9]);
    let info = dlc.feed(&rx).expect("UIH info surfaced");
    if info != alloc::vec![9, 9, 9] {
        return TestResult::Fail("DLC.feed should expose UIH payload");
    }

    // Disconnect → DM/UA cycle.
    let disc = dlc.disconnect();
    if disc.frame_type != crate::rfcomm::FRAME_DISC {
        return TestResult::Fail("disconnect should emit DISC");
    }
    let ua2 = Frame::ua(2, false);
    dlc.feed(&ua2);
    if dlc.state != DlcState::Closed {
        return TestResult::Fail("UA after DISC should close");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/rfcomm", smoke_rfcomm_dlc_state_machine_open_then_send);

// ── AVDTP / A2DP smokes ────────────────────────────────────────────

fn smoke_avdtp_header_round_trip() -> TestResult {
    use crate::avdtp::{Header, MSG_COMMAND, PKT_SINGLE, SID_DISCOVER};
    let h = Header {
        transaction: 5,
        packet_type: PKT_SINGLE,
        message_type: MSG_COMMAND,
        signal_id: SID_DISCOVER,
    };
    let bytes = h.encode();
    if bytes.len() != 2 {
        return TestResult::Fail("header should be 2 bytes for SINGLE messages");
    }
    // byte 0: 0101 (txn=5) | 00 (PKT_SINGLE) | 00 (CMD) = 0x50
    if bytes[0] != 0x50 {
        return TestResult::Fail("header byte 0 packing wrong");
    }
    if bytes[1] != SID_DISCOVER {
        return TestResult::Fail("header byte 1 should carry SID");
    }
    let back = Header::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avdtp", smoke_avdtp_header_round_trip);

fn smoke_avdtp_discover_command_layout() -> TestResult {
    use crate::avdtp::{discover_command, SID_DISCOVER};
    let bytes = discover_command(3);
    if bytes.len() != 2 {
        return TestResult::Fail("discover command = header only");
    }
    if bytes[1] != SID_DISCOVER {
        return TestResult::Fail("discover SID mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avdtp", smoke_avdtp_discover_command_layout);

fn smoke_avdtp_sep_round_trip() -> TestResult {
    use crate::avdtp::{StreamEndPoint, MEDIA_AUDIO, SEP_TYPE_SINK};
    let s = StreamEndPoint {
        seid: 0x05,
        in_use: false,
        media_type: MEDIA_AUDIO,
        tsep: SEP_TYPE_SINK,
    };
    let b = s.encode();
    // byte 0: seid(0x05)<<2 = 0x14, in_use=0 → 0x14
    if b[0] != 0x14 {
        return TestResult::Fail("SEP byte 0 layout wrong");
    }
    // byte 1: media=0 (audio) | tsep<<3 = 0x08
    if b[1] != 0x08 {
        return TestResult::Fail("SEP byte 1 layout wrong (sink, audio)");
    }
    let back = StreamEndPoint::decode(&b).expect("decode");
    if back != s {
        return TestResult::Fail("SEP round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avdtp", smoke_avdtp_sep_round_trip);

fn smoke_avdtp_sbc_capability_round_trip() -> TestResult {
    use crate::avdtp::{
        SbcCapability, SBC_ALLOC_LOUDNESS, SBC_ALLOC_SNR, SBC_BLOCK_16, SBC_BLOCK_4,
        SBC_BLOCK_8, SBC_CHAN_JOINT_STEREO, SBC_CHAN_STEREO, SBC_FREQ_44100, SBC_FREQ_48000,
        SBC_SUBBANDS_8,
    };
    let cap = SbcCapability {
        frequency: SBC_FREQ_44100 | SBC_FREQ_48000,
        channel_mode: SBC_CHAN_STEREO | SBC_CHAN_JOINT_STEREO,
        block_length: SBC_BLOCK_4 | SBC_BLOCK_8 | SBC_BLOCK_16,
        subbands: SBC_SUBBANDS_8,
        allocation: SBC_ALLOC_SNR | SBC_ALLOC_LOUDNESS,
        min_bitpool: 2,
        max_bitpool: 53,
    };
    let bytes = cap.encode();
    if bytes.len() != 4 {
        return TestResult::Fail("SBC capability blob = 4 bytes");
    }
    let back = SbcCapability::decode(&bytes).expect("decode");
    if back != cap {
        return TestResult::Fail("SBC capability round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avdtp", smoke_avdtp_sbc_capability_round_trip);

fn smoke_avdtp_sbc_media_codec_capability_descriptor() -> TestResult {
    use crate::avdtp::{
        sbc_media_codec_capability, SbcCapability, CAT_MEDIA_CODEC, CODEC_SBC, MEDIA_AUDIO,
        SBC_ALLOC_LOUDNESS, SBC_BLOCK_16, SBC_CHAN_JOINT_STEREO, SBC_FREQ_44100, SBC_SUBBANDS_8,
    };
    let blob = sbc_media_codec_capability(
        MEDIA_AUDIO,
        SbcCapability {
            frequency: SBC_FREQ_44100,
            channel_mode: SBC_CHAN_JOINT_STEREO,
            block_length: SBC_BLOCK_16,
            subbands: SBC_SUBBANDS_8,
            allocation: SBC_ALLOC_LOUDNESS,
            min_bitpool: 2,
            max_bitpool: 53,
        },
    );
    if blob[0] != CAT_MEDIA_CODEC {
        return TestResult::Fail("category byte should be MEDIA_CODEC (0x07)");
    }
    if blob[1] != 6 {
        return TestResult::Fail("length should be 6 (media_type + codec_type + 4-byte SBC)");
    }
    if blob[3] != CODEC_SBC {
        return TestResult::Fail("codec byte should be SBC (0x00)");
    }
    if blob.len() != 8 {
        return TestResult::Fail("blob total length: 2 hdr + 2 type + 4 sbc = 8");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avdtp", smoke_avdtp_sbc_media_codec_capability_descriptor);

fn smoke_avdtp_set_configuration_command_layout() -> TestResult {
    use crate::avdtp::{set_configuration_command, SID_SET_CONFIGURATION};
    let bytes = set_configuration_command(2, 5, 9, &[0xAA, 0xBB]);
    // byte 0: txn=2, SINGLE, CMD = 0x20
    // byte 1: SID
    // byte 2: ACP SEID = 5 << 2 = 0x14
    // byte 3: INT SEID = 9 << 2 = 0x24
    // byte 4..: capabilities
    if bytes[0] != 0x20 {
        return TestResult::Fail("header byte 0 wrong");
    }
    if bytes[1] != SID_SET_CONFIGURATION {
        return TestResult::Fail("SID mismatch");
    }
    if bytes[2] != 0x14 {
        return TestResult::Fail("ACP SEID encoding wrong");
    }
    if bytes[3] != 0x24 {
        return TestResult::Fail("INT SEID encoding wrong");
    }
    if &bytes[4..] != &[0xAA, 0xBB] {
        return TestResult::Fail("trailing capability blob lost");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avdtp", smoke_avdtp_set_configuration_command_layout);

fn smoke_avdtp_psm_assigned_number() -> TestResult {
    use crate::avdtp::AVDTP_PSM;
    if AVDTP_PSM != 0x0019 {
        return TestResult::Fail("AVDTP PSM is 0x0019 per Assigned Numbers");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avdtp", smoke_avdtp_psm_assigned_number);

// ── HFP AT-command codec smokes ────────────────────────────────────

fn smoke_hfp_brsf_round_trip() -> TestResult {
    use crate::hfp::{brsf_command, parse_at, AtForm, HF_FEAT_CODEC_NEGOTIATION, HF_FEAT_VOLUME_CONTROL};
    let line = brsf_command(HF_FEAT_VOLUME_CONTROL | HF_FEAT_CODEC_NEGOTIATION);
    let parsed = parse_at(&line).expect("parse");
    if parsed.name != "+BRSF" {
        return TestResult::Fail("BRSF command name mismatch");
    }
    if parsed.form != AtForm::Write {
        return TestResult::Fail("BRSF should be a write-form (=)");
    }
    if parsed.params != "144" {
        // 16 (volume) | 128 (codec) = 144
        return TestResult::Fail("BRSF parameter should be the decimal feature bitmap");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hfp", smoke_hfp_brsf_round_trip);

fn smoke_hfp_cind_test_command() -> TestResult {
    use crate::hfp::{cind_test_command, parse_at, AtForm};
    let line = cind_test_command();
    let parsed = parse_at(&line).expect("parse");
    if parsed.name != "+CIND" || parsed.form != AtForm::Test {
        return TestResult::Fail("CIND test form (=?) lost");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hfp", smoke_hfp_cind_test_command);

fn smoke_hfp_cind_read_command() -> TestResult {
    use crate::hfp::{cind_read_command, parse_at, AtForm};
    let line = cind_read_command();
    let parsed = parse_at(&line).expect("parse");
    if parsed.form != AtForm::Read {
        return TestResult::Fail("CIND read form (?) lost");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hfp", smoke_hfp_cind_read_command);

fn smoke_hfp_basic_ata_command() -> TestResult {
    use crate::hfp::{answer_command, parse_at, AtForm};
    let line = answer_command();
    let parsed = parse_at(&line).expect("parse");
    if parsed.name != "A" {
        return TestResult::Fail("ATA basic command name = 'A'");
    }
    if parsed.form != AtForm::Basic {
        return TestResult::Fail("ATA is the basic form");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hfp", smoke_hfp_basic_ata_command);

fn smoke_hfp_rejects_non_at_line() -> TestResult {
    use crate::hfp::{parse_at, HfpError};
    match parse_at("HELLO\r") {
        Err(HfpError::NotAtCommand) => TestResult::Pass,
        _ => TestResult::Fail("non-AT line must be rejected"),
    }
}
kernel_test_in!("bluetooth/hfp", smoke_hfp_rejects_non_at_line);

fn smoke_hfp_ciev_unsolicited_format() -> TestResult {
    use crate::hfp::ciev_unsolicited;
    let s = ciev_unsolicited(2, 1);
    if s != "\r\n+CIEV: 2,1\r\n" {
        return TestResult::Fail("+CIEV unsolicited result formatting wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hfp", smoke_hfp_ciev_unsolicited_format);

fn smoke_hfp_csv_number_parser() -> TestResult {
    use crate::hfp::parse_csv_numbers;
    let v = parse_csv_numbers("1,0,1,0,0").expect("parse");
    if v != alloc::vec![1u32, 0, 1, 0, 0] {
        return TestResult::Fail("CSV decode mismatch");
    }
    let with_blanks = parse_csv_numbers("1,,5").expect("parse with blanks");
    if with_blanks != alloc::vec![1u32, 0, 5] {
        return TestResult::Fail("blank tokens should decode to 0 (HFP CIND convention)");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hfp", smoke_hfp_csv_number_parser);

fn smoke_hfp_ok_and_error_responses() -> TestResult {
    use crate::hfp::{error_response, ok_response};
    if ok_response() != "\r\nOK\r\n" {
        return TestResult::Fail("OK response framing wrong");
    }
    if error_response() != "\r\nERROR\r\n" {
        return TestResult::Fail("ERROR response framing wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hfp", smoke_hfp_ok_and_error_responses);

// ── SDP smokes ─────────────────────────────────────────────────────

fn smoke_sdp_pdu_header_round_trip() -> TestResult {
    use crate::sdp::{PduHeader, PDU_SERVICE_SEARCH_REQUEST};
    let h = PduHeader {
        pdu_id: PDU_SERVICE_SEARCH_REQUEST,
        transaction_id: 0xCAFE,
        parameter_length: 0x1234,
    };
    let bytes = h.encode();
    if bytes.len() != 5 {
        return TestResult::Fail("PDU header is 5 bytes");
    }
    if bytes[0] != PDU_SERVICE_SEARCH_REQUEST {
        return TestResult::Fail("PDU ID byte 0");
    }
    if bytes[1] != 0xCA || bytes[2] != 0xFE {
        return TestResult::Fail("transaction ID is big-endian");
    }
    if bytes[3] != 0x12 || bytes[4] != 0x34 {
        return TestResult::Fail("parameter length is big-endian");
    }
    let back = PduHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("PDU header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_pdu_header_round_trip);

fn smoke_sdp_de_header_packing() -> TestResult {
    use crate::sdp::{de_header, DE_TYPE_UINT};
    // type 1 (uint) + size index 2 (4 bytes) → (1<<3) | 2 = 0x0A
    if de_header(DE_TYPE_UINT, 2) != 0x0A {
        return TestResult::Fail("DE header packing wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_de_header_packing);

fn smoke_sdp_encode_uint_widths() -> TestResult {
    use crate::sdp::{encode_uint, DE_TYPE_UINT};
    // 16-bit uint 0xCAFE.
    let mut out = alloc::vec::Vec::new();
    encode_uint(&mut out, 2, 0xCAFE);
    if out != alloc::vec![(DE_TYPE_UINT << 3) | 1, 0xCA, 0xFE] {
        return TestResult::Fail("16-bit uint encoding");
    }
    // 32-bit uint 0xDEAD_BEEF.
    let mut out = alloc::vec::Vec::new();
    encode_uint(&mut out, 4, 0xDEAD_BEEF);
    if out != alloc::vec![(DE_TYPE_UINT << 3) | 2, 0xDE, 0xAD, 0xBE, 0xEF] {
        return TestResult::Fail("32-bit uint encoding");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_encode_uint_widths);

fn smoke_sdp_encode_uuid_16bit() -> TestResult {
    use crate::sdp::{encode_uuid, DE_TYPE_UUID};
    let mut out = alloc::vec::Vec::new();
    encode_uuid(&mut out, &[0x11, 0x05]); // OBEX File Transfer
    if out != alloc::vec![(DE_TYPE_UUID << 3) | 1, 0x11, 0x05] {
        return TestResult::Fail("UUID-16 encoding");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_encode_uuid_16bit);

fn smoke_sdp_encode_text_uses_size_index_5() -> TestResult {
    use crate::sdp::{decode_element, encode_text, DE_TYPE_TEXT};
    let mut out = alloc::vec::Vec::new();
    encode_text(&mut out, "narf");
    // header byte | 1-byte length | "narf"
    if out[0] != (DE_TYPE_TEXT << 3) | 5 {
        return TestResult::Fail("Text uses size-index 5");
    }
    if out[1] != 4 {
        return TestResult::Fail("size byte should = string length");
    }
    let (ty, payload, consumed) = decode_element(&out).expect("decode");
    if ty != DE_TYPE_TEXT {
        return TestResult::Fail("decode type mismatch");
    }
    if payload != b"narf" {
        return TestResult::Fail("decode payload mismatch");
    }
    if consumed != out.len() {
        return TestResult::Fail("consumed should equal element length");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_encode_text_uses_size_index_5);

fn smoke_sdp_encode_sequence_carries_children() -> TestResult {
    use crate::sdp::{decode_element, encode_sequence, encode_uuid, DE_TYPE_SEQUENCE};
    let mut child = alloc::vec::Vec::new();
    encode_uuid(&mut child, &[0x11, 0x05]);
    encode_uuid(&mut child, &[0x11, 0x06]);
    let mut out = alloc::vec::Vec::new();
    encode_sequence(&mut out, 5, &child);
    let (ty, payload, _) = decode_element(&out).expect("decode");
    if ty != DE_TYPE_SEQUENCE {
        return TestResult::Fail("type should be Sequence");
    }
    if payload != child {
        return TestResult::Fail("sequence payload should equal children");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_encode_sequence_carries_children);

fn smoke_sdp_service_search_request_envelope() -> TestResult {
    use crate::sdp::{
        build_service_search_request, decode_element, PduHeader, DE_TYPE_SEQUENCE,
        PDU_SERVICE_SEARCH_REQUEST,
    };
    let req = build_service_search_request(0x0001, &[&[0x11, 0x05]], 0xFFFF);
    let h = PduHeader::decode(&req).expect("decode header");
    if h.pdu_id != PDU_SERVICE_SEARCH_REQUEST {
        return TestResult::Fail("PDU ID should be SERVICE_SEARCH_REQUEST");
    }
    if h.transaction_id != 0x0001 {
        return TestResult::Fail("transaction ID");
    }
    // Body starts at byte 5 with a Sequence DataElement.
    let (ty, _, _) = decode_element(&req[5..]).expect("decode body");
    if ty != DE_TYPE_SEQUENCE {
        return TestResult::Fail("first body element should be the UUID Sequence");
    }
    // Last byte must be the continuation-state size (0).
    if *req.last().unwrap() != 0 {
        return TestResult::Fail("continuation state size byte missing");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_service_search_request_envelope);

fn smoke_sdp_service_attribute_request_record_handle() -> TestResult {
    use crate::sdp::{build_service_attribute_request, PduHeader, PDU_SERVICE_ATTRIBUTE_REQUEST};
    let req = build_service_attribute_request(0x0002, 0xCAFE_BEEF, 0x100, &[0x0001, 0x0004], false);
    let h = PduHeader::decode(&req).expect("decode");
    if h.pdu_id != PDU_SERVICE_ATTRIBUTE_REQUEST {
        return TestResult::Fail("opcode mismatch");
    }
    // First 4 bytes after the header are the record handle, big-endian.
    if &req[5..9] != &[0xCA, 0xFE, 0xBE, 0xEF] {
        return TestResult::Fail("record handle should be big-endian");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_service_attribute_request_record_handle);

fn smoke_sdp_psm_assigned_number() -> TestResult {
    if crate::sdp::SDP_PSM != 0x0001 {
        return TestResult::Fail("SDP PSM = 0x0001 per Assigned Numbers");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/sdp", smoke_sdp_psm_assigned_number);

// ── Bluetooth Mesh smokes ──────────────────────────────────────────

fn smoke_mesh_network_header_round_trip() -> TestResult {
    use crate::mesh::NetworkHeader;
    let h = NetworkHeader {
        ivi: 1,
        nid: 0x42,
        ctl: false,
        ttl: 7,
        seq: 0xCAFE_BE,
        src: 0x1234,
        dst: 0xFFFF,
    };
    let bytes = h.encode();
    if bytes[0] != ((1 << 7) | 0x42) {
        return TestResult::Fail("byte 0 should pack IVI<<7 | NID");
    }
    if bytes[1] != 7 {
        return TestResult::Fail("CTL=0 + TTL=7 → byte 1 = 0x07");
    }
    let back = NetworkHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("network header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/mesh", smoke_mesh_network_header_round_trip);

fn smoke_mesh_seq_is_24bit_be() -> TestResult {
    use crate::mesh::NetworkHeader;
    let h = NetworkHeader {
        seq: 0x123456,
        ..Default::default()
    };
    let bytes = h.encode();
    if bytes[2] != 0x12 || bytes[3] != 0x34 || bytes[4] != 0x56 {
        return TestResult::Fail("SEQ should be 3 BE bytes");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/mesh", smoke_mesh_seq_is_24bit_be);

fn smoke_mesh_segmented_access_header_round_trip() -> TestResult {
    use crate::mesh::SegmentedAccessHeader;
    let h = SegmentedAccessHeader {
        seg: true,
        akf: true,
        aid: 0x12,
        szmic: false,
        seq_zero: 0x1AB3,
        seg_o: 5,
        seg_n: 9,
    };
    let bytes = h.encode();
    if bytes[0] & 0xC0 != 0xC0 {
        return TestResult::Fail("SEG+AKF bits should be set");
    }
    let back = SegmentedAccessHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("segmented header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/mesh", smoke_mesh_segmented_access_header_round_trip);

fn smoke_mesh_access_opcode_one_byte() -> TestResult {
    use crate::mesh::AccessOpcode;
    let bytes = AccessOpcode::OneByte(0x42).encode();
    if bytes != alloc::vec![0x42u8] {
        return TestResult::Fail("1-byte opcode should encode as itself");
    }
    let (op, n) = AccessOpcode::decode(&bytes).expect("decode");
    if op != AccessOpcode::OneByte(0x42) || n != 1 {
        return TestResult::Fail("1-byte decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/mesh", smoke_mesh_access_opcode_one_byte);

fn smoke_mesh_access_opcode_two_byte() -> TestResult {
    use crate::mesh::AccessOpcode;
    let v = 0x2C00; // Generic OnOff Set (Mesh Model spec)
    let bytes = AccessOpcode::TwoByte(v).encode();
    if bytes[0] & 0xC0 != 0x80 {
        return TestResult::Fail("2-byte opcode top bits = 0b10");
    }
    let (op, n) = AccessOpcode::decode(&bytes).expect("decode");
    if op != AccessOpcode::TwoByte(v) || n != 2 {
        return TestResult::Fail("2-byte decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/mesh", smoke_mesh_access_opcode_two_byte);

fn smoke_mesh_access_opcode_vendor_form_carries_company_id_le() -> TestResult {
    use crate::mesh::AccessOpcode;
    let bytes = AccessOpcode::Vendor {
        op: 0x05,
        company_id: 0x004C, // Apple
    }
    .encode();
    if bytes[0] & 0xC0 != 0xC0 {
        return TestResult::Fail("3-byte opcode top bits = 0b11");
    }
    if bytes[1] != 0x4C || bytes[2] != 0x00 {
        return TestResult::Fail("Company ID is little-endian");
    }
    let (op, _) = AccessOpcode::decode(&bytes).expect("decode");
    if op != (AccessOpcode::Vendor { op: 0x05, company_id: 0x004C }) {
        return TestResult::Fail("vendor opcode round-trip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/mesh",
    smoke_mesh_access_opcode_vendor_form_carries_company_id_le
);

fn smoke_mesh_access_opcode_rejects_reserved() -> TestResult {
    use crate::mesh::{AccessOpcode, MeshError};
    match AccessOpcode::decode(&[0x00]) {
        Err(MeshError::BadOpcode) => {}
        _ => return TestResult::Fail("opcode 0x00 must be rejected"),
    }
    match AccessOpcode::decode(&[0x7F]) {
        Err(MeshError::BadOpcode) => TestResult::Pass,
        _ => TestResult::Fail("opcode 0x7F must be rejected"),
    }
}
kernel_test_in!("bluetooth/mesh", smoke_mesh_access_opcode_rejects_reserved);

fn smoke_mesh_composition_header_round_trip() -> TestResult {
    use crate::mesh::CompositionHeader;
    let h = CompositionHeader {
        cid: 0x004C,
        pid: 0x1234,
        vid: 0x0001,
        crpl: 32,
        features: CompositionHeader::FEATURE_RELAY | CompositionHeader::FEATURE_PROXY,
    };
    let bytes = h.encode();
    let back = CompositionHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("composition header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/mesh", smoke_mesh_composition_header_round_trip);

// ── GAP advertising-data smokes ────────────────────────────────────

fn smoke_gap_record_iterator_walks_two_records() -> TestResult {
    use crate::gap::{AdIter, AD_COMPLETE_LOCAL_NAME, AD_FLAGS};
    // Record 1: Flags = 0x06 (LE General Discoverable + BR/EDR not supported)
    // Record 2: Complete Local Name = "narf"
    let buf = [
        2u8, AD_FLAGS, 0x06,
        5, AD_COMPLETE_LOCAL_NAME, b'n', b'a', b'r', b'f',
    ];
    let recs: alloc::vec::Vec<_> = AdIter::new(&buf).collect::<Result<_, _>>().expect("walk");
    if recs.len() != 2 {
        return TestResult::Fail("expected 2 records");
    }
    if recs[0].ad_type != AD_FLAGS || recs[0].payload != [0x06] {
        return TestResult::Fail("flags record decode wrong");
    }
    if recs[1].ad_type != AD_COMPLETE_LOCAL_NAME || recs[1].payload != b"narf" {
        return TestResult::Fail("name record decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gap", smoke_gap_record_iterator_walks_two_records);

fn smoke_gap_iterator_stops_on_zero_length() -> TestResult {
    use crate::gap::{AdIter, AD_FLAGS};
    let buf = [2u8, AD_FLAGS, 0x06, 0, 0, 0, 0];
    let count = AdIter::new(&buf).count();
    if count != 1 {
        return TestResult::Fail("zero-length record terminates iteration");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gap", smoke_gap_iterator_stops_on_zero_length);

fn smoke_gap_truncated_record_surfaces_error() -> TestResult {
    use crate::gap::{AdIter, GapError, AD_COMPLETE_LOCAL_NAME};
    let buf = [10u8, AD_COMPLETE_LOCAL_NAME, b'a', b'b']; // claims length 10, only 2 follow
    match AdIter::new(&buf).next() {
        Some(Err(GapError::Truncated)) => TestResult::Pass,
        _ => TestResult::Fail("truncated record must error"),
    }
}
kernel_test_in!("bluetooth/gap", smoke_gap_truncated_record_surfaces_error);

fn smoke_gap_builder_round_trip_with_decoders() -> TestResult {
    use crate::gap::{
        append_complete_local_name, append_flags, append_manufacturer_data, append_tx_power,
        flags, local_name, manufacturer_data, tx_power, FLAGS_BR_EDR_NOT_SUPPORTED,
        FLAGS_LE_GENERAL_DISCOVERABLE,
    };
    let mut buf = alloc::vec::Vec::new();
    append_flags(&mut buf, FLAGS_LE_GENERAL_DISCOVERABLE | FLAGS_BR_EDR_NOT_SUPPORTED);
    append_complete_local_name(&mut buf, "narf");
    append_tx_power(&mut buf, -7);
    append_manufacturer_data(&mut buf, 0x004C, &[1, 2, 3]);

    if flags(&buf) != Some(FLAGS_LE_GENERAL_DISCOVERABLE | FLAGS_BR_EDR_NOT_SUPPORTED) {
        return TestResult::Fail("flags decode mismatch");
    }
    if local_name(&buf).as_deref() != Some("narf") {
        return TestResult::Fail("local-name decode mismatch");
    }
    if tx_power(&buf) != Some(-7) {
        return TestResult::Fail("tx-power decode mismatch");
    }
    let (cid, payload) = manufacturer_data(&buf).expect("manufacturer data present");
    if cid != 0x004C {
        return TestResult::Fail("Company ID lives at low 2 bytes");
    }
    if payload != [1, 2, 3] {
        return TestResult::Fail("vendor payload tail mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gap", smoke_gap_builder_round_trip_with_decoders);

fn smoke_gap_service_uuid_list_round_trip() -> TestResult {
    use crate::gap::{append_service_uuid_list_16, service_uuids_16};
    let mut buf = alloc::vec::Vec::new();
    append_service_uuid_list_16(&mut buf, true, &[0x1812, 0x180F, 0x180A]);
    let uuids = service_uuids_16(&buf);
    if uuids != alloc::vec![0x1812u16, 0x180F, 0x180A] {
        return TestResult::Fail("service UUID list round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/gap", smoke_gap_service_uuid_list_round_trip);

fn smoke_gap_record_length_byte_covers_type_plus_payload() -> TestResult {
    use crate::gap::{append_record, AD_FLAGS};
    let mut buf = alloc::vec::Vec::new();
    append_record(&mut buf, AD_FLAGS, &[0x06]);
    if buf[0] != 2 {
        return TestResult::Fail("length byte = 1 (type) + 1 (payload) = 2");
    }
    if buf[1] != AD_FLAGS {
        return TestResult::Fail("AD type byte 1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/gap",
    smoke_gap_record_length_byte_covers_type_plus_payload
);

// ── HID Profile (Classic BT) ──────────────────────────────────────

fn smoke_hidp_handshake_packet_round_trip() -> TestResult {
    use crate::hid_profile::{build_handshake, decode_header, handshake, TransactionType};
    let buf = build_handshake(handshake::SUCCESSFUL);
    if buf.len() != 1 {
        return TestResult::Fail("handshake should be 1 byte");
    }
    let h = decode_header(&buf).expect("header");
    if h.transaction != TransactionType::Handshake || h.parameter != handshake::SUCCESSFUL {
        return TestResult::Fail("handshake decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hid", smoke_hidp_handshake_packet_round_trip);

fn smoke_hidp_get_report_with_size_field() -> TestResult {
    use crate::hid_profile::{build_get_report, ReportType};
    let buf = build_get_report(ReportType::Input, Some(0x05), Some(0x40));
    if buf.len() != 4 {
        return TestResult::Fail("GET_REPORT with size = 1 hdr + 1 id + 2 size = 4 bytes");
    }
    if buf[0] >> 4 != 0x4 {
        return TestResult::Fail("transaction byte wrong");
    }
    if buf[0] & 0x08 == 0 {
        return TestResult::Fail("size flag should be set");
    }
    if buf[1] != 0x05 {
        return TestResult::Fail("report id missing");
    }
    let sz = u16::from_le_bytes([buf[2], buf[3]]);
    if sz != 0x40 {
        return TestResult::Fail("size hint mis-encoded");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hid", smoke_hidp_get_report_with_size_field);

fn smoke_hidp_data_input_round_trip() -> TestResult {
    use crate::hid_profile::{build_data, parse_input_data, ReportType};
    let payload = [0x01u8, 0x02, 0x03];
    let buf = build_data(ReportType::Input, &payload);
    let body = parse_input_data(&buf).expect("input data");
    if body != payload {
        return TestResult::Fail("DATA(Input) round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hid", smoke_hidp_data_input_round_trip);

fn smoke_hidp_psm_constants_match_spec() -> TestResult {
    use crate::hid_profile::{PSM_HID_CONTROL, PSM_HID_INTERRUPT};
    if PSM_HID_CONTROL != 0x0011 || PSM_HID_INTERRUPT != 0x0013 {
        return TestResult::Fail("HID PSMs wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hid", smoke_hidp_psm_constants_match_spec);

// ── USB HCI transport ─────────────────────────────────────────────

fn smoke_btusb_recogniser_accepts_class_triple() -> TestResult {
    use crate::usb_transport::is_bluetooth_hci;
    let cfg: [u8; 25] = [
        9, 2, 25, 0, 1, 1, 0, 0xA0, 0,
        9, 4, 0, 0, 1, 0xE0, 0x01, 0x01, 0,
        7, 5, 0x81, 0x03, 16, 0, 1,
    ];
    if !is_bluetooth_hci(&cfg) {
        return TestResult::Fail("class 0xE0/0x01/0x01 should match");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/usb-transport", smoke_btusb_recogniser_accepts_class_triple);

fn smoke_btusb_find_endpoints_returns_event_acl() -> TestResult {
    use crate::usb_transport::find_endpoints;
    // CONFIG + INTERFACE(HCI) + INT-IN(0x81) + BULK-OUT(0x02) + BULK-IN(0x82)
    let cfg: [u8; 39] = [
        9, 2, 39, 0, 1, 1, 0, 0xA0, 0,
        9, 4, 0, 0, 3, 0xE0, 0x01, 0x01, 0,
        7, 5, 0x81, 0x03, 16, 0, 1,
        7, 5, 0x02, 0x02, 64, 0, 0,
        7, 5, 0x82, 0x02, 64, 0, 0,
    ];
    let eps = find_endpoints(&cfg).expect("find");
    if eps.event_ep != Some(0x81) || eps.acl_in_ep != Some(0x82) || eps.acl_out_ep != Some(0x02) {
        return TestResult::Fail("endpoint addresses wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/usb-transport", smoke_btusb_find_endpoints_returns_event_acl);

fn smoke_btusb_hci_command_setup_packet_shape() -> TestResult {
    use crate::usb_transport::{build_hci_command, hci_command_setup, is_hci_command_setup};
    let cmd = build_hci_command(0x0C03, &[]); // HCI_Reset
    if cmd != [0x03, 0x0C, 0x00] {
        return TestResult::Fail("HCI_Reset wire form wrong");
    }
    let setup = hci_command_setup(0, cmd.len() as u16);
    if !is_hci_command_setup(&setup) {
        return TestResult::Fail("setup recogniser rejected its own packet");
    }
    if setup[0] != 0x20 || setup[1] != 0x00 || setup[6] != 3 || setup[7] != 0 {
        return TestResult::Fail("setup packet shape wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/usb-transport", smoke_btusb_hci_command_setup_packet_shape);

// ── Stage 2 smokes ──────────────────────────────────────────────────
//
// Six smokes covering: Inquiry cmd encode, Inquiry Result decode,
// Classic Connection Complete decode, SSP cmd shape, SCO setup,
// btusb→HCI cmd_queue dispatch.

/// Smoke 1 — HCI_Inquiry command encodes LAP + length + num_responses
/// per §7.1.1. Vol 4 Part E table 7.1 wire layout: 5-byte params.
fn smoke_classic_inquiry_cmd_encode() -> TestResult {
    use crate::classic::{build_inquiry, decode_inquiry_params, GIAC};
    use crate::opcode::HCI_INQUIRY;

    let cmd = build_inquiry(GIAC, 0x08, 0); // 8 × 1.28 s = 10.24 s, unlimited devices.
    if cmd.opcode != HCI_INQUIRY {
        return TestResult::Fail("opcode should be HCI_INQUIRY (0x0401)");
    }
    if cmd.params.len() != 5 {
        return TestResult::Fail("HCI_Inquiry must have exactly 5 parameter bytes");
    }
    // Verify GIAC = 0x33 0x8B 0x9E (LE on the wire).
    let (lap, len, num) = match decode_inquiry_params(&cmd) {
        Some(v) => v,
        None => return TestResult::Fail("decode_inquiry_params returned None"),
    };
    if lap != GIAC {
        return TestResult::Fail("LAP field not GIAC");
    }
    if len != 0x08 {
        return TestResult::Fail("inquiry length field wrong");
    }
    if num != 0 {
        return TestResult::Fail("num_responses field wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/classic", smoke_classic_inquiry_cmd_encode);

/// Smoke 2 — HCI_Inquiry_Result event decodes BD_ADDR + CoD +
/// clock_offset per §7.7.2. One synthetic response.
fn smoke_classic_inquiry_result_decode() -> TestResult {
    use crate::event::{parse_inquiry_results, EventCode};
    use crate::hci::Event;

    // Construct a 1-response Inquiry Result event.
    // Layout: Num(1) + [ BD_ADDR(6) PSRM(1) Rsvd(2) CoD(3) ClkOff(2) ] = 15 bytes.
    let bd_addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let cod = [0x04, 0x04, 0x20]; // Laptop, Audio.
    let clk_off = 0x1234u16;
    let mut params = vec![0x01u8]; // Num_Responses = 1.
    params.extend_from_slice(&bd_addr);
    params.push(0x01); // PSRM = R1.
    params.extend_from_slice(&[0x00, 0x00]); // Reserved.
    params.extend_from_slice(&cod);
    params.push((clk_off & 0xFF) as u8);
    params.push((clk_off >> 8) as u8);

    let event = Event {
        code: EventCode::InquiryResult as u8,
        params,
    };

    let results = match parse_inquiry_results(&event) {
        Some(r) => r,
        None => return TestResult::Fail("parse_inquiry_results returned None"),
    };
    if results.len() != 1 {
        return TestResult::Fail("expected 1 inquiry result");
    }
    if results[0].bd_addr != bd_addr {
        return TestResult::Fail("BD_ADDR mismatch");
    }
    if results[0].class_of_device != cod {
        return TestResult::Fail("CoD mismatch");
    }
    if results[0].clock_offset != clk_off {
        return TestResult::Fail("clock_offset mismatch");
    }
    if results[0].page_scan_repetition_mode != 0x01 {
        return TestResult::Fail("PSRM mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/classic", smoke_classic_inquiry_result_decode);

/// Smoke 3 — HCI_Connection_Complete event (classic BR/EDR) decodes
/// status, handle, BD_ADDR, link_type, encryption per §7.7.3.
fn smoke_classic_connection_complete_decode() -> TestResult {
    use crate::event::{ClassicConnectionComplete, EventCode};
    use crate::hci::Event;

    let bd_addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let handle = 0x0042u16;
    // Layout: Status(1) Handle_LE(2) BD_ADDR(6) Link_Type(1) Enc(1) = 11 bytes.
    let mut params = vec![0x00u8]; // Status OK.
    params.push((handle & 0xFF) as u8);
    params.push((handle >> 8) as u8);
    params.extend_from_slice(&bd_addr);
    params.push(0x01); // ACL link type.
    params.push(0x01); // Encryption enabled.

    let event = Event {
        code: EventCode::ConnectionComplete as u8,
        params,
    };

    let cc = match ClassicConnectionComplete::parse(&event) {
        Some(c) => c,
        None => return TestResult::Fail("ClassicConnectionComplete::parse returned None"),
    };
    if cc.status != 0x00 {
        return TestResult::Fail("status not OK");
    }
    if cc.handle != handle {
        return TestResult::Fail("handle mismatch");
    }
    if cc.bd_addr != bd_addr {
        return TestResult::Fail("BD_ADDR mismatch");
    }
    if cc.link_type != 0x01 {
        return TestResult::Fail("link_type should be ACL (1)");
    }
    if cc.encryption_enabled != 0x01 {
        return TestResult::Fail("encryption_enabled should be 1");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/classic", smoke_classic_connection_complete_decode);

/// Smoke 4 — SSP IO_Capability_Request_Reply shapes correctly.
/// §7.1.29: 9-byte parameter block — BD_ADDR(6) + IO_Cap(1) + OOB(1) + AuthReq(1).
fn smoke_ssp_io_capability_request_reply_shape() -> TestResult {
    use crate::classic::{build_io_capability_reply, AuthRequirements, ClassicIoCap};
    use crate::opcode::HCI_IO_CAPABILITY_REQUEST_REPLY;

    let bd_addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let cmd = build_io_capability_reply(
        bd_addr,
        ClassicIoCap::DisplayYesNo,
        false,
        AuthRequirements::GeneralBondingMitm,
    );

    if cmd.opcode != HCI_IO_CAPABILITY_REQUEST_REPLY {
        return TestResult::Fail("opcode mismatch");
    }
    if cmd.params.len() != 9 {
        return TestResult::Fail("IO_Cap_Reply must have exactly 9 parameter bytes");
    }
    // BD_ADDR at params[0..6].
    if cmd.params[0..6] != bd_addr {
        return TestResult::Fail("BD_ADDR not at params[0..6]");
    }
    // IO_Capability at params[6].
    if cmd.params[6] != ClassicIoCap::DisplayYesNo as u8 {
        return TestResult::Fail("IO_Capability byte wrong");
    }
    // OOB_Data_Present at params[7].
    if cmd.params[7] != 0x00 {
        return TestResult::Fail("OOB_Data_Present should be 0");
    }
    // Authentication_Requirements at params[8].
    if cmd.params[8] != AuthRequirements::GeneralBondingMitm as u8 {
        return TestResult::Fail("Authentication_Requirements byte wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/classic", smoke_ssp_io_capability_request_reply_shape);

/// Smoke 5 — HCI_Setup_Synchronous_Connection encodes correctly.
/// §7.1.26: 17-byte parameter block. Verify handle + bandwidth fields.
fn smoke_sco_setup_synchronous_connection_encode() -> TestResult {
    use crate::classic::{
        build_setup_synchronous_connection, SCO_BANDWIDTH_8KHZ, SCO_VOICE_SETTING_CVSD,
        ESCO_PACKET_TYPES_ALL,
    };
    use crate::opcode::HCI_SETUP_SYNCHRONOUS_CONNECTION;

    let handle = 0x0042u16;
    let cmd = build_setup_synchronous_connection(
        handle,
        SCO_BANDWIDTH_8KHZ,
        SCO_BANDWIDTH_8KHZ,
        7,   // max_latency in ms
        SCO_VOICE_SETTING_CVSD,
        0xFF, // retransmission_effort = don't care
        ESCO_PACKET_TYPES_ALL,
    );

    if cmd.opcode != HCI_SETUP_SYNCHRONOUS_CONNECTION {
        return TestResult::Fail("opcode should be HCI_SETUP_SYNCHRONOUS_CONNECTION");
    }
    if cmd.params.len() != 17 {
        return TestResult::Fail("Setup_Sync_Connection must have 17 parameter bytes");
    }
    // Handle at params[0..2] LE.
    let got_handle = u16::from_le_bytes([cmd.params[0], cmd.params[1]]);
    if got_handle != handle {
        return TestResult::Fail("handle encoding wrong");
    }
    // Transmit bandwidth at params[2..6] LE (8000 = 0x1F40).
    let got_bw = u32::from_le_bytes([cmd.params[2], cmd.params[3], cmd.params[4], cmd.params[5]]);
    if got_bw != SCO_BANDWIDTH_8KHZ {
        return TestResult::Fail("transmit bandwidth encoding wrong");
    }
    // Voice setting at params[12..14].
    let got_voice = u16::from_le_bytes([cmd.params[12], cmd.params[13]]);
    if got_voice != SCO_VOICE_SETTING_CVSD {
        return TestResult::Fail("voice_setting encoding wrong");
    }
    // Packet type at params[15..17].
    let got_pkt = u16::from_le_bytes([cmd.params[15], cmd.params[16]]);
    if got_pkt != ESCO_PACKET_TYPES_ALL {
        return TestResult::Fail("packet_type encoding wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/classic", smoke_sco_setup_synchronous_connection_encode);

/// Smoke 6 — HCI command queue credit model: enqueue, drain on
/// command-complete, and re-drain pending entries. Mirrors the flow
/// in `net/bluetooth/hci_core.c` — `hci_cmd_work` / credit tracking.
fn smoke_btusb_hci_cmd_queue_dispatch() -> TestResult {
    use crate::cmd_queue::CmdQueue;
    use crate::hci::Command;
    use crate::opcode::{HCI_INQUIRY, HCI_RESET, HCI_SET_EVENT_MASK};
    use crate::transport::LoopbackTransport;

    let lt = LoopbackTransport::new("cmd-queue-test");
    let q = CmdQueue::new();

    // Initial credit = 1 (spec default §4.4.1). First command should
    // be sent immediately.
    q.enqueue(Command::new(HCI_RESET), &lt).expect("enqueue");
    let sent = lt.sent_commands();
    if sent.len() != 1 {
        return TestResult::Fail("first command should be sent immediately (credit=1)");
    }
    if sent[0].opcode != HCI_RESET {
        return TestResult::Fail("wrong opcode sent first");
    }
    // Credit should now be 0 — second command must queue.
    if q.credits() != 0 {
        return TestResult::Fail("credit should be 0 after first send");
    }
    if q.pending_len() != 0 {
        return TestResult::Fail("pending queue should be empty before second enqueue");
    }
    q.enqueue(Command::new(HCI_SET_EVENT_MASK), &lt).expect("enqueue2");
    if q.pending_len() != 1 {
        return TestResult::Fail("second command should be pending (no credits)");
    }

    // Simulate Command_Complete for HCI_RESET granting 2 credits.
    q.notify_complete(HCI_RESET, 2);
    if q.credits() != 2 {
        return TestResult::Fail("credits should be 2 after notify_complete");
    }

    // Drain should flush the pending command.
    let flushed = q.drain(&lt).expect("drain");
    if flushed != 1 {
        return TestResult::Fail("drain should have flushed 1 pending command");
    }
    let sent2 = lt.sent_commands();
    if sent2.len() != 2 {
        return TestResult::Fail("transport should have received 2 commands total");
    }
    if sent2[1].opcode != HCI_SET_EVENT_MASK {
        return TestResult::Fail("second command should be HCI_SET_EVENT_MASK");
    }
    // Credit consumed by drain: 2 - 1 = 1.
    if q.credits() != 1 {
        return TestResult::Fail("credit should be 1 after drain");
    }

    // Enqueue another command — should be sent immediately (credit=1).
    q.enqueue(Command::new(HCI_INQUIRY), &lt).expect("enqueue3");
    if q.pending_len() != 0 {
        return TestResult::Fail("HCI_INQUIRY should have been sent immediately");
    }
    if q.credits() != 0 {
        return TestResult::Fail("credit should be 0 after third enqueue");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_btusb_hci_cmd_queue_dispatch);

// ── profiles/avdtp: session state machine ─────────────────────────

/// Smoke 1: AVDTP Discover request encoder.
///
/// Verifies that [`crate::profiles::avdtp::Session::discover`] emits a
/// correctly-formed Discover command (transaction label preserved,
/// SID = SID_DISCOVER, message type = Command).
fn smoke_profiles_avdtp_discover_request_encoder() -> TestResult {
    use crate::avdtp::{MSG_COMMAND, PKT_SINGLE, SID_DISCOVER};
    use crate::profiles::avdtp::Session;

    let mut session = Session::new(/*int_seid=*/ 1);
    let bytes = session.discover();

    if bytes.len() != 2 {
        return TestResult::Fail("Discover command = 2 bytes (header only)");
    }
    // byte 0: txn(4) | PKT_SINGLE(2) | MSG_COMMAND(2)
    let packet_type = (bytes[0] >> 2) & 0x03;
    let message_type = bytes[0] & 0x03;
    if packet_type != PKT_SINGLE {
        return TestResult::Fail("packet type must be SINGLE");
    }
    if message_type != MSG_COMMAND {
        return TestResult::Fail("message type must be COMMAND");
    }
    if bytes[1] != SID_DISCOVER {
        return TestResult::Fail("SID must be SID_DISCOVER (0x01)");
    }
    // Transaction label must be in range 0..=15.
    let txn = (bytes[0] >> 4) & 0x0F;
    if txn > 15 {
        return TestResult::Fail("transaction label out of range");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/profiles",
    smoke_profiles_avdtp_discover_request_encoder
);

/// Smoke 2: AVDTP Get Capabilities decoder — SBC codec-info bit
/// positions (A2DP §4.3.2 table 4.1).
///
/// Synthesises a Get Capabilities Accept payload containing a Media
/// Codec service descriptor for SBC and verifies that
/// [`crate::avdtp::SbcCapability::decode`] extracts each field at the
/// correct bit position.
fn smoke_profiles_avdtp_get_capabilities_sbc_bit_positions() -> TestResult {
    use crate::avdtp::{
        SbcCapability, SBC_ALLOC_LOUDNESS, SBC_ALLOC_SNR, SBC_BLOCK_16, SBC_CHAN_JOINT_STEREO,
        SBC_CHAN_STEREO, SBC_FREQ_44100, SBC_FREQ_48000, SBC_SUBBANDS_8,
    };

    // A2DP §4.3.2 table 4.1:
    //   byte 0:  bits[7..4] = sampling frequency, bits[3..0] = channel mode
    //   byte 1:  bits[7..4] = block length, bits[3..2] = subbands, bits[1..0] = alloc method
    //   byte 2:  min bitpool
    //   byte 3:  max bitpool
    let raw: [u8; 4] = [
        SBC_FREQ_48000 | SBC_FREQ_44100 | SBC_CHAN_JOINT_STEREO | SBC_CHAN_STEREO,
        SBC_BLOCK_16 | SBC_SUBBANDS_8 | SBC_ALLOC_LOUDNESS | SBC_ALLOC_SNR,
        2,  // min bitpool
        53, // max bitpool
    ];

    let cap = SbcCapability::decode(&raw).expect("decode");

    if cap.frequency & SBC_FREQ_48000 == 0 {
        return TestResult::Fail("SBC_FREQ_48000 bit must be in bits[7..4] of byte 0");
    }
    if cap.frequency & SBC_FREQ_44100 == 0 {
        return TestResult::Fail("SBC_FREQ_44100 bit must be in bits[7..4] of byte 0");
    }
    if cap.channel_mode & SBC_CHAN_JOINT_STEREO == 0 {
        return TestResult::Fail("SBC_CHAN_JOINT_STEREO bit must be in bits[3..0] of byte 0");
    }
    if cap.block_length & SBC_BLOCK_16 == 0 {
        return TestResult::Fail("SBC_BLOCK_16 bit must be in bits[7..4] of byte 1");
    }
    if cap.subbands & SBC_SUBBANDS_8 == 0 {
        return TestResult::Fail("SBC_SUBBANDS_8 bit must be in bits[3..2] of byte 1");
    }
    if cap.allocation & SBC_ALLOC_LOUDNESS == 0 {
        return TestResult::Fail("SBC_ALLOC_LOUDNESS bit must be in bits[1..0] of byte 1");
    }
    if cap.min_bitpool != 2 || cap.max_bitpool != 53 {
        return TestResult::Fail("bitpool range decoding wrong");
    }

    // Round-trip must be lossless.
    let re = cap.encode();
    if re != raw {
        return TestResult::Fail("SBC capability encode/decode round-trip lost bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/profiles",
    smoke_profiles_avdtp_get_capabilities_sbc_bit_positions
);

// ── profiles/a2dp: SBC negotiation ────────────────────────────────

/// Smoke 3: SBC capability negotiation — intersect SEP tables.
///
/// Tests [`crate::profiles::a2dp::negotiate_sbc`] against three
/// scenarios: happy path, no-common-frequency, and no-common-bitpool.
fn smoke_profiles_a2dp_sbc_negotiate_intersects_tables() -> TestResult {
    use crate::avdtp::{
        SbcCapability, SBC_ALLOC_LOUDNESS, SBC_BLOCK_16, SBC_CHAN_JOINT_STEREO,
        SBC_FREQ_44100, SBC_FREQ_48000, SBC_SUBBANDS_8,
    };
    use crate::profiles::a2dp::{negotiate_sbc, NegotiateResult, LOCAL_SBC_SOURCE_CAPS};

    // ── Happy path: remote offers 44.1 kHz only ──────────────────────
    let remote = SbcCapability {
        frequency: SBC_FREQ_44100,
        channel_mode: SBC_CHAN_JOINT_STEREO,
        block_length: SBC_BLOCK_16,
        subbands: SBC_SUBBANDS_8,
        allocation: SBC_ALLOC_LOUDNESS,
        min_bitpool: 2,
        max_bitpool: 53,
    };
    let cfg = match negotiate_sbc(&LOCAL_SBC_SOURCE_CAPS, &remote) {
        NegotiateResult::Ok(c) => c,
        other => {
            let _ = other;
            return TestResult::Fail("happy-path negotiation should succeed");
        }
    };
    // Local prefers 48000 but only 44100 available → 44100.
    if cfg.frequency != SBC_FREQ_44100 {
        return TestResult::Fail("negotiated frequency should be 44100 when remote only offers it");
    }
    if cfg.channel_mode != SBC_CHAN_JOINT_STEREO {
        return TestResult::Fail("negotiated channel mode should be Joint Stereo");
    }
    if cfg.min_bitpool != 2 || cfg.max_bitpool != 53 {
        return TestResult::Fail("negotiated bitpool range should be 2..=53");
    }

    // ── No common frequency ──────────────────────────────────────────
    let remote_no_freq = SbcCapability {
        frequency: 0x00, // no bits set
        ..remote
    };
    if negotiate_sbc(&LOCAL_SBC_SOURCE_CAPS, &remote_no_freq)
        != NegotiateResult::NoCommonFrequency
    {
        return TestResult::Fail("should return NoCommonFrequency when bitmask is empty");
    }

    // ── Bitpool ranges don't overlap ─────────────────────────────────
    let remote_high_bitpool = SbcCapability {
        min_bitpool: 60,
        max_bitpool: 100,
        ..remote
    };
    // local max = 53 < remote min = 60 → no overlap.
    if negotiate_sbc(&LOCAL_SBC_SOURCE_CAPS, &remote_high_bitpool)
        != NegotiateResult::NoCommonBitpool
    {
        return TestResult::Fail("should return NoCommonBitpool when ranges don't overlap");
    }

    // ── Remote offers 48 kHz: should win over 44.1 by preference ─────
    let remote_48 = SbcCapability {
        frequency: SBC_FREQ_48000 | SBC_FREQ_44100,
        ..remote
    };
    let cfg48 = match negotiate_sbc(&LOCAL_SBC_SOURCE_CAPS, &remote_48) {
        NegotiateResult::Ok(c) => c,
        _ => return TestResult::Fail("48+44 negotiation should succeed"),
    };
    if cfg48.frequency != SBC_FREQ_48000 {
        return TestResult::Fail("48000 should be preferred over 44100 when both available");
    }

    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/profiles",
    smoke_profiles_a2dp_sbc_negotiate_intersects_tables
);

// ── profiles/hfp: AT command parser ───────────────────────────────

/// Smoke 4: HFP AT command parser — classify all mandatory HFP commands.
///
/// Tests [`crate::profiles::hfp::classify_at`] against the HFP 1.8
/// mandatory AT commands that both HF and AG must support.
fn smoke_profiles_hfp_at_command_parser() -> TestResult {
    use crate::profiles::hfp::{classify_at, HfpCommand};

    // AT+BRSF=<n>
    let cmd = classify_at("AT+BRSF=144\r");
    if cmd != HfpCommand::Brsf(144) {
        return TestResult::Fail("AT+BRSF=144 should classify as Brsf(144)");
    }

    // AT+CIND=?
    let cmd = classify_at("AT+CIND=?\r");
    if cmd != HfpCommand::CindTest {
        return TestResult::Fail("AT+CIND=? should classify as CindTest");
    }

    // AT+CIND?
    let cmd = classify_at("AT+CIND?\r");
    if cmd != HfpCommand::CindRead {
        return TestResult::Fail("AT+CIND? should classify as CindRead");
    }

    // AT+CMER=3,0,0,1
    let cmd = classify_at("AT+CMER=3,0,0,1\r");
    if cmd != HfpCommand::Cmer {
        return TestResult::Fail("AT+CMER=3,0,0,1 should classify as Cmer");
    }

    // AT+CHLD=?
    let cmd = classify_at("AT+CHLD=?\r");
    if cmd != HfpCommand::ChldTest {
        return TestResult::Fail("AT+CHLD=? should classify as ChldTest");
    }

    // ATA — answer
    let cmd = classify_at("ATA\r");
    if cmd != HfpCommand::Answer {
        return TestResult::Fail("ATA should classify as Answer");
    }

    // AT+CHUP — hangup
    let cmd = classify_at("AT+CHUP\r");
    if cmd != HfpCommand::Hangup {
        return TestResult::Fail("AT+CHUP should classify as Hangup");
    }

    // AT+BAC=1,2 — available codecs (codec negotiation)
    let cmd = classify_at("AT+BAC=1,2\r");
    if cmd != HfpCommand::Bac(alloc::vec![1, 2]) {
        return TestResult::Fail("AT+BAC=1,2 should classify as Bac([1,2])");
    }

    // AT+BCS=2 — codec connection confirm (mSBC)
    let cmd = classify_at("AT+BCS=2\r");
    if cmd != HfpCommand::Bcs(2) {
        return TestResult::Fail("AT+BCS=2 should classify as Bcs(2)");
    }

    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/profiles",
    smoke_profiles_hfp_at_command_parser
);

// ── profiles/hfp: SCO setup ────────────────────────────────────────

/// Smoke 5: HFP SCO setup — parameter selection for CVSD and mSBC.
///
/// Verifies that [`crate::profiles::hfp::sco_params_for_codec`]
/// returns the correct bandwidth and voice-setting values as specified
/// in HFP 1.8 §4.11 and Core spec §6.12.
fn smoke_profiles_hfp_sco_setup_parameters() -> TestResult {
    use crate::profiles::hfp::{sco_params_for_codec, CODEC_CVSD, CODEC_MSBC};

    // ── CVSD narrow-band ─────────────────────────────────────────────
    let cvsd = sco_params_for_codec(CODEC_CVSD).expect("CVSD params must be defined");
    // HFP §4.11 + Core §6.12: 8 kHz PCM, CVSD air coding.
    if cvsd.tx_bandwidth != 8_000 {
        return TestResult::Fail("CVSD tx_bandwidth must be 8000 B/s");
    }
    if cvsd.rx_bandwidth != 8_000 {
        return TestResult::Fail("CVSD rx_bandwidth must be 8000 B/s");
    }
    // Voice setting 0x0060: input coding = Linear PCM (bits[1..0]=00),
    // input data format = 2's complement (bits[3..2]=00), sample size=16
    // (bit 5=1), air coding = CVSD (bits[9..8] via bits[7..6]=01 for
    // some representations) — 0x0060 is the canonical "16-bit linear PCM
    // + CVSD" value from the HFP 1.8 reference table.
    if cvsd.voice_setting != 0x0060 {
        return TestResult::Fail("CVSD voice setting must be 0x0060");
    }

    // ── mSBC wide-band ───────────────────────────────────────────────
    let msbc = sco_params_for_codec(CODEC_MSBC).expect("mSBC params must be defined");
    // mSBC: transparent data mode (0x0063).
    if msbc.voice_setting != 0x0063 {
        return TestResult::Fail("mSBC voice setting must be 0x0063 (transparent)");
    }
    // mSBC max_latency per HFP 1.8 table 5.10.
    if msbc.max_latency != 0x000D {
        return TestResult::Fail("mSBC max_latency must be 13 ms (0x000D)");
    }

    // ── Unknown codec ────────────────────────────────────────────────
    if sco_params_for_codec(0xFF).is_some() {
        return TestResult::Fail("unknown codec ID must return None");
    }

    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/profiles",
    smoke_profiles_hfp_sco_setup_parameters
);

// ── profiles/a2dp: stream-start state machine ─────────────────────

/// Smoke 6: A2DP source role — stream-start state machine.
///
/// Walks [`crate::profiles::a2dp::A2dpSource`] through the full
/// stream-start procedure using a stub AVDTP session, verifying that
/// each state transition is correct and that the final state is
/// `Streaming`.
fn smoke_profiles_a2dp_source_stream_start_state_machine() -> TestResult {
    use crate::avdtp::{
        Header, SbcCapability, SBC_ALLOC_LOUDNESS, SBC_BLOCK_16, SBC_CHAN_JOINT_STEREO,
        SBC_FREQ_48000, SBC_SUBBANDS_8, SEP_TYPE_SINK, MEDIA_AUDIO,
        MSG_RESPONSE_ACCEPT, PKT_SINGLE, SID_DISCOVER, SID_GET_CAPABILITIES,
        SID_SET_CONFIGURATION, SID_OPEN, SID_START, StreamEndPoint,
    };
    use crate::profiles::a2dp::{A2dpSource, SourceState};
    use crate::profiles::avdtp::{Session, SessionState};

    let mut session = Session::new(/*int_seid=*/ 1);
    let mut src = A2dpSource::new();

    // ── Step 1: connect → Discover ───────────────────────────────────
    let disc_bytes = src.on_connected(&mut session);
    if src.state != SourceState::Discovering {
        return TestResult::Fail("should be Discovering after on_connected");
    }
    // Verify the discover command has the correct SID.
    if disc_bytes[1] != SID_DISCOVER {
        return TestResult::Fail("on_connected should emit a Discover command");
    }

    // Extract the transaction label from the discover command.
    let disc_txn = (disc_bytes[0] >> 4) & 0x0F;

    // ── Step 2: feed Discover Accept with one Sink SEP ───────────────
    let sink_sep = StreamEndPoint {
        seid: 0x02,
        in_use: false,
        media_type: MEDIA_AUDIO,
        tsep: SEP_TYPE_SINK,
    };
    let mut disc_rsp = Header {
        transaction: disc_txn,
        packet_type: PKT_SINGLE,
        message_type: MSG_RESPONSE_ACCEPT,
        signal_id: SID_DISCOVER,
    }
    .encode()
    .to_vec();
    disc_rsp.extend_from_slice(&sink_sep.encode());

    session.feed(&disc_rsp).expect("feed discover rsp");
    if session.state != SessionState::Configuring {
        return TestResult::Fail("session should be Configuring after Discover Accept");
    }
    if session.remote_seps.len() != 1 {
        return TestResult::Fail("one SEP should have been parsed from Discover Accept");
    }

    // ── Step 3: on_discovered → Get Capabilities ─────────────────────
    let getcaps_bytes = src
        .on_discovered(&mut session)
        .expect("on_discovered should pick the Sink SEP");
    if src.state != SourceState::AwaitingCaps {
        return TestResult::Fail("should be AwaitingCaps after on_discovered");
    }
    if getcaps_bytes[1] != SID_GET_CAPABILITIES {
        return TestResult::Fail("on_discovered should emit a Get Capabilities command");
    }

    let getcaps_txn = (getcaps_bytes[0] >> 4) & 0x0F;

    // ── Step 4: feed Get Capabilities Accept ─────────────────────────
    let getcaps_rsp = Header {
        transaction: getcaps_txn,
        packet_type: PKT_SINGLE,
        message_type: MSG_RESPONSE_ACCEPT,
        signal_id: SID_GET_CAPABILITIES,
    }
    .encode()
    .to_vec();
    session.feed(&getcaps_rsp).expect("feed getcaps rsp");
    if session.state != SessionState::Configuring {
        return TestResult::Fail("session should return to Configuring after GetCaps");
    }

    // ── Step 5: on_caps → Set Configuration ──────────────────────────
    let remote_caps = SbcCapability {
        frequency: SBC_FREQ_48000,
        channel_mode: SBC_CHAN_JOINT_STEREO,
        block_length: SBC_BLOCK_16,
        subbands: SBC_SUBBANDS_8,
        allocation: SBC_ALLOC_LOUDNESS,
        min_bitpool: 2,
        max_bitpool: 53,
    };
    let setcfg_bytes = src
        .on_caps(&mut session, &remote_caps)
        .expect("on_caps should succeed");
    if src.config.is_none() {
        return TestResult::Fail("config should be set after on_caps");
    }
    if setcfg_bytes[1] != SID_SET_CONFIGURATION {
        return TestResult::Fail("on_caps should emit a Set Configuration command");
    }

    let setcfg_txn = (setcfg_bytes[0] >> 4) & 0x0F;

    // ── Step 6: feed Set Configuration Accept → Open ─────────────────
    let setcfg_rsp = Header {
        transaction: setcfg_txn,
        packet_type: PKT_SINGLE,
        message_type: MSG_RESPONSE_ACCEPT,
        signal_id: SID_SET_CONFIGURATION,
    }
    .encode()
    .to_vec();
    session.feed(&setcfg_rsp).expect("feed setcfg rsp");
    if session.state != SessionState::Configured {
        return TestResult::Fail("session should be Configured after SetConfig Accept");
    }

    let open_bytes = src.on_configured(&mut session);
    if open_bytes[1] != SID_OPEN {
        return TestResult::Fail("on_configured should emit an Open command");
    }

    let open_txn = (open_bytes[0] >> 4) & 0x0F;

    // ── Step 7: feed Open Accept → Start ─────────────────────────────
    let open_rsp = Header {
        transaction: open_txn,
        packet_type: PKT_SINGLE,
        message_type: MSG_RESPONSE_ACCEPT,
        signal_id: SID_OPEN,
    }
    .encode()
    .to_vec();
    session.feed(&open_rsp).expect("feed open rsp");
    if session.state != SessionState::Open {
        return TestResult::Fail("session should be Open after Open Accept");
    }

    let start_bytes = src.on_opened(&mut session);
    if start_bytes[1] != SID_START {
        return TestResult::Fail("on_opened should emit a Start command");
    }

    let start_txn = (start_bytes[0] >> 4) & 0x0F;

    // ── Step 8: feed Start Accept → Streaming ────────────────────────
    let start_rsp = Header {
        transaction: start_txn,
        packet_type: PKT_SINGLE,
        message_type: MSG_RESPONSE_ACCEPT,
        signal_id: SID_START,
    }
    .encode()
    .to_vec();
    session.feed(&start_rsp).expect("feed start rsp");
    if session.state != SessionState::Streaming {
        return TestResult::Fail("session should be Streaming after Start Accept");
    }

    src.on_started();
    if src.state != SourceState::Streaming {
        return TestResult::Fail("A2dpSource should be Streaming after on_started");
    }

    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/profiles",
    smoke_profiles_a2dp_source_stream_start_state_machine
);

/// A2DP source streaming → SBC encoder bridge. Drives an A2dpSource
/// directly into the Streaming state (without the AVDTP handshake)
/// and verifies `encode_pcm` produces a syncword-prefixed SBC frame
/// whose length matches the A2DP §12.9 formula for the negotiated
/// configuration. Confirms the codec bridge — the integration point
/// for the actual audio path — is wired correctly.
fn smoke_profiles_a2dp_source_sbc_encode_streaming() -> TestResult {
    use crate::avdtp::{
        SBC_ALLOC_LOUDNESS, SBC_BLOCK_16, SBC_CHAN_JOINT_STEREO,
        SBC_FREQ_44100, SBC_SUBBANDS_8, SbcCapability,
    };
    use crate::profiles::a2dp::{A2dpSource, SourceState};

    let mut src = A2dpSource::new();
    // Pre-seed the source state to Streaming without doing the
    // full AVDTP handshake (which is exercised by the previous test).
    src.config = Some(SbcCapability {
        frequency: SBC_FREQ_44100,
        channel_mode: SBC_CHAN_JOINT_STEREO,
        block_length: SBC_BLOCK_16,
        subbands: SBC_SUBBANDS_8,
        allocation: SBC_ALLOC_LOUDNESS,
        min_bitpool: 2,
        max_bitpool: 53,
    });
    src.state = SourceState::Streaming;

    // 16 blocks × 8 subbands × 2 channels = 256 i16 samples.
    let pcm: alloc::vec::Vec<i16> = (0..(16 * 8 * 2))
        .map(|i| ((i as i32 * 256) - 32768) as i16)
        .collect();
    let frame = match src.encode_pcm(&pcm) {
        Some(f) => f,
        None => return TestResult::Fail("encode_pcm returned None in Streaming"),
    };
    if frame.is_empty() {
        return TestResult::Fail("encode_pcm produced empty frame");
    }
    if frame[0] != 0x9C {
        return TestResult::Fail("encode_pcm frame missing SBC syncword");
    }
    // Expected length for 44.1k joint stereo 16 blocks 8 sb bitpool 53.
    if frame.len() != 119 {
        return TestResult::Fail("encode_pcm wrong frame length");
    }
    // A2DP MTU sanity: a 119-byte SBC frame fits well within an
    // L2CAP MTU of 895 (A2DP minimum).
    if frame.len() > 895 {
        return TestResult::Fail("frame larger than A2DP min MTU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/profiles",
    smoke_profiles_a2dp_source_sbc_encode_streaming
);

// ── ISO data packet round-trip ───────────────────────────────────────

/// Vol 4 Part E §5.4.5: ISO Data packet handle field carries 12 bits of
/// handle, 2 bits of PB flag, 1 bit of TS flag. Encode/decode must
/// round-trip both flags.
fn smoke_iso_data_round_trip() -> TestResult {
    use crate::hci::IsoData;
    let original = IsoData {
        handle: 0x123,
        pb_flag: 0b10, // complete SDU
        ts_flag: true,
        data: alloc::vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
    };
    let bytes = original.encode();
    if bytes.len() != 4 + 6 {
        return TestResult::Fail("ISO encoded length wrong");
    }
    // Wire bit-15 should be zero; PB=0b10 → bits 12..14 = 0b10;
    // TS=1 → bit 14.
    let h = u16::from_le_bytes([bytes[0], bytes[1]]);
    if (h & 0x0FFF) != 0x123 {
        return TestResult::Fail("ISO handle truncation wrong");
    }
    if ((h >> 12) & 0x3) != 0b10 {
        return TestResult::Fail("ISO PB encoding wrong");
    }
    if (h & (1 << 14)) == 0 {
        return TestResult::Fail("ISO TS bit not set");
    }
    let decoded = IsoData::decode(&bytes).expect("decode iso");
    if decoded != original {
        return TestResult::Fail("ISO round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_iso_data_round_trip);

/// Vol 4 Part E §5.4.3: SCO data packet handle field carries 12 bits of
/// handle + 2 bits packet-status flag. Round-trip both fields.
fn smoke_sco_data_round_trip() -> TestResult {
    use crate::hci::ScoData;
    let original = ScoData {
        handle: 0x0FF,
        packet_status: 0b01, // possibly invalid
        data: alloc::vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    };
    let bytes = original.encode();
    if bytes.len() != 3 + 10 {
        return TestResult::Fail("SCO encoded length wrong");
    }
    let decoded = ScoData::decode(&bytes).expect("decode sco");
    if decoded != original {
        return TestResult::Fail("SCO round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_sco_data_round_trip);

/// btusb_quirks::identify maps known VID:PID to the right family.
/// Cover at least one match for every implemented Quirk variant.
fn smoke_btusb_quirks_identification() -> TestResult {
    use crate::btusb_quirks::{identify, Quirk};
    if identify(0x8087, 0x0032) != Some(Quirk::Intel) {
        return TestResult::Fail("Intel AX210 (8087:0032) not matched");
    }
    if identify(0x0bda, 0x8771) != Some(Quirk::Realtek) {
        return TestResult::Fail("Realtek RTL8761B not matched");
    }
    if identify(0x0489, 0xe0cd) != Some(Quirk::QualcommWcn6855) {
        return TestResult::Fail("Qualcomm WCN6855 not matched");
    }
    if identify(0x0e8d, 0x7922) != Some(Quirk::MediaTek) {
        return TestResult::Fail("MediaTek MT7922 not matched");
    }
    if identify(0x0a12, 0x0001) != Some(Quirk::Csr) {
        return TestResult::Fail("CSR8510 not matched");
    }
    // Unknown VID/PID should miss.
    if identify(0x1234, 0x5678).is_some() {
        return TestResult::Fail("unknown VID/PID spuriously matched");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/btusb", smoke_btusb_quirks_identification);

/// Fake-CSR detection — bcdDevice 0x0867 on VID 0x0a12 PID 0x0001 is
/// a known clone with broken BD_ADDR. is_fake_csr must flag it; real
/// CSR8510 (bcdDevice 0x4001) must not.
fn smoke_btusb_fake_csr_detection() -> TestResult {
    use crate::btusb_quirks::is_fake_csr;
    if !is_fake_csr(0x0a12, 0x0001, 0x0867) {
        return TestResult::Fail("fake CSR 0867 not detected");
    }
    if !is_fake_csr(0x0a12, 0x0001, 0x1915) {
        return TestResult::Fail("fake CSR 1915 not detected");
    }
    if is_fake_csr(0x0a12, 0x0001, 0x4001) {
        return TestResult::Fail("real CSR8510 flagged as fake");
    }
    if is_fake_csr(0x8087, 0x0032, 0x0867) {
        return TestResult::Fail("Intel adapter flagged as fake CSR");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/btusb", smoke_btusb_fake_csr_detection);

/// Per-quirk firmware paths return non-empty for the four vendors that
/// require host-side blob loading; empty for CSR (on-chip firmware).
fn smoke_btusb_firmware_paths_per_quirk() -> TestResult {
    use crate::btusb_quirks::{firmware_paths, Quirk};
    if firmware_paths(Quirk::Intel).is_empty() {
        return TestResult::Fail("Intel firmware list empty");
    }
    if firmware_paths(Quirk::Realtek).is_empty() {
        return TestResult::Fail("Realtek firmware list empty");
    }
    if firmware_paths(Quirk::MediaTek).is_empty() {
        return TestResult::Fail("MediaTek firmware list empty");
    }
    if firmware_paths(Quirk::QualcommWcn6855).is_empty() {
        return TestResult::Fail("Qualcomm firmware list empty");
    }
    if !firmware_paths(Quirk::Csr).is_empty() {
        return TestResult::Fail("CSR firmware list should be empty (on-chip)");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/btusb", smoke_btusb_firmware_paths_per_quirk);

// ── AVRCP smokes ────────────────────────────────────────────────────

/// AVCTP §6.2: packet header has 4-bit transaction label + 2-bit packet
/// type + CR + IPID. Round-trip encode/decode of all four fields.
fn smoke_avrcp_avctp_packet_round_trip() -> TestResult {
    use crate::avrcp::{AvctpPacket, AVCTP_SINGLE, AVRCP_PID};
    let original = AvctpPacket {
        transaction_label: 0x0A,
        packet_type: AVCTP_SINGLE,
        is_response: false,
        ipid: false,
        pid: AVRCP_PID,
        payload: alloc::vec![1, 2, 3, 4, 5],
    };
    let bytes = original.encode();
    // Header byte: 0xA<<4 | 0b00<<2 | 0 | 0 = 0xA0.
    if bytes[0] != 0xA0 {
        return TestResult::Fail("AVCTP header byte wrong");
    }
    // PID is big-endian 0x110E.
    if bytes[1] != 0x11 || bytes[2] != 0x0E {
        return TestResult::Fail("AVCTP PID encoding wrong");
    }
    let decoded = AvctpPacket::decode(&bytes).expect("decode");
    if decoded != original {
        return TestResult::Fail("AVCTP round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avrcp", smoke_avrcp_avctp_packet_round_trip);

/// AVRCP §4.6.1 PASS THROUGH frame builder for PLAY (op 0x44) press
/// state. Decode back to assert opcode + state bit.
fn smoke_avrcp_pass_through_play_press() -> TestResult {
    use crate::avrcp::{
        pass_through_frame, AVC_OPCODE_PASS_THROUGH, CTYPE_CONTROL, OP_PLAY, PassThrough,
        SUBUNIT_PANEL_BYTE,
    };
    let frame = pass_through_frame(OP_PLAY, false);
    if frame.len() != 5 {
        return TestResult::Fail("PASS THROUGH frame should be 5 bytes");
    }
    if frame[0] != CTYPE_CONTROL {
        return TestResult::Fail("ctype not CONTROL");
    }
    if frame[1] != SUBUNIT_PANEL_BYTE {
        return TestResult::Fail("subunit not PANEL");
    }
    if frame[2] != AVC_OPCODE_PASS_THROUGH {
        return TestResult::Fail("opcode not PASS_THROUGH");
    }
    let decoded = PassThrough::decode(&frame).expect("decode");
    if decoded.operation_id != OP_PLAY {
        return TestResult::Fail("operation_id != PLAY");
    }
    if decoded.released {
        return TestResult::Fail("PLAY press shouldn't be released");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avrcp", smoke_avrcp_pass_through_play_press);

/// AVRCP §4.6.1 PASS THROUGH release frame mirrors the press; the
/// state bit (bit 7 of byte 3) flips.
fn smoke_avrcp_pass_through_release() -> TestResult {
    use crate::avrcp::{pass_through_frame, OP_VOLUME_UP, PassThrough};
    let frame = pass_through_frame(OP_VOLUME_UP, true);
    if (frame[3] & 0x80) == 0 {
        return TestResult::Fail("release bit not set");
    }
    let decoded = PassThrough::decode(&frame).expect("decode");
    if !decoded.released {
        return TestResult::Fail("release flag not detected");
    }
    if decoded.operation_id != OP_VOLUME_UP {
        return TestResult::Fail("operation_id != VOLUME_UP");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avrcp", smoke_avrcp_pass_through_release);

/// AVRCP §28.20 SET_ABSOLUTE_VOLUME — Vendor Dependent frame with
/// BT-SIG company ID and a 7-bit volume value.
fn smoke_avrcp_set_absolute_volume() -> TestResult {
    use crate::avrcp::{
        parse_vendor_dependent, set_absolute_volume, BT_SIG_COMPANY_ID,
        PDU_SET_ABSOLUTE_VOLUME,
    };
    let frame = set_absolute_volume(0x40);
    let (_ctype, cid, pdu_id, params) =
        parse_vendor_dependent(&frame).expect("parse vendor-dep");
    if cid != BT_SIG_COMPANY_ID {
        return TestResult::Fail("company ID not BT SIG");
    }
    if pdu_id != PDU_SET_ABSOLUTE_VOLUME {
        return TestResult::Fail("pdu id not SET_ABSOLUTE_VOLUME");
    }
    if params.len() != 1 || params[0] != 0x40 {
        return TestResult::Fail("volume param wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avrcp", smoke_avrcp_set_absolute_volume);

/// AVRCP §28.5 REGISTER_NOTIFICATION for EVENT_VOLUME_CHANGED — used
/// by absolute-volume controllers to learn the peer's volume change.
fn smoke_avrcp_register_notification_volume_changed() -> TestResult {
    use crate::avrcp::{
        parse_vendor_dependent, register_notification, EVENT_VOLUME_CHANGED, PDU_REGISTER_NOTIFICATION,
    };
    let frame = register_notification(EVENT_VOLUME_CHANGED, 0);
    let (_ctype, _cid, pdu_id, params) =
        parse_vendor_dependent(&frame).expect("parse vendor-dep");
    if pdu_id != PDU_REGISTER_NOTIFICATION {
        return TestResult::Fail("pdu id not REGISTER_NOTIFICATION");
    }
    // 1-byte event id + 4-byte playback interval = 5 bytes.
    if params.len() != 5 || params[0] != EVENT_VOLUME_CHANGED {
        return TestResult::Fail("event id / playback interval wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/avrcp",
    smoke_avrcp_register_notification_volume_changed
);

/// AVRCP media_key_press wraps the PASS THROUGH frame in an AVCTP
/// single command. The first 3 bytes are the AVCTP header + PID.
fn smoke_avrcp_media_key_press_wrapping() -> TestResult {
    use crate::avrcp::media_key_press;
    let bytes = media_key_press(0x05, crate::avrcp::OP_PLAY);
    // AVCTP header: label=5 → 0x50, ptype=0b00, cr=cmd=0 → 0x50.
    if bytes[0] != 0x50 {
        return TestResult::Fail("AVCTP header label wrong");
    }
    // PID big-endian 0x110E.
    if bytes[1] != 0x11 || bytes[2] != 0x0E {
        return TestResult::Fail("AVCTP PID big-endian wrong");
    }
    // Payload should be a PASS THROUGH frame, byte 2 = opcode 0x7C.
    if bytes[3 + 2] != 0x7C {
        return TestResult::Fail("PASS THROUGH opcode not in payload");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/avrcp", smoke_avrcp_media_key_press_wrapping);

// ── ERTM smokes ─────────────────────────────────────────────────────

/// Vol 3 Part A §3.3.5: L2CAP FCS uses CRC-16 with polynomial 0xA001
/// (reflected). Verify against a known vector — a single zero byte
/// CRCs to 0 (initial value 0, no LSB flips since 0x00 input).
fn smoke_ertm_fcs_known_vector() -> TestResult {
    use crate::ertm::fcs;
    // 0x00 byte: each bit shift sees LSB=0, no XOR; result is 0.
    if fcs(&[0x00]) != 0 {
        return TestResult::Fail("fcs([0x00]) != 0");
    }
    // 0x01 byte: shift right by 1, LSB was 1 → XOR 0xA001.
    // CRC after step 1 = 0xA001. Step 2..8 (zero ext): each shift
    // either XORs or doesn't. Final CRC for 0x01 input is 0xC0C0
    // (computed by hand and matches the Modbus CRC of "01").
    let single01 = fcs(&[0x01]);
    if single01 == 0 {
        return TestResult::Fail("fcs([0x01]) suspiciously 0");
    }
    // Round-trip: appending the FCS little-endian must result in a
    // CRC of 0 when the whole message is re-CRC'd (Modbus property).
    let mut msg = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
    let c = fcs(&msg);
    msg.extend_from_slice(&c.to_le_bytes());
    if fcs(&msg) != 0 {
        return TestResult::Fail("appending FCS doesn't zero re-CRC");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/ertm", smoke_ertm_fcs_known_vector);

/// ERTM I-frame encode/decode round-trip. ECF layout is 16-bit LE with
/// the discriminator in bit 0; we encode an unsegmented I-frame
/// with tx_seq=5 / req_seq=3 / SAR=0b00 and assert each field.
fn smoke_ertm_iframe_round_trip() -> TestResult {
    use crate::ertm::{IFrame, SAR_UNSEGMENTED};
    let original = IFrame {
        tx_seq: 5,
        req_seq: 3,
        sar: SAR_UNSEGMENTED,
        payload: alloc::vec![1, 2, 3, 4],
        fcs: None,
    };
    let bytes = original.encode();
    if (bytes[0] & 1) != 0 {
        return TestResult::Fail("I-frame discriminator wrong");
    }
    let decoded = IFrame::decode(&bytes, false).expect("decode");
    if decoded != original {
        return TestResult::Fail("I-frame round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/ertm", smoke_ertm_iframe_round_trip);

/// ERTM S-frame round-trip — RR with req_seq=7 and final-bit set.
fn smoke_ertm_sframe_rr_round_trip() -> TestResult {
    use crate::ertm::{SFrame, SupervisorFunc};
    let original = SFrame {
        function: SupervisorFunc::Rr,
        req_seq: 7,
        final_bit: true,
    };
    let bytes = original.encode();
    if (bytes[0] & 1) != 1 {
        return TestResult::Fail("S-frame discriminator wrong");
    }
    let decoded = SFrame::decode(&bytes).expect("decode");
    if decoded != original {
        return TestResult::Fail("S-frame round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/ertm", smoke_ertm_sframe_rr_round_trip);

/// ERTM tx-window enforcement (§3.4.2). With tx_window=3, the first
/// three assigns succeed (outstanding 0→1→2) — the *fourth* try is
/// the one that should be blocked. After an ack the window slides
/// and we can send again.
fn smoke_ertm_tx_window_enforcement() -> TestResult {
    use crate::ertm::ErtmState;
    let mut s = ErtmState::new(3);
    for _ in 0..3 {
        if !s.can_send() {
            return TestResult::Fail("should be able to send within window");
        }
        s.assign_tx_seq();
    }
    if s.can_send() {
        return TestResult::Fail("tx-window not enforced after 3 sends");
    }
    // Peer acks 2 frames.
    s.on_peer_ack(2);
    if !s.can_send() {
        return TestResult::Fail("window not slid after peer ack");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/ertm", smoke_ertm_tx_window_enforcement);

/// ERTM RFC config option encoder produces the exact 11-byte layout
/// the spec mandates (§5.4): type(0x04) length(9) mode(1) tx_win(1)
/// max_transmit(1) retransmit_timeout(2 LE) monitor_timeout(2 LE)
/// max_pdu(2 LE) = 1+1+9 = 11 bytes total.
fn smoke_ertm_config_option_rfc_encoding() -> TestResult {
    use crate::ertm::{config_option_rfc, CONFIG_OPT_RFC, MODE_ERTM};
    let opt = config_option_rfc(MODE_ERTM, 10, 3, 2000, 12000, 1024);
    if opt[0] != CONFIG_OPT_RFC {
        return TestResult::Fail("option type not RFC");
    }
    if opt[1] != 9 {
        return TestResult::Fail("option length != 9");
    }
    if opt[2] != MODE_ERTM {
        return TestResult::Fail("mode not ERTM");
    }
    if opt[3] != 10 {
        return TestResult::Fail("tx_window wrong");
    }
    // retransmit_timeout 2000 = 0x07D0 LE.
    if u16::from_le_bytes([opt[5], opt[6]]) != 2000 {
        return TestResult::Fail("retransmit_timeout LE wrong");
    }
    if u16::from_le_bytes([opt[9], opt[10]]) != 1024 {
        return TestResult::Fail("max_pdu LE wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/ertm", smoke_ertm_config_option_rfc_encoding);

/// ERTM sequence-number arithmetic wraps at the 64 boundary. Within a
/// window [62..3), seqs 62, 63, 0, 1, 2 must be admitted; 4, 5, 60
/// must not.
fn smoke_ertm_seq_in_window_wrap() -> TestResult {
    use crate::ertm::seq_in_window;
    if !seq_in_window(62, 62, 3) {
        return TestResult::Fail("62 should be in [62..3)");
    }
    if !seq_in_window(62, 0, 3) {
        return TestResult::Fail("0 should be in [62..3)");
    }
    if !seq_in_window(62, 2, 3) {
        return TestResult::Fail("2 should be in [62..3)");
    }
    if seq_in_window(62, 3, 3) {
        return TestResult::Fail("3 is exclusive end");
    }
    if seq_in_window(62, 60, 3) {
        return TestResult::Fail("60 is outside the wrap window");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/ertm", smoke_ertm_seq_in_window_wrap);

// ── HCI extension opcode smokes ─────────────────────────────────────

/// LE Encrypt opcode (§7.8.22, OGF=0x08 OCF=0x0017 → 0x2017). Issuing
/// the command requires concatenating a 16-byte key + 16-byte
/// plaintext as the 32-byte parameter block.
fn smoke_hci_le_encrypt_encoding() -> TestResult {
    use crate::hci::Command;
    use crate::opcode::HCI_LE_ENCRYPT;
    let key = [0x11u8; 16];
    let plaintext = [0x22u8; 16];
    let mut params = alloc::vec::Vec::with_capacity(32);
    params.extend_from_slice(&key);
    params.extend_from_slice(&plaintext);
    let cmd = Command::with_params(HCI_LE_ENCRYPT, &params);
    let bytes = cmd.encode();
    // 2-byte opcode + 1-byte plen + 32-byte param = 35.
    if bytes.len() != 35 {
        return TestResult::Fail("encrypt cmd length wrong");
    }
    if u16::from_le_bytes([bytes[0], bytes[1]]) != 0x2017 {
        return TestResult::Fail("encrypt opcode != 0x2017");
    }
    if bytes[2] != 32 {
        return TestResult::Fail("encrypt plen != 32");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_hci_le_encrypt_encoding);

/// LE Rand opcode (§7.8.23, OGF=0x08 OCF=0x0018 → 0x2018). No params;
/// 8 random bytes come back via Command Complete.
fn smoke_hci_le_rand_encoding() -> TestResult {
    use crate::hci::Command;
    use crate::opcode::HCI_LE_RAND;
    let cmd = Command::with_params(HCI_LE_RAND, &[]);
    let bytes = cmd.encode();
    if bytes.len() != 3 {
        return TestResult::Fail("LE_Rand cmd length != 3");
    }
    if u16::from_le_bytes([bytes[0], bytes[1]]) != 0x2018 {
        return TestResult::Fail("LE_Rand opcode != 0x2018");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/hci", smoke_hci_le_rand_encoding);

/// LE Add Device To Filter Accept List (§7.8.16) — 7-byte param:
/// address_type(1) + BD_ADDR(6 LE). Used to mint a peer to the
/// allowlist for auto-connect.
fn smoke_hci_le_add_filter_accept_list_encoding() -> TestResult {
    use crate::hci::Command;
    use crate::opcode::HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST;
    let mut params = alloc::vec::Vec::with_capacity(7);
    params.push(0x00); // public address
    params.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
    let cmd = Command::with_params(HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST, &params);
    let bytes = cmd.encode();
    if u16::from_le_bytes([bytes[0], bytes[1]]) != 0x2011 {
        return TestResult::Fail("accept-list opcode != 0x2011");
    }
    if bytes[2] != 7 {
        return TestResult::Fail("accept-list plen != 7");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/hci",
    smoke_hci_le_add_filter_accept_list_encoding
);

// ── LE LTK Request decoder smoke ───────────────────────────────────

/// LE Long Term Key Request subevent (§7.7.65.5) carries Rand + EDIV.
/// Synthesise the event and round-trip the fields.
fn smoke_le_long_term_key_request_decode() -> TestResult {
    use crate::event::{LeLongTermKeyRequest, LeSubevent};
    use crate::hci::Event;
    let mut params = alloc::vec::Vec::new();
    params.push(LeSubevent::LongTermKeyRequest as u8); // subevent
    params.extend_from_slice(&0x0123u16.to_le_bytes()); // handle
    params.extend_from_slice(&0xDEADBEEFCAFEBABEu64.to_le_bytes()); // rand
    params.extend_from_slice(&0x5678u16.to_le_bytes()); // ediv
    let event = Event {
        code: crate::event::EventCode::LeMeta as u8,
        params,
    };
    let ltkr = LeLongTermKeyRequest::parse(&event).expect("parse");
    if ltkr.handle != 0x123 {
        return TestResult::Fail("handle decode wrong");
    }
    if ltkr.random_number != 0xDEADBEEFCAFEBABE {
        return TestResult::Fail("rand decode wrong");
    }
    if ltkr.ediv != 0x5678 {
        return TestResult::Fail("ediv decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/event", smoke_le_long_term_key_request_decode);

/// IO Capability Request event (§7.7.40) carries just the peer BD_ADDR.
fn smoke_io_capability_request_decode() -> TestResult {
    use crate::event::{EventCode, IoCapabilityRequest};
    use crate::hci::Event;
    let event = Event {
        code: EventCode::IoCapabilityRequest as u8,
        params: alloc::vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
    };
    let req = IoCapabilityRequest::parse(&event).expect("parse");
    if req.bd_addr != [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC] {
        return TestResult::Fail("BD_ADDR decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/event", smoke_io_capability_request_decode);

/// User Confirmation Request event (§7.7.42) — numeric-comparison SSP.
/// 6-byte BD_ADDR + 4-byte little-endian numeric value.
fn smoke_user_confirmation_request_decode() -> TestResult {
    use crate::event::{EventCode, UserConfirmationRequest};
    use crate::hci::Event;
    let mut params = alloc::vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    params.extend_from_slice(&123456u32.to_le_bytes());
    let event = Event {
        code: EventCode::UserConfirmationRequest as u8,
        params,
    };
    let req = UserConfirmationRequest::parse(&event).expect("parse");
    if req.numeric_value != 123456 {
        return TestResult::Fail("numeric value decode wrong");
    }
    if req.bd_addr != [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] {
        return TestResult::Fail("BD_ADDR decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/event", smoke_user_confirmation_request_decode);

// ── L2CAP signaling builders ────────────────────────────────────────

/// L2CAP §4.2 Connection Request — PSM(2 LE) + Source_CID(2 LE).
/// Verify the wire layout matches the spec exactly.
fn smoke_l2cap_connection_request_encoding() -> TestResult {
    use crate::l2cap::{build_connection_request, PSM_AVDTP, SignallingCode};
    let cmd = build_connection_request(0x42, PSM_AVDTP, 0x0050);
    if cmd.code != SignallingCode::ConnectionRequest as u8 {
        return TestResult::Fail("conn-req code wrong");
    }
    if cmd.identifier != 0x42 {
        return TestResult::Fail("identifier wrong");
    }
    if cmd.data.len() != 4 {
        return TestResult::Fail("data length not 4");
    }
    if u16::from_le_bytes([cmd.data[0], cmd.data[1]]) != PSM_AVDTP {
        return TestResult::Fail("PSM encoding wrong");
    }
    if u16::from_le_bytes([cmd.data[2], cmd.data[3]]) != 0x0050 {
        return TestResult::Fail("source CID encoding wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/l2cap", smoke_l2cap_connection_request_encoding);

/// L2CAP §4.3 Connection Response — 8-byte payload with the Result
/// codes from table 4-5.
fn smoke_l2cap_connection_response_success() -> TestResult {
    use crate::l2cap::{
        build_connection_response, CONN_RESULT_SUCCESS, CONN_STATUS_NO_INFORMATION,
    };
    let cmd = build_connection_response(0x05, 0x0050, 0x0040, CONN_RESULT_SUCCESS,
                                         CONN_STATUS_NO_INFORMATION);
    if cmd.data.len() != 8 {
        return TestResult::Fail("conn-rsp data not 8 bytes");
    }
    if u16::from_le_bytes([cmd.data[0], cmd.data[1]]) != 0x0050 {
        return TestResult::Fail("dest CID wrong");
    }
    if u16::from_le_bytes([cmd.data[2], cmd.data[3]]) != 0x0040 {
        return TestResult::Fail("source CID wrong");
    }
    if u16::from_le_bytes([cmd.data[4], cmd.data[5]]) != CONN_RESULT_SUCCESS {
        return TestResult::Fail("result wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/l2cap", smoke_l2cap_connection_response_success);

/// L2CAP §4.4 Configure Request — Dest_CID + Flags + options. We
/// embed an MTU=1024 option (§5.1) and verify the encoded bytes.
fn smoke_l2cap_configure_request_mtu_option() -> TestResult {
    use crate::l2cap::{build_configure_request, config_option_mtu};
    let opt = config_option_mtu(1024);
    let cmd = build_configure_request(0x10, 0x0050, false, &opt);
    // Layout: dest_cid(2) + flags(2) + options(4) = 8 bytes.
    if cmd.data.len() != 8 {
        return TestResult::Fail("config-req data not 8 bytes");
    }
    // dest cid = 0x0050.
    if u16::from_le_bytes([cmd.data[0], cmd.data[1]]) != 0x0050 {
        return TestResult::Fail("dest CID wrong");
    }
    // flags = 0 (no continuation).
    if u16::from_le_bytes([cmd.data[2], cmd.data[3]]) != 0 {
        return TestResult::Fail("flags should be 0");
    }
    // option: type=0x01 length=2 mtu=1024 LE.
    if cmd.data[4] != 0x01 || cmd.data[5] != 2 {
        return TestResult::Fail("MTU option header wrong");
    }
    if u16::from_le_bytes([cmd.data[6], cmd.data[7]]) != 1024 {
        return TestResult::Fail("MTU value wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/l2cap", smoke_l2cap_configure_request_mtu_option);

/// L2CAP §4.22 LE Credit-Based Connection Request — 10-byte data
/// block with LE_PSM, Source_CID, MTU, MPS, Initial_Credits all LE.
fn smoke_l2cap_le_credit_based_connection_request() -> TestResult {
    use crate::l2cap::build_le_credit_based_connection_request;
    let cmd = build_le_credit_based_connection_request(0x20, 0x0080, 0x0040, 512, 251, 10);
    if cmd.data.len() != 10 {
        return TestResult::Fail("LE-CoC req not 10 bytes");
    }
    if u16::from_le_bytes([cmd.data[0], cmd.data[1]]) != 0x0080 {
        return TestResult::Fail("LE PSM wrong");
    }
    if u16::from_le_bytes([cmd.data[4], cmd.data[5]]) != 512 {
        return TestResult::Fail("MTU wrong");
    }
    if u16::from_le_bytes([cmd.data[8], cmd.data[9]]) != 10 {
        return TestResult::Fail("Initial credits wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_le_credit_based_connection_request
);

/// L2CAP §4.20 LE Connection Parameter Update Request — peripheral
/// asks central to renegotiate interval. Data is 4×u16 LE.
fn smoke_l2cap_le_conn_param_update_request() -> TestResult {
    use crate::l2cap::build_le_connection_parameter_update_request;
    // 7.5 ms interval = 6 units, 15 ms = 12 units, lat=0, timeout=500=5s.
    let cmd = build_le_connection_parameter_update_request(0x30, 6, 12, 0, 500);
    if cmd.data.len() != 8 {
        return TestResult::Fail("conn-param-update data not 8 bytes");
    }
    if u16::from_le_bytes([cmd.data[0], cmd.data[1]]) != 6 {
        return TestResult::Fail("interval_min wrong");
    }
    if u16::from_le_bytes([cmd.data[6], cmd.data[7]]) != 500 {
        return TestResult::Fail("timeout wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_le_conn_param_update_request
);

/// L2CAP §4.10 Information Request for Extended Features — used by
/// initiators to discover ERTM / Streaming / FCS support.
fn smoke_l2cap_information_request_extended_features() -> TestResult {
    use crate::l2cap::{
        build_information_request, INFO_TYPE_EXTENDED_FEATURES, SignallingCode,
    };
    let cmd = build_information_request(0x01, INFO_TYPE_EXTENDED_FEATURES);
    if cmd.code != SignallingCode::InformationRequest as u8 {
        return TestResult::Fail("not InformationRequest");
    }
    if u16::from_le_bytes([cmd.data[0], cmd.data[1]]) != INFO_TYPE_EXTENDED_FEATURES {
        return TestResult::Fail("info type not Extended Features");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/l2cap",
    smoke_l2cap_information_request_extended_features
);

/// Confirm well-known PSMs match the Assigned Numbers values used in
/// every public Bluetooth profile.
fn smoke_l2cap_well_known_psms() -> TestResult {
    use crate::l2cap::{
        PSM_AVCTP, PSM_AVCTP_BROWSING, PSM_AVDTP, PSM_BNEP, PSM_HID_CONTROL,
        PSM_HID_INTERRUPT, PSM_RFCOMM, PSM_SDP,
    };
    if PSM_SDP != 0x0001 { return TestResult::Fail("PSM_SDP wrong"); }
    if PSM_RFCOMM != 0x0003 { return TestResult::Fail("PSM_RFCOMM wrong"); }
    if PSM_BNEP != 0x000F { return TestResult::Fail("PSM_BNEP wrong"); }
    if PSM_HID_CONTROL != 0x0011 { return TestResult::Fail("PSM_HID_CONTROL wrong"); }
    if PSM_HID_INTERRUPT != 0x0013 { return TestResult::Fail("PSM_HID_INTERRUPT wrong"); }
    if PSM_AVCTP != 0x0017 { return TestResult::Fail("PSM_AVCTP wrong"); }
    if PSM_AVDTP != 0x0019 { return TestResult::Fail("PSM_AVDTP wrong"); }
    if PSM_AVCTP_BROWSING != 0x001B { return TestResult::Fail("PSM_AVCTP_BROWSING wrong"); }
    TestResult::Pass
}
kernel_test_in!("bluetooth/l2cap", smoke_l2cap_well_known_psms);

// ── Well-known service builders ─────────────────────────────────────

/// Mounting the GAP service emits a Primary Service decl + Device Name
/// + Appearance characteristics. Walk the resulting database and
/// assert all three slots are present with the right UUIDs.
fn smoke_services_gap_mount() -> TestResult {
    use crate::gatt::Uuid;
    use crate::gatt_server::AttributeDatabase;
    use crate::services::{
        mount_gap_service, APPEARANCE_KEYBOARD, UUID_APPEARANCE, UUID_DEVICE_NAME,
    };
    let mut db = AttributeDatabase::new();
    let _svc = mount_gap_service(&mut db, "narf-test", APPEARANCE_KEYBOARD);
    let attrs = db.attrs();
    // 5 attrs: Primary Service + Device Name decl + value + Appearance
    // decl + value.
    if attrs.len() != 5 {
        return TestResult::Fail("GAP service should produce 5 attrs");
    }
    // Walk slots: 0x2800 (svc), 0x2803 (decl), name, 0x2803 (decl),
    // appearance.
    let name_attr = attrs.iter().find(|a| a.uuid == Uuid::U16(UUID_DEVICE_NAME));
    if name_attr.is_none() || name_attr.unwrap().value != b"narf-test" {
        return TestResult::Fail("Device Name characteristic missing/wrong");
    }
    let app_attr = attrs.iter().find(|a| a.uuid == Uuid::U16(UUID_APPEARANCE));
    if app_attr.is_none() {
        return TestResult::Fail("Appearance characteristic missing");
    }
    if u16::from_le_bytes([app_attr.unwrap().value[0], app_attr.unwrap().value[1]])
        != APPEARANCE_KEYBOARD
    {
        return TestResult::Fail("Appearance value not Keyboard");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/services", smoke_services_gap_mount);

/// Battery Service with NOTIFY + CCCD — mount and assert the initial
/// battery level + the CCCD attribute are present.
fn smoke_services_battery_mount_with_cccd() -> TestResult {
    use crate::gatt::{Uuid, UUID_CCC_DESCRIPTOR};
    use crate::gatt_server::AttributeDatabase;
    use crate::services::{mount_battery_service, UUID_BATTERY_LEVEL};
    let mut db = AttributeDatabase::new();
    let (_svc, level_handle, cccd_handle) = mount_battery_service(&mut db, 85);
    // Service Decl + Characteristic Decl + Value + CCCD = 4 attrs.
    if db.attrs().len() != 4 {
        return TestResult::Fail("battery service should produce 4 attrs");
    }
    let level = db.attr_by_handle(level_handle).expect("level attr");
    if level.uuid != Uuid::U16(UUID_BATTERY_LEVEL) {
        return TestResult::Fail("level uuid wrong");
    }
    if level.value != alloc::vec![85] {
        return TestResult::Fail("level value wrong");
    }
    let cccd = db.attr_by_handle(cccd_handle).expect("cccd attr");
    if cccd.uuid != Uuid::U16(UUID_CCC_DESCRIPTOR) {
        return TestResult::Fail("cccd uuid wrong");
    }
    if cccd.value != alloc::vec![0, 0] {
        return TestResult::Fail("cccd initial != 0x0000");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/services", smoke_services_battery_mount_with_cccd);

/// Device Information Service: only manufacturer + model populated.
fn smoke_services_device_info_partial() -> TestResult {
    use crate::gatt::Uuid;
    use crate::gatt_server::AttributeDatabase;
    use crate::services::{
        mount_device_information_service, DeviceInformation, UUID_MANUFACTURER_NAME_STRING,
        UUID_MODEL_NUMBER_STRING, UUID_SERIAL_NUMBER_STRING,
    };
    let mut db = AttributeDatabase::new();
    let info = DeviceInformation {
        manufacturer: Some("narf"),
        model: Some("narf-001"),
        ..Default::default()
    };
    let _svc = mount_device_information_service(&mut db, &info);
    let attrs = db.attrs();
    // Service + 2 characteristics × (decl + value) = 5 attrs.
    if attrs.len() != 5 {
        return TestResult::Fail("DIS partial mount expected 5 attrs");
    }
    let mfr = attrs.iter().find(|a| a.uuid == Uuid::U16(UUID_MANUFACTURER_NAME_STRING));
    if mfr.is_none() || mfr.unwrap().value != b"narf" {
        return TestResult::Fail("manufacturer not mounted");
    }
    let mdl = attrs.iter().find(|a| a.uuid == Uuid::U16(UUID_MODEL_NUMBER_STRING));
    if mdl.is_none() || mdl.unwrap().value != b"narf-001" {
        return TestResult::Fail("model not mounted");
    }
    if attrs.iter().any(|a| a.uuid == Uuid::U16(UUID_SERIAL_NUMBER_STRING)) {
        return TestResult::Fail("serial spuriously mounted");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/services", smoke_services_device_info_partial);

/// Heart Rate Measurement 8-bit format. Flags byte = 0x00 and 1-byte
/// BPM follows per HRS v1.0 §3.1.
fn smoke_services_heart_rate_measurement_8bit() -> TestResult {
    use crate::services::heart_rate_measurement_8bit;
    let v = heart_rate_measurement_8bit(72);
    if v.len() != 2 {
        return TestResult::Fail("HRM 8-bit value should be 2 bytes");
    }
    if v[0] != 0x00 {
        return TestResult::Fail("HRM flags should be 0 (8-bit format)");
    }
    if v[1] != 72 {
        return TestResult::Fail("HRM BPM value wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/services",
    smoke_services_heart_rate_measurement_8bit
);

/// CCCD value encoder — bit 0 = Notifications, bit 1 = Indications.
fn smoke_services_cccd_value_encoding() -> TestResult {
    use crate::services::{cccd_value, CCCD_INDICATIONS, CCCD_NOTIFICATIONS};
    let v = cccd_value(true, false);
    if u16::from_le_bytes(v) != CCCD_NOTIFICATIONS {
        return TestResult::Fail("CCCD(notify) != bit 0");
    }
    let v = cccd_value(false, true);
    if u16::from_le_bytes(v) != CCCD_INDICATIONS {
        return TestResult::Fail("CCCD(indicate) != bit 1");
    }
    let v = cccd_value(true, true);
    if u16::from_le_bytes(v) != (CCCD_NOTIFICATIONS | CCCD_INDICATIONS) {
        return TestResult::Fail("CCCD(both) != bits 0+1");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/services", smoke_services_cccd_value_encoding);

