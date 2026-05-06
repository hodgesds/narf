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
