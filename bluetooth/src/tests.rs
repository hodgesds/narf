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
