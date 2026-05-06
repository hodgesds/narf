//! Smoke tests for narf-bluetooth.
//!
//! Cover the packet codec round-trip and the bring-up state machine
//! end-to-end against a synthetic transport that replays canned
//! Command Complete events for every Mandatory opcode.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
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
