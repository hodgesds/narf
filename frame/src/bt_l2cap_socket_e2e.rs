//! Cross-crate e2e fixture: AF_BLUETOOTH L2CAP socket over the real
//! pump (issue #814).
//!
//! Drives a scripted fake HCI controller through the REAL
//! narf-bluetooth stack (bring-up → pump) and the REAL narf-userspace
//! socket layer, with the REAL filesystem broker handlers installed
//! (the same fns the `bluetooth-mgmt` initcall installs). The
//! conversation: bind L2CAP LE PSM 0x0080 → listen → peer LE
//! connection + CoC open → accept → peer SDU → recv → send (assert
//! the K-frame on the wire) → shutdown (assert the Disconnection
//! Request on the wire).
//!
//! The frame crate is the only home for this: it depends on both
//! narf-userspace and narf-bluetooth, and the `kernel-test` feature
//! enables both crates' `kernel-test` features.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bluetooth::event::EventCode;
use narf_bluetooth::hci::{AclData, Command, Event};
use narf_bluetooth::l2cap::{BFrame, CID_LE_SIGNALLING, PB_COMPLETE_LE};
use narf_bluetooth::opcode as op;
use narf_bluetooth::transport::{HciTransport, TransportError};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_userspace::socket::{
    SocketFile, SocketOp, SocketOpResult, AF_BLUETOOTH, BTPROTO_L2CAP, SOCK_STREAM,
};

/// Scripted HCI transport: the test plays the controller — queuing
/// Command Complete events for bring-up, connection events, and
/// inbound ACL — and reads back every command / ACL packet the host
/// stack emitted.
#[derive(Debug)]
struct ScriptedTransport {
    events: IrqSafeSpinLock<VecDeque<Event>>,
    acl_inbox: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    sent_commands: IrqSafeSpinLock<Vec<Command>>,
    sent_acl: IrqSafeSpinLock<Vec<Vec<u8>>>,
}

impl ScriptedTransport {
    fn new() -> Self {
        Self {
            events: IrqSafeSpinLock::new(VecDeque::new()),
            acl_inbox: IrqSafeSpinLock::new(VecDeque::new()),
            sent_commands: IrqSafeSpinLock::new(Vec::new()),
            sent_acl: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    fn enqueue_event(&self, e: Event) {
        self.events.lock().push_back(e);
    }

    fn enqueue_acl(&self, bytes: Vec<u8>) {
        self.acl_inbox.lock().push_back(bytes);
    }

    fn sent_acl_frames(&self) -> Vec<(u16, BFrame)> {
        self.sent_acl
            .lock()
            .iter()
            .filter_map(|bytes| AclData::decode(bytes))
            .filter_map(|acl| BFrame::decode(&acl.data).map(|f| (acl.handle, f)))
            .collect()
    }
}

impl HciTransport for ScriptedTransport {
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
        self.sent_commands.lock().push(cmd.clone());
        Ok(())
    }

    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        Ok(self.events.lock().pop_front())
    }

    fn send_acl(&self, data: &[u8]) -> Result<(), TransportError> {
        self.sent_acl.lock().push(data.to_vec());
        Ok(())
    }

    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(self.acl_inbox.lock().pop_front())
    }

    fn name(&self) -> &'static str {
        "fake-hci"
    }
}

/// Command Complete event for `opcode`; `ret` starts with the HCI
/// status byte, as on the wire.
fn cc(opcode: u16, ret: &[u8]) -> Event {
    let mut params = alloc::vec![1, (opcode & 0xFF) as u8, (opcode >> 8) as u8];
    params.extend_from_slice(ret);
    Event {
        code: EventCode::CommandComplete as u8,
        params,
    }
}

fn reset_all() {
    narf_bluetooth::transport::__test_reset();
    narf_bluetooth::controller::__test_reset_controllers();
    narf_bluetooth::pump::__test_reset();
}

fn script_successful_bringup(fake: &ScriptedTransport) {
    fake.enqueue_event(cc(op::HCI_RESET, &[0]));
    // Status, HCI v5.3 (0x0B), rev 0x1234, LMP v5.3, mfr 0x0002
    // (Intel), subver 0x5678.
    fake.enqueue_event(cc(
        op::HCI_READ_LOCAL_VERSION,
        &[0, 0x0B, 0x34, 0x12, 0x0B, 0x02, 0x00, 0x78, 0x56],
    ));
    fake.enqueue_event(cc(
        op::HCI_READ_BD_ADDR,
        &[0, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
    ));
    // Status, ACL MTU 1022, SCO MTU 64, ACL total 8, SCO total 4.
    fake.enqueue_event(cc(
        op::HCI_READ_BUFFER_SIZE,
        &[0, 0xFE, 0x03, 64, 0x08, 0x00, 0x04, 0x00],
    ));
    fake.enqueue_event(cc(op::HCI_SET_EVENT_MASK, &[0]));
    // Identity reads (§7.4.14/§7.4.23, issue #815): bring-up
    // reads the local name and Class of Device after the event
    // mask, so the script must answer both.
    let mut name_ret = alloc::vec![0u8; 249];
    name_ret[1..10].copy_from_slice(b"narf-pump");
    fake.enqueue_event(cc(op::HCI_READ_LOCAL_NAME, &name_ret));
    fake.enqueue_event(cc(op::HCI_READ_CLASS_OF_DEVICE, &[0, 0x04, 0x0C, 0x02]));
}

fn le_connection_complete(handle: u16, peer: [u8; 6]) -> Event {
    let mut params = alloc::vec![0x01, 0x00];
    params.extend_from_slice(&handle.to_le_bytes());
    params.push(0x01); // role: Peripheral (we accepted)
    params.push(0x00); // peer address type: public
    params.extend_from_slice(&peer);
    params.extend_from_slice(&0x0028u16.to_le_bytes()); // interval 50 ms
    params.extend_from_slice(&0u16.to_le_bytes()); // latency
    params.extend_from_slice(&0x01F4u16.to_le_bytes()); // timeout 5 s
    params.push(0x00); // central clock accuracy
    Event {
        code: EventCode::LeMeta as u8,
        params,
    }
}

fn acl_packet(handle: u16, frame: &BFrame) -> Vec<u8> {
    AclData {
        handle,
        pb_flag: PB_COMPLETE_LE,
        bc_flag: 0,
        data: frame.encode(),
    }
    .encode()
}

/// The socket path end to end on the real stack: a scripted LE peer
/// connects and opens a CoC to a listening L2CAP socket, the socket
/// layer accepts it, a peer SDU arrives via recv, a send lands on
/// the wire as a K-frame, and shutdown sends the Disconnection
/// Request. Nothing here is a loopback stub — every byte crosses
/// the pump's L2CAP routing and the broker.
fn e2e_bt_l2cap_socket_over_real_pump() -> TestResult {
    reset_all();
    let fake = Arc::new(ScriptedTransport::new());
    let transport: Arc<dyn HciTransport> = fake.clone();
    narf_bluetooth::transport::register(transport);
    script_successful_bringup(&fake);

    let cap = narf_bluetooth::bootstrap_bluetooth_authority();
    let outcomes = narf_bluetooth::controller::bring_up_all(&cap);
    if outcomes.len() != 1 || outcomes[0].result.is_err() {
        reset_all();
        return TestResult::Fail("bring-up against fake controller failed");
    }

    // The REAL broker handlers — the same fns the `bluetooth-mgmt`
    // initcall installs at bring-up.
    narf_filesystem::bluetooth::install_bt_l2cap_handlers(
        narf_bluetooth::pump::register_psm,
        narf_bluetooth::pump::unregister_psm,
        narf_bluetooth::pump::take_pending_channel,
        narf_bluetooth::pump::pending_channel,
        narf_bluetooth::pump::send_channel,
        narf_bluetooth::pump::drain_channel_rx,
        narf_bluetooth::pump::channel_rx_pending,
        narf_bluetooth::pump::disconnect_channel,
    );
    narf_filesystem::bluetooth::install_bt_rfcomm_handlers(
        narf_bluetooth::pump::take_pending_rfcomm,
        narf_bluetooth::pump::pending_rfcomm,
        narf_bluetooth::pump::send_rfcomm,
        narf_bluetooth::pump::drain_rfcomm_rx,
        narf_bluetooth::pump::rfcomm_rx_pending,
        narf_bluetooth::pump::close_rfcomm_dlc,
    );

    // Socket: bind L2CAP LE PSM 0x0080 BDADDR_ANY → listen.
    let server = SocketFile::with_protocol(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_L2CAP);
    let mut body = alloc::vec![];
    body.extend_from_slice(&0x0080u16.to_le_bytes());
    body.extend_from_slice(&[0u8; 6]);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.push(1); // LE public
    let addr = narf_userspace::socket::SockAddr {
        family: AF_BLUETOOTH,
        body,
    };
    if !matches!(
        server.dispatch_op(SocketOp::Bind { addr }),
        SocketOpResult::Ok(_)
    ) {
        reset_all();
        return TestResult::Fail("e2e: L2CAP bind failed");
    }
    if !matches!(
        server.dispatch_op(SocketOp::Listen { backlog: 8 }),
        SocketOpResult::Ok(_)
    ) {
        reset_all();
        return TestResult::Fail("e2e: L2CAP listen failed");
    }

    // Peer LE connection, then a CoC open (id 0x07, PSM 0x0080,
    // peer CID 0x0041, MTU 1024, MPS 256, 8 initial credits).
    let handle = 0x0040;
    let peer = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    fake.enqueue_event(le_connection_complete(handle, peer));
    let _ = narf_bluetooth::pump::pump_once(0);
    let open = narf_bluetooth::l2cap::build_le_credit_based_connection_request(
        0x07, 0x0080, 0x0041, 1024, 256, 8,
    );
    let mut payload = Vec::new();
    open.encode(&mut payload);
    fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_LE_SIGNALLING, payload)));
    let _ = narf_bluetooth::pump::pump_once(0);

    // Accept through the real socket layer.
    let mut expected = alloc::vec![];
    expected.extend_from_slice(&0x0080u16.to_le_bytes());
    expected.extend_from_slice(&peer);
    expected.extend_from_slice(&0x0041u16.to_le_bytes());
    expected.push(1);
    let child = match server.dispatch_op(SocketOp::Accept) {
        SocketOpResult::Accepted {
            socket,
            peer: Some(addr),
        } if addr.body == expected => socket,
        SocketOpResult::Accepted { .. } => {
            reset_all();
            return TestResult::Fail("e2e: accept peer sockaddr mismatch");
        }
        _ => {
            reset_all();
            return TestResult::Fail("e2e: accept did not return Accepted");
        }
    };

    // Peer data: single-K-frame SDU "hi" on our local CID 0x0040.
    fake.enqueue_acl(acl_packet(
        handle,
        &BFrame::new(0x0040, alloc::vec![0x02, 0x00, b'h', b'i']),
    ));
    let _ = narf_bluetooth::pump::pump_once(0);
    let mut out = [0u8; 16];
    match child.dispatch_op(SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    }) {
        SocketOpResult::Received { n, .. } if n == 2 && &out[..2] == b"hi" => {}
        _ => {
            reset_all();
            return TestResult::Fail("e2e: recv did not return the peer SDU");
        }
    }

    // Socket send: one K-frame ("pong" + length prefix) on the
    // peer CID 0x0041.
    match child.dispatch_op(SocketOp::Send {
        buf: b"pong",
        flags: 0,
        addr: None,
    }) {
        SocketOpResult::Ok(4) => {}
        _ => {
            reset_all();
            return TestResult::Fail("e2e: send did not report 4 bytes");
        }
    }
    let frames = fake.sent_acl_frames();
    let send_ok = frames.iter().any(|(h, f)| {
        *h == handle
            && f.cid == 0x0041
            && f.payload == alloc::vec![0x04, 0x00, b'p', b'o', b'n', b'g']
    });
    if !send_ok {
        reset_all();
        return TestResult::Fail("e2e: send K-frame missing from the wire");
    }

    // Socket shutdown: Disconnection Request on LE signalling.
    if !matches!(
        child.dispatch_op(SocketOp::Shutdown { how: 0 }),
        SocketOpResult::Ok(_)
    ) {
        reset_all();
        return TestResult::Fail("e2e: shutdown failed");
    }
    let frames = fake.sent_acl_frames();
    let disc_ok = frames.iter().any(|(_, f)| {
        f.cid == CID_LE_SIGNALLING
            && f.payload == alloc::vec![0x06, 0x00, 0x04, 0x00, 0x41, 0x00, 0x40, 0x00]
    });
    if !disc_ok {
        reset_all();
        return TestResult::Fail("e2e: disconnect request missing from the wire");
    }

    reset_all();
    TestResult::Pass
}
kernel_test_in!("frame", e2e_bt_l2cap_socket_over_real_pump);
