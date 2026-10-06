//! Raw HCI socket bridge — the `HCI_CHANNEL_RAW` / `HCI_CHANNEL_USER` data
//! path. Userspace sends HCI Command/ACL packets (prefixed with the one-byte
//! HCI packet-type indicator) and drains HCI Event packets for a controller
//! identified by its HCI index.
//!
//! Linux ref: net/bluetooth/hci_sock.c (hci_sock_sendmsg / hci_rcv_frame).
//! The native controller's transport provides the actual I/O; real HCI is
//! hardware-gated, so this is exercised via the LoopbackTransport.

extern crate alloc;

use alloc::vec::Vec;

use crate::controller;
use crate::hci::Command;

/// HCI packet-type indicators (first byte on the HCI socket wire).
const HCI_COMMAND_PKT: u8 = 0x01;
const HCI_ACLDATA_PKT: u8 = 0x02;
const HCI_EVENT_PKT: u8 = 0x04;

/// Send a type-prefixed HCI packet to controller `dev`'s transport. Returns
/// false for an unknown index or an unsupported/short packet.
pub fn send(dev: u16, packet: &[u8]) -> bool {
    let controllers = controller::controllers();
    let Some(controller) = controllers.get(dev as usize) else {
        return false;
    };
    let transport = controller.transport();
    match packet.first().copied() {
        Some(HCI_COMMAND_PKT) if packet.len() >= 4 => {
            // opcode(le16) | plen(u8) | params.
            let opcode = u16::from_le_bytes([packet[1], packet[2]]);
            let plen = packet[3] as usize;
            let params = packet.get(4..4 + plen).unwrap_or(&packet[4..]);
            transport
                .send_command(&Command::with_params(opcode, params))
                .is_ok()
        }
        Some(HCI_ACLDATA_PKT) => transport.send_acl(&packet[1..]).is_ok(),
        _ => false,
    }
}

/// Drain the next HCI event from controller `dev`, encoded for the socket as
/// `HCI_EVENT_PKT || code || plen || params`. `None` when no controller or no
/// pending event.
pub fn drain_event(dev: u16) -> Option<Vec<u8>> {
    let controllers = controller::controllers();
    let controller = controllers.get(dev as usize)?;
    let event = controller.transport().recv_event().ok()??;
    // HCI_EVENT_PKT || code || param-length || params.
    let mut out = Vec::with_capacity(3 + event.params.len());
    out.push(HCI_EVENT_PKT);
    out.push(event.code);
    out.push(event.params.len() as u8);
    out.extend_from_slice(&event.params);
    Some(out)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::event::EventCode;
    use crate::hci::Event;
    use crate::transport::LoopbackTransport;
    use alloc::sync::Arc;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_hci_sock_send_and_drain() -> TestResult {
        crate::transport::__test_reset();
        controller::__test_reset_controllers();
        let loopback = Arc::new(LoopbackTransport::new("hci-sock"));
        let transport: Arc<dyn crate::transport::HciTransport> = loopback.clone();
        crate::transport::register(transport.clone());
        let dev =
            controller::register_ready_transport(transport, controller::ControllerInfo::default())
                as u16;

        // Send HCI_Reset (opcode 0x0C03, no params) as a type-prefixed command.
        let reset = [HCI_COMMAND_PKT, 0x03, 0x0c, 0x00];
        let sent = send(dev, &reset);

        // The loopback records the command it received.
        let got_cmd = loopback.sent_commands().iter().any(|c| c.opcode == 0x0c03);

        // Enqueue an event and drain it through the socket encoder.
        loopback.enqueue_event(Event {
            code: EventCode::CommandComplete as u8,
            params: alloc::vec![0x01, 0x03, 0x0c, 0x00],
        });
        let drained = drain_event(dev);

        // Unknown index / short packet are rejected.
        let bad_index = send(0x00ff, &reset);
        let short = send(dev, &[HCI_COMMAND_PKT, 0x03]);

        crate::transport::__test_reset();
        controller::__test_reset_controllers();

        if !sent || !got_cmd {
            return TestResult::Fail("HCI command was not forwarded to the transport");
        }
        match drained {
            Some(pkt)
                if pkt[0] == HCI_EVENT_PKT
                    && pkt[1] == EventCode::CommandComplete as u8
                    && pkt[2] == 4 => {}
            _ => return TestResult::Fail("HCI event was not drained/encoded correctly"),
        }
        if bad_index || short {
            return TestResult::Fail("bad index or short packet was not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/hci_sock", smoke_hci_sock_send_and_drain);
}
