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

/// Number of registered controllers — for the HCIGETDEVLIST ioctl.
pub fn dev_count() -> usize {
    controller::controller_count()
}

/// Build the 92-byte `struct hci_dev_info` for controller `dev` (HCIGETDEVINFO).
/// Fields NARF does not model (features, link policy/mode, stats) stay zero,
/// as on a freshly-registered Linux adapter.
pub fn dev_info(dev: u16) -> Option<Vec<u8>> {
    let info = controller::controllers().get(dev as usize)?.info();
    let mut b = alloc::vec![0u8; 92];
    b[0..2].copy_from_slice(&dev.to_le_bytes()); // dev_id
    let name = alloc::format!("hci{dev}");
    let n = name.len().min(7); // name[8], keep nul-terminated
    b[2..2 + n].copy_from_slice(&name.as_bytes()[..n]);
    b[10..16].copy_from_slice(&info.bd_addr); // bdaddr
    let flags: u32 = u32::from(crate::mgmt::is_powered(dev)); // bit0 = HCI_UP
    b[16..20].copy_from_slice(&flags.to_le_bytes());
    // type @20, features @21..29 left 0 (BR/EDR primary).
    b[44..46].copy_from_slice(&info.acl_data_mtu.to_le_bytes());
    b[46..48].copy_from_slice(&info.acl_total_num.to_le_bytes());
    b[48..50].copy_from_slice(&u16::from(info.sco_data_mtu).to_le_bytes());
    b[50..52].copy_from_slice(&info.sco_total_num.to_le_bytes());
    Some(b)
}

/// Build the HCI_CHANNEL_MONITOR bind-time replay: one HCI_MON_NEW_INDEX
/// packet per controller so btmon lists the adapters. Each packet is a
/// hci_mon_hdr (opcode/index/len) + hci_mon_new_index (type, bus, bdaddr,
/// name[8]). Linux ref: net/bluetooth/hci_sock.c send_monitor_replay.
pub fn monitor_replay() -> Vec<Vec<u8>> {
    const HCI_MON_NEW_INDEX: u16 = 0;
    const HCI_PRIMARY: u8 = 0;
    const HCI_VIRTUAL: u8 = 0;
    let mut out = Vec::new();
    for (i, controller) in controller::controllers().iter().enumerate() {
        let info = controller.info();
        let mut payload = Vec::with_capacity(16);
        payload.push(HCI_PRIMARY); // type
        payload.push(HCI_VIRTUAL); // bus
        payload.extend_from_slice(&info.bd_addr);
        let name = alloc::format!("hci{i}");
        let mut name_field = [0u8; 8];
        let n = name.len().min(8);
        name_field[..n].copy_from_slice(&name.as_bytes()[..n]);
        payload.extend_from_slice(&name_field);

        let mut pkt = Vec::with_capacity(6 + payload.len());
        pkt.extend_from_slice(&HCI_MON_NEW_INDEX.to_le_bytes());
        pkt.extend_from_slice(&(i as u16).to_le_bytes());
        pkt.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&payload);
        out.push(pkt);
    }
    out
}

/// Power a controller on/off (HCIDEVUP/HCIDEVDOWN). Returns false for an
/// unknown index.
pub fn dev_power(dev: u16, on: bool) -> bool {
    if (dev as usize) >= controller::controller_count() {
        return false;
    }
    crate::mgmt::set_powered(dev, on);
    true
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

    fn smoke_hci_sock_monitor_replay() -> TestResult {
        crate::transport::__test_reset();
        controller::__test_reset_controllers();
        let transport: Arc<dyn crate::transport::HciTransport> =
            Arc::new(LoopbackTransport::new("mon"));
        crate::transport::register(transport.clone());
        let _ = controller::register_ready_transport(
            transport,
            controller::ControllerInfo {
                bd_addr: [1, 2, 3, 4, 5, 6],
                ..controller::ControllerInfo::default()
            },
        );

        let pkts = monitor_replay();
        // One NEW_INDEX (opcode 0, index 0, len 16); bdaddr at payload+2
        // (hdr 6 + type 1 + bus 1 = offset 8).
        let ok = pkts.len() == 1
            && pkts[0].len() == 22
            && u16::from_le_bytes([pkts[0][0], pkts[0][1]]) == 0
            && u16::from_le_bytes([pkts[0][2], pkts[0][3]]) == 0
            && u16::from_le_bytes([pkts[0][4], pkts[0][5]]) == 16
            && pkts[0][8..14] == [1, 2, 3, 4, 5, 6]
            && &pkts[0][14..18] == b"hci0";

        crate::transport::__test_reset();
        controller::__test_reset_controllers();

        if !ok {
            return TestResult::Fail("monitor NEW_INDEX replay packet malformed");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/hci_sock", smoke_hci_sock_monitor_replay);
}
