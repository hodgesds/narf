// SPDX-License-Identifier: GPL-2.0-or-later
//! Real public Device, IPC, kernel DHCP, CCMP and native eight-link chain.
use super::*;
fn smoke_ar9285_large_tx_public_ipc_eight_originals_kernel_dhcp_and_recipient_coexistence(
) -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for protected in [false, true] {
        for recipient in [false, true] {
            let h = Harness::new_ht(protected, 255);
            crate::ath9k::tx_ba::large_tests::qualify(&h.model, 8, 65535, 64);
            crate::ath9k::qos::tests::qualify(&h.model);
            h.peer.lock().qos_tids = true;
            if recipient {
                crate::ath9k::rx_ba::tests::qualify(&h.model, 64);
            }
            h.join();
            h.pump();
            if recipient {
                h.model
                    .inject(&crate::ath9k::rx_ba::tests::addba(0, 0, 64, 0, false), 0)
                    .unwrap();
                h.pump();
                h.model.rx_aggr.set((1 << 17) | (1 << 29));
            }
            let lease = match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
                Ok(lease) => lease,
                Err(_) => return TestResult::Fail("v4 sender lost actual kernel DHCP"),
            };
            if !h.plan.matches_lease(&lease) {
                return TestResult::Fail("v4 DHCP lease differs");
            }
            let frames: Vec<Vec<u8>> = (0..8)
                .map(|index| {
                    udp_ipv4(
                        AP,
                        h.plan.station,
                        h.plan.lease_ip,
                        h.plan.server_ip,
                        49200 + index,
                        7,
                        &[index as u8; 64],
                    )
                })
                .collect();
            for frame in &frames {
                if narf_net::iface::send_on(h.device.name(), frame).is_err() {
                    return TestResult::Fail("v4 public IPC burst rejected");
                }
            }
            h.pump();
            let chain = h.model.last_chain.borrow().clone();
            let delivered = h.peer.lock().uplink.clone();
            if chain.len() != 8
                || delivered.get(delivered.len().saturating_sub(8)..) != Some(frames.as_slice())
                || h.peer.lock().tx_ba_requests.len() != 1
                || h.model.word(*chain.last().unwrap() + 56).unwrap() & (1 << 30) == 0
            {
                return TestResult::Fail(
                    "public IPC burst missed actual eight-link/native BA originals",
                );
            }
            // Actual public nonzero-TID single between two TID0 chains.
            // This EtherType is UP7 in the source classifier; its payload is
            // opaque to DHCP and must not touch the TID0 peer reorder owner.
            let next = h
                .model
                .transmitted
                .borrow()
                .iter()
                .rev()
                .find(|frame| frame.first() == Some(&0x88) && frame.get(24..26) == Some(&[0, 0]))
                .map(|frame| ((u16::from_le_bytes([frame[22], frame[23]]) >> 4) + 1) & 4095)
                .unwrap();
            let mut other = frames[0].clone();
            other[12..14].copy_from_slice(&0x8917u16.to_be_bytes());
            narf_net::iface::send_on(h.device.name(), &other).unwrap();
            h.pump();
            let last = h.model.transmitted.borrow().last().unwrap().clone();
            if !h.device.link_up()
                || h.peer.lock().uplink.last() != Some(&other)
                || last.get(24..26) != Some(&[7, 0])
                || h.model.queues.borrow().last() != Some(&3)
            {
                return TestResult::Fail(
                    "nonzero-TID single corrupted sender BA or missed its native QCU",
                );
            }
            for frame in &frames {
                narf_net::iface::send_on(h.device.name(), frame).unwrap();
            }
            h.pump();
            let head = h.model.last_chain.borrow()[0];
            let original = h.model.bytes(h.model.word(head + 4).unwrap(), 26).unwrap();
            if (u16::from_le_bytes([original[22], original[23]]) >> 4) != next
                || !h.peer.lock().uplink.ends_with(&frames)
            {
                return TestResult::Fail(
                    "other-TID single advanced TID0 BA/SC before next eight-link chain",
                );
            }
            let down = udp_ipv4(
                h.plan.station,
                AP,
                h.plan.server_ip,
                h.plan.lease_ip,
                7,
                49200,
                b"v4 current downlink",
            );
            let wire = h.peer.lock().downlink(&down).unwrap();
            h.model.inject(&wire, 0).unwrap();
            h.pump();
            if !h.received().contains(&down) {
                return TestResult::Fail("v4 sender lost ordinary/recipient native current RX");
            }
            h.device.retire_host();
            h.pump();
            if h.model.master.get()
                || h.model.released.borrow().len() != 19
                || h.device.enqueue(&frames[0], Default::default()).is_ok()
            {
                return TestResult::Fail(
                    "v4 retirement lost original ring/new maps or reopened name",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/large-tx",
    smoke_ar9285_large_tx_public_ipc_eight_originals_kernel_dhcp_and_recipient_coexistence
);
