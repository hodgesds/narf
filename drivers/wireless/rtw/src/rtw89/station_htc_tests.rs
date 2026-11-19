//! HE +HTC through the retained station, real packet core and AP CCMP peer.
use super::*;

fn smoke_rtw8852b_he_htc_report_fallback_ccmp_and_downlink() -> TestResult {
    const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    for protected in [false, true] {
        let h = Harness::build_phy(
            protected,
            true,
            false,
            Some(&RATES),
            true,
            Some((true, &HE_IES)),
        );
        if h.join().is_err() || !h.peer.lock().station_ht || !h.peer.lock().station_he {
            return TestResult::Fail("HE +HTC fixture association");
        }
        let ethernet = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 5, 6, b"htc");
        let send = |ethernet: &[u8]| {
            let before = h.peer.lock().uplink.len();
            let result = narf_net::iface::send_on(h.device.name(), ethernet);
            h.pump();
            result.is_ok()
                && !h.closed()
                && h.peer.lock().uplink.len() == before + 1
                && h.peer.lock().uplink.last().map(Vec::as_slice) == Some(ethernet)
        };
        // Conservative before the first report; then MCS3 enables insertion,
        // MCS2 fences it, a new high rate permits it, and legacy fences it.
        for rate in [None, Some(3), Some(2), Some(11), Some(0)] {
            if let Some(mcs) = rate {
                let mut report = [6, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, mcs, 3, 0, 0];
                if mcs == 0 {
                    report[13] = 0;
                }
                if h.model(|io| io.packets.inject_c2h(&report)).is_err() {
                    return TestResult::Fail("native C2H fixture injection");
                }
                h.pump();
            }
            if !send(&ethernet) {
                return TestResult::Fail("HE +HTC native TXWD or AP CCMP failed");
            }
            let frame = h.model(|io| io.packets.transmitted.last().unwrap().clone());
            let expected = rate.is_some_and(|mcs| mcs > 2);
            if (frame[1] & 0x80 != 0) != expected
                || expected && frame[24..30] != [0x10, 0, 0x1b, 0, 0, 0]
            {
                narf_console::klog!(
                    "HTC report {:?}: expected {}, FC {:02x?} QoS/control {:02x?}\n",
                    rate,
                    expected,
                    &frame[..2],
                    &frame[24..30]
                );
                return TestResult::Fail("RA fallback did not control actual +HTC bytes");
            }
        }
        // A different MACID cannot lift the last low-rate fence.
        let mut report = [6, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 3, 3, 0, 0];
        h.model(|io| io.packets.inject_c2h(&report)).unwrap();
        h.pump();
        if !send(&ethernet) || h.model(|io| io.packets.transmitted.last().unwrap()[1] & 0x80 != 0) {
            return TestResult::Fail("foreign RA report changed live HE header form");
        }
        report[8] = 0;
        h.model(|io| io.packets.inject_c2h(&report)).unwrap();
        h.pump();
        // A high rate does not override ARP/ICMP/DHCP interoperability rules.
        let mut arp = ethernet.clone();
        arp[12..14].copy_from_slice(&[8, 6]);
        let mut icmp = ethernet.clone();
        icmp[23] = 1;
        let dhcp = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 68, 67, b"dhcp");
        for special in [&arp, &icmp, &dhcp] {
            if !send(special) || h.model(|io| io.packets.transmitted.last().unwrap()[1] & 0x80 != 0)
            {
                return TestResult::Fail("HE +HTC altered a special packet header");
            }
        }
        if !send(&ethernet) || !h.model(|io| io.packets.transmitted.last().unwrap()[1] & 0x80 != 0)
        {
            return TestResult::Fail("ordinary data did not restore HE +HTC after special packet");
        }
        // A-Control is excluded from the CCMP AAD: adding it to the peer's
        // already-protected downlink must preserve the MIC and TID replay.
        let reply = udp_ipv4(
            OWN,
            AP,
            h.plan.server_ip,
            h.plan.lease_ip,
            6,
            5,
            b"htc-down",
        );
        let mut wire = h.peer.lock().downlink(&reply).unwrap();
        wire[1] |= 0x80;
        wire[24] |= 0x10;
        wire.splice(26..26, [0x1b, 0, 0, 0]);
        if h.model(|io| io.packets.inject_phy(&wire, 0x183, 5))
            .is_err()
        {
            return TestResult::Fail("HE +HTC downlink injection");
        }
        h.pump();
        if h.received() != vec![reply] {
            return TestResult::Fail("HE +HTC downlink normalization or CCMP failed");
        }
        if complete(h.device.disassociate()).is_err() || !h.closed() {
            return TestResult::Fail("HE +HTC disconnect retained carrier");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/htc",
    smoke_rtw8852b_he_htc_report_fallback_ccmp_and_downlink
);
