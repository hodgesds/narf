//! Tag5 `QOS_TIDS` program: per-TID DQA queues for all four access
//! categories, 802.1D classification and receipt-fenced retirement.
use super::super::super::mvm_boot::feature_bits;
use super::*;

fn with_dscp(mut ethernet: Vec<u8>, dscp: u8) -> Vec<u8> {
    ethernet[15] = dscp << 2;
    ethernet
}

fn uplink(dscp: u8, tag: &[u8]) -> Vec<u8> {
    with_dscp(
        udp_ipv4(AP, OWN, NETWORK.lease_ip, NETWORK.server_ip, 49152, 7, tag),
        dscp,
    )
}

fn smoke_mvm_qos_tids_program_allocates_all_tids_and_classifies_traffic() -> TestResult {
    check(|| {
        let h = Harness::build_features(false, true, 5, 3, false, false, feature_bits::QOS_TIDS)?;
        h.join()?;
        // Management 23, TID0 24 and TIDs 1..=7 on 25..=31.
        if h.retained().1 != 9 {
            return Err("tag5 QOS_TIDS did not allocate one DQA queue per TID");
        }
        let lease =
            narf_net::dhcp::dhcp_acquire(h.device.name(), 0).map_err(|_| "QoS TID kernel DHCP")?;
        if !NETWORK.matches_lease(&lease) {
            return Err("QoS TID DHCP lease mismatch");
        }
        // RFC 8325 / cfg80211_classify8021d: EF->6 (VO), AF41->4 (VI),
        // CS1->1 (BK), CS3->4, CS6->7, AF21->3 (BE), default 0.
        let cases = [
            (46u8, 6u8, b"ef".as_slice()),
            (34, 4, b"af41"),
            (8, 1, b"cs1"),
            (24, 4, b"cs3"),
            (48, 7, b"cs6"),
            (18, 3, b"af21"),
            (0, 0, b"be"),
        ];
        for (dscp, _, tag) in cases {
            narf_net::iface::send_on(h.device.name(), &uplink(dscp, tag))
                .map_err(|_| "QoS TID uplink admission")?;
            h.pump()?;
        }
        {
            let actor = h.actor.lock();
            for (dscp, tid, tag) in cases {
                let frame = uplink(dscp, tag);
                if !actor
                    .tid_frames
                    .iter()
                    .any(|(t, q, e)| *t == tid && *q == 24 + u16::from(tid) && *e == frame)
                {
                    return Err("QoS frame not on its TID queue with its QoS TID");
                }
            }
        }
        let start = {
            let mut actor = h.actor.lock();
            actor.closing = true;
            actor.commands.len()
        };
        run(h.device.disassociate())?.map_err(|_| "QoS TID ordered close")?;
        leaving_deauthentication_preceded_teardown(&h, start)?;
        let removed = h
            .actor
            .lock()
            .commands
            .iter()
            .filter(|(g, c, b)| *g == 5 && *c == 0x17 && b[0] == 1)
            .count();
        if h.retained() != (0, 0, 0) || removed != 9 {
            return Err("QoS TID close did not remove every DQA queue by receipt");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/qos",
    smoke_mvm_qos_tids_program_allocates_all_tids_and_classifies_traffic
);

fn smoke_mvm_without_tag5_program_qos_stays_on_be_tid0() -> TestResult {
    check(|| {
        let h = Harness::profile(false, true)?;
        h.join()?;
        if h.retained().1 != 2 {
            return Err("tag2 program allocated extra TID queues");
        }
        let frame = uplink(46, b"ef-without-tag5");
        narf_net::iface::send_on(h.device.name(), &frame).map_err(|_| "tag2 uplink")?;
        h.pump()?;
        let actor = h.actor.lock();
        if !actor.security.data.contains(&frame) || !actor.tid_frames.is_empty() {
            return Err("EF traffic left BE/TID0 without a QOS_TIDS program");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/qos",
    smoke_mvm_without_tag5_program_qos_stays_on_be_tid0
);

fn wmm(acm: [bool; 4]) -> narf_wireless::wmm::Parameters {
    // WMM Parameter element, ACI order BE, BK, VI, VO.
    let mut ie = vec![221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0];
    for (aci, aifsn) in [(0u8, 3u8), (1, 7), (2, 2), (3, 2)] {
        let acm = u8::from(acm[usize::from(aci)]) << 4;
        ie.extend_from_slice(&[aci << 5 | acm | aifsn, 0xa4, 0, 0]);
    }
    narf_wireless::wmm::Parameters::parse(&ie)
        .ok()
        .flatten()
        .expect("fixture WMM IE")
}

fn smoke_mvm_qos_user_priority_and_acm_downgrade_match_mac80211() -> TestResult {
    use super::super::super::mvm_boot::data_priority::{admitted_priority, user_priority};
    let mut v6 = vec![0u8; 54];
    v6[12..14].copy_from_slice(&[0x86, 0xdd]);
    // Traffic class EF (46 << 2 = 0xb8) split across bytes 14/15.
    v6[14] = 0x60 | 0xb;
    v6[15] = 0x80;
    let mut arp = uplink(46, b"x");
    arp[12..14].copy_from_slice(&[8, 6]);
    if user_priority(&uplink(46, b"x")) != 6
        || user_priority(&uplink(10, b"x")) != 0
        || user_priority(&uplink(40, b"x")) != 5
        || user_priority(&uplink(56, b"x")) != 7
        || user_priority(&v6) != 6
        || user_priority(&arp) != 0
    {
        return TestResult::Fail("802.1D classification differs from cfg80211");
    }
    let open = wmm([false; 4]);
    let vo_acm = wmm([false, false, false, true]);
    let vo_vi_acm = wmm([false, false, true, true]);
    let all = wmm([true; 4]);
    if admitted_priority(&open, 6) != 6
        || admitted_priority(&vo_acm, 7) != 5
        || admitted_priority(&vo_vi_acm, 6) != 3
        || admitted_priority(&vo_vi_acm, 1) != 1
        || admitted_priority(&all, 6) != 2
    {
        return TestResult::Fail("ACM downgrade differs from ieee80211_downgrade_queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/qos",
    smoke_mvm_qos_user_priority_and_acm_downgrade_match_mac80211
);
