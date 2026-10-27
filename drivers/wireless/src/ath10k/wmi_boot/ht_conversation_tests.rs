//! HT20 service facts, native commands and actual DMA packet conversations.
use super::*;
#[path = "rx_ba_conversation_tests.rs"]
mod rx_ba_conversation_tests;

fn elements(primary: u8) -> Vec<u8> {
    // HT20/SGI20, SMPS disabled,64KiB/8us peer A-MPDU limit, MCS0..7.
    let mut ies = vec![45, 26, 0x2c, 0, 0x1b, 0xff];
    ies.extend_from_slice(&[0; 11]);
    ies.push(1);
    ies.extend_from_slice(&[0; 10]);
    ies.extend_from_slice(&[61, 22, primary]);
    ies.extend_from_slice(&[0; 21]);
    ies
}
pub(super) fn enable(h: &Harness) {
    {
        let mut r = h.device.radio.try_lock().unwrap();
        let caps = r.htt.wmi.caps.as_mut().unwrap();
        caps.ht = 3; // Source SERVICE_READY HT-enabled and SGI20 bits.
        caps.rf_chains = 2;
    }
    let primary = h.request().channel as u8;
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.wmm_offer = Some(WMM_PARAMETERS.to_vec());
        f.wmm_response = Some(WMM_PARAMETERS.to_vec());
        f.ht_offer = Some(elements(primary));
        f.ht_response = Some(elements(primary));
        f.ht_expected = true;
    });
}
fn smoke_ath10k_ht20_sgi_native_six_dialects_open_wpa2_dhcp_ip() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for frequency in [2412, 5180] {
            for secured in [false, true] {
                if let Err(error) = composition_radio(
                    version,
                    dialect,
                    secured,
                    false,
                    false,
                    frequency,
                    TestPhy::Ht,
                ) {
                    return TestResult::Fail(error);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht20_sgi_native_six_dialects_open_wpa2_dhcp_ip
);

fn smoke_ath10k_ht_response_mcs_guard_density_are_bound_to_native_peer() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new(version, dialect, true);
        enable(&h);
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            let response = f.ht_response.as_mut().unwrap();
            response[2] = 0x0c;
            response[4] = 0x08;
            response[5] = 0x15;
            f.ht_sgi = false;
            f.ht_ampdu = 0x08;
            f.ht_mcs = 0x15;
            f.ht_capabilities = 0x000c;
        });
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (uplink, _) = packets();
        if narf_net::iface::send_on(&h.name, &uplink).is_err() {
            return TestResult::Fail("HT response-bound native DATA enqueue");
        }
        h.pump();
        if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&uplink)) {
            return TestResult::Fail("HT peer response did not survive actual HTT TX");
        }
        // Peer RX capabilities narrow our TX; AP TX uses the local RX
        // capability actually sent in our association request.
        let (_, downlink) = packets();
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.rx_phy = Some((8, 7, 0x80));
            let frame = f.downlink(&downlink);
            f.queue.push_back(frame);
        });
        h.pump();
        if !h.received(&downlink) {
            return TestResult::Fail("peer RX mask/SGI was incorrectly applied to native AP TX");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_response_mcs_guard_density_are_bound_to_native_peer
);

fn smoke_ath10k_ht_malformed_offer_fails_before_native_station_publication() -> TestResult {
    for case in 0..6 {
        let h = Harness::new(4, Dialect::Tlv, false);
        enable(&h);
        h.model(|m| {
            let ie = m.data.as_mut().unwrap().ht_offer.as_mut().unwrap();
            match case {
                0 => ie.extend_from_slice(&elements(1)),
                1 => ie[30] = 6,
                2 => ie[37] = 1,
                3 => ie[5] = 0,
                4 => {
                    ie[29] = 21;
                    ie.pop();
                }
                _ => {
                    ie[1] = 25;
                    ie.remove(27);
                }
            }
        });
        if matches!(case, 0 | 1 | 4) {
            // The native scan cache already rejects duplicate/wrong-primary
            // or short HT Operation. Such an AP must not become a join plan.
            let result = drive(h.device.scan(ScanRequest {
                frequencies_mhz: vec![2412],
                channels: vec![1],
                ssids: vec![],
                active: false,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: None,
                duration_mandatory: false,
                extra_ies: vec![],
            }));
            if !matches!(result, Poll::Ready(Ok(bss)) if bss.is_empty())
                || !h.never_opened()
                || !h.model(|m| m.native_management.is_empty())
            {
                return TestResult::Fail("malformed HT Operation entered native scan cache");
            }
            continue;
        }
        if let Err(error) = h.scan() {
            return TestResult::Fail(error);
        }
        let before = h.model(|m| m.sent.len());
        if !matches!(
            drive(h.device.associate_for_test(h.request(), [0x73; 32])),
            Poll::Ready(Err(_))
        ) || !h.never_opened()
            || !h.model(|m| m.sent.len() == before && m.native_management.is_empty())
        {
            return TestResult::Fail("malformed HT offer emitted native station/management");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_malformed_offer_fails_before_native_station_publication
);

fn smoke_ath10k_ht_missing_or_incompatible_response_never_opens_port() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for case in 0..4 {
            let h = Harness::new(version, dialect, true);
            enable(&h);
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                match case {
                    0 => f.ht_response = None,
                    1 => f.ht_response.as_mut().unwrap()[30] = 6,
                    2 => f.ht_response.as_mut().unwrap()[5] = 0,
                    _ => f
                        .ht_response
                        .as_mut()
                        .unwrap()
                        .extend_from_slice(&elements(1)),
                }
            });
            if let Err(error) = h.scan() {
                return TestResult::Fail(error);
            }
            if !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            ) || !h.never_opened()
                || !h.model(|m| m.data.as_ref().unwrap().control_phase == 2)
            {
                return TestResult::Fail("HT response failure published native peer or WPA2 port");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_missing_or_incompatible_response_never_opens_port
);

fn smoke_ath10k_ht_rx_width_mcs_guard_checks_precede_ccmp_replay_commit() -> TestResult {
    for (preamble, sig, guard) in [(8, 0x80, 0), (8, 8, 0), (12, 0, 0), (8, 7, 0x80)] {
        let h = Harness::new(4, Dialect::Tlv, true);
        enable(&h);
        if guard != 0 {
            h.device
                .radio
                .try_lock()
                .unwrap()
                .htt
                .wmi
                .caps
                .as_mut()
                .unwrap()
                .ht = 1;
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.ht_response.as_mut().unwrap()[2] = 0x0c;
                f.ht_capabilities = 0x000c;
                f.ht_sgi = false;
                f.ht_request_sgi = false;
            });
        }
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (_, downlink) = packets();
        let encrypted = h.model(|m| m.data.as_mut().unwrap().downlink(&downlink));
        let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.rx_phy = Some((preamble, sig, guard));
            f.queue.push_back(encrypted.clone());
        });
        h.pump();
        if !h.device.link_up()
            || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
        {
            return TestResult::Fail("unnegotiated native HT width/MCS admitted protected data");
        }
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.rx_phy = Some((9, 7, if guard != 0 { 0 } else { 0x80 }));
            f.queue.push_back(encrypted);
        });
        h.pump();
        if narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before + 1 {
            return TestResult::Fail("bad HT metadata consumed PN before valid native RX");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_rx_width_mcs_guard_checks_precede_ccmp_replay_commit
);

fn smoke_ath10k_ht_firmware_wmm_gates_keep_genuine_legacy_fallback() -> TestResult {
    for case in 0..4 {
        let h = Harness::new(4, Dialect::Tlv, true);
        enable(&h);
        {
            let mut r = h.device.radio.try_lock().unwrap();
            let caps = r.htt.wmi.caps.as_mut().unwrap();
            match case {
                0 => caps.ht = 0,
                1 => caps.rf_chains = 0,
                2 => caps.ht = 1,
                _ => {}
            }
        }
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.ht_expected = case == 2;
            if case == 2 {
                f.ht_request_sgi = false;
                f.ht_sgi = false;
                // The AP's original002c body remains unchanged. Native
                // peer_ht_caps must mask SGI20 by actual local support,
                // exactly as mac80211 does before PEER_ASSOC.
                f.ht_capabilities = 0x000c;
            }
            if case == 3 {
                f.wmm_offer = None;
                f.wmm_response = None;
            }
        });
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (uplink, _) = packets();
        if narf_net::iface::send_on(&h.name, &uplink).is_err() {
            return TestResult::Fail("firmware/WMM HT gate denied legacy fallback DATA");
        }
        h.pump();
        if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&uplink)) {
            return TestResult::Fail("fallback/native DATA did not retain actual DMA path");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_firmware_wmm_gates_keep_genuine_legacy_fallback
);

fn smoke_ath10k_ht_pending_native_peer_cancel_or_policy_loss_keeps_dma_closed() -> TestResult {
    for revoke in [false, true] {
        let h = Harness::new(4, Dialect::Tlv, true);
        enable(&h);
        h.model(|m| m.data.as_mut().unwrap().wmm_hold = true);
        if let Err(error) = h.scan() {
            return TestResult::Fail(error);
        }
        {
            let mut future = core::pin::pin!(h.device.associate_for_test(h.request(), [0x73; 32]));
            if !drive(future.as_mut()).is_pending() {
                return TestResult::Fail("HT native WMM publication did not retain waiter");
            }
            if revoke {
                *h.policy.lock() = None;
                if !matches!(drive(future.as_mut()), Poll::Ready(Err(_))) {
                    return TestResult::Fail("HT native wait ignored current policy loss");
                }
            }
        }
        *h.policy.lock() = Some(station_tests::policy());
        let before = h.model(|m| m.sent.len());
        if !h.never_opened()
            || !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            )
            || !h.model(|m| {
                m.sent.len() == before
                    && m.inner.inner.retained.is_some()
                    && m.inner.storage.as_ref().is_some_and(|s| s.filled == 1023)
            })
        {
            return TestResult::Fail("cancelled/revoked HT peer reopened or released native DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_pending_native_peer_cancel_or_policy_loss_keeps_dma_closed
);

fn subframes(ethernet: &[u8], count: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for at in 0..count {
        body.extend_from_slice(&ethernet[..12]);
        body.extend_from_slice(&((ethernet.len() - 6) as u16).to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        body.extend_from_slice(&ethernet[12..]);
        if at + 1 < count {
            while body.len() % 4 != 0 {
                body.push(0x5a);
            }
        }
    }
    body
}
fn aggregate(h: &Harness, mut body: Vec<u8>, pn: u64) -> Vec<u8> {
    let mut header = vec![0; 26];
    header[0] = 0x88;
    header[1] = if h.secured { 0x42 } else { 2 };
    header[4..10].copy_from_slice(&OWN);
    header[10..16].copy_from_slice(&AP);
    header[16..22].copy_from_slice(&AP);
    header[24] = 0x80;
    if h.secured {
        body = h.model(|m| {
            let f = m.data.as_ref().unwrap();
            let tk = f.ptk.as_ref().unwrap().tk.as_slice().try_into().unwrap();
            narf_wireless::ccmp::protect(&Ccm, &header, tk, pn, 0, 0, false, &mut body).unwrap()
        });
    }
    header.extend_from_slice(&body);
    header
}
fn inject_aggregate(h: &Harness, frame: Vec<u8>) {
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.rx_phy = Some((8, 7, 0x80));
        f.queue.push_back(frame);
    });
    h.pump();
}
fn smoke_ath10k_ht_amsdu_native_raw_open_wpa2_all_dialects() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for secured in [false, true] {
            let h = Harness::new(version, dialect, secured);
            enable(&h);
            if let Err(error) = h.join() {
                return TestResult::Fail(error);
            }
            let (_, downlink) = packets();
            let frame = aggregate(&h, subframes(&downlink, 2), 1);
            let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
            inject_aggregate(&h, frame.clone());
            if !h.device.link_up()
                || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before + 2
                || !h.received(&downlink)
                || !h.received(&downlink)
            {
                return TestResult::Fail(
                    "native RAW aggregate did not publish exact two Ethernet frames",
                );
            }
            if secured {
                inject_aggregate(&h, frame);
                if narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before + 2 {
                    return TestResult::Fail(
                        "native aggregate replay escaped shared TID/key epoch",
                    );
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_amsdu_native_raw_open_wpa2_all_dialects
);

fn smoke_ath10k_ht_amsdu_later_subframe_or_mic_failure_cannot_publish_or_consume_pn() -> TestResult
{
    for case in 0..4 {
        let h = Harness::new(4, Dialect::Tlv, true);
        enable(&h);
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (_, downlink) = packets();
        let valid = subframes(&downlink, 2);
        let mut malformed = valid.clone();
        let second = (14 + downlink.len() - 6).next_multiple_of(4);
        match case {
            0 => malformed[second + 12..second + 14].copy_from_slice(&0xffffu16.to_be_bytes()),
            1 => malformed[second + 20..second + 22].copy_from_slice(&[0x88, 0x8e]),
            2 => malformed[second..second + 6].copy_from_slice(&[4; 6]),
            _ => {}
        }
        let mut bad = aggregate(&h, malformed, 1);
        if case == 3 {
            *bad.last_mut().unwrap() ^= 1;
        }
        let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
        inject_aggregate(&h, bad);
        if !h.device.link_up()
            || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
        {
            return TestResult::Fail(
                "bad aggregate published a prefix or closed current native owner",
            );
        }
        inject_aggregate(&h, aggregate(&h, valid, 1));
        if narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before + 2 {
            return TestResult::Fail(
                "bad native aggregate consumed shared PN before full validation",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_amsdu_later_subframe_or_mic_failure_cannot_publish_or_consume_pn
);

fn retained_native_dma(h: &Harness) -> bool {
    h.model(|m| {
        m.inner.inner.retained.is_some()
            && m.inner
                .storage
                .as_ref()
                .is_some_and(|storage| storage.filled == 1023)
    })
}

fn smoke_ath10k_ht_open_aggregate_qos_header_mutations_never_reach_host() -> TestResult {
    for (at, mask) in [(24, 0x10), (24, 0x20), (25, 1), (1, 0x80)] {
        let h = Harness::new(4, Dialect::Tlv, false);
        enable(&h);
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (_, downlink) = packets();
        let valid = aggregate(&h, subframes(&downlink, 2), 0);
        let mut bad = valid.clone();
        bad[at] ^= mask;
        let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
        inject_aggregate(&h, bad);
        if !h.device.link_up()
            || h.received(&downlink)
            || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
        {
            return TestResult::Fail("Open aggregate accepted EOSP/ACK/HT-control header alias");
        }
        inject_aggregate(&h, valid);
        if !h.received(&downlink)
            || !h.received(&downlink)
            || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before + 2
        {
            return TestResult::Fail("bad Open QoS aggregate poisoned genuine native RX");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_open_aggregate_qos_header_mutations_never_reach_host
);

fn policy_loss_at_publication(
    point: crate::ath10k::interface::ReceivePoint,
) -> Result<(), &'static str> {
    use crate::ath10k::interface::ReceivePoint;
    use core::sync::atomic::{AtomicUsize, Ordering};
    let h = Harness::new(4, Dialect::Tlv, true);
    enable(&h);
    h.join()?;
    let policy = h.policy.clone();
    let reached = Arc::new(AtomicUsize::new(0));
    let count = reached.clone();
    h.device.set_receive_hook_for_test(move |at| {
        if at == point {
            count.fetch_add(1, Ordering::AcqRel);
            *policy.lock() = None;
        }
    });
    let (_, downlink) = packets();
    let frame = aggregate(&h, subframes(&downlink, 2), 1);
    let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
    inject_aggregate(&h, frame);
    if reached.load(Ordering::Acquire) != 1
        || !h.closed()
        || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
        || !retained_native_dma(&h)
    {
        return Err(
            "final aggregate policy loss published stack data/carrier or released native DMA",
        );
    }
    if point == ReceivePoint::AfterFrameAllocation {
        if h.received(&downlink) {
            return Err("policy revoked after real allocation still published IPC frame");
        }
    } else if !h.received(&downlink) || !h.received(&downlink) {
        // IPC preceded this independent revocation point and was authorized.
        // The separately checked network callback must still be suppressed.
        return Err("callback-boundary fixture did not first publish authorized IPC batch");
    }
    *h.policy.lock() = Some(station_tests::policy());
    inject_aggregate(&h, aggregate(&h, subframes(&downlink, 2), 2));
    let (uplink, _) = packets();
    if !h.closed()
        || h.received(&downlink)
        || h.device.enqueue(&uplink, narf_net::TxMeta::plain()).is_ok()
        || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
    {
        return Err("restored policy revived terminal aggregate publication owner");
    }
    Ok(())
}
fn smoke_ath10k_ht_aggregate_policy_revoked_after_allocation_cannot_publish_ipc() -> TestResult {
    policy_loss_at_publication(crate::ath10k::interface::ReceivePoint::AfterFrameAllocation)
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_aggregate_policy_revoked_after_allocation_cannot_publish_ipc
);
fn smoke_ath10k_ht_aggregate_policy_revoked_before_callback_cannot_publish_stack() -> TestResult {
    policy_loss_at_publication(crate::ath10k::interface::ReceivePoint::BeforeCallbackAdmission)
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_aggregate_policy_revoked_before_callback_cannot_publish_stack
);

fn smoke_ath10k_ht_same_drain_rekey_withholds_aggregate_until_current_port() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    enable(&h);
    if let Err(error) = h.join() {
        return TestResult::Fail(error);
    }
    let (uplink, downlink) = packets();
    let native = aggregate(&h, subframes(&downlink, 2), 1);
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.rx_phy = Some((8, 7, 0x80));
        f.hold_data = true;
        let group = f.group_rekey();
        f.queue.push_back(native);
        f.queue.push_back(group);
    });
    let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
    h.pump();
    if !h.device.link_up()
        || h.received(&downlink)
        || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
        || !h.model(|m| {
            let f = m.data.as_ref().unwrap();
            f.held.len() == 1 && f.group_replies == 1
        })
        || h.device
            .radio
            .try_lock()
            .unwrap()
            .data_permission()
            .is_some()
        || !retained_native_dma(&h)
    {
        return TestResult::Fail(
            "same-drain rekey published aggregate prefix or lost retained carrier/reply",
        );
    }
    let sent = h.model(|m| m.data.as_ref().unwrap().uplink.len());
    if h.device
        .enqueue(&uplink, narf_net::TxMeta::plain())
        .is_err()
    {
        return TestResult::Fail("established rekey could not retain ordinary queued host TX");
    }
    h.pump();
    if h.model(|m| m.data.as_ref().unwrap().uplink.len()) != sent {
        return TestResult::Fail("same-drain closed rekey port transmitted queued host data");
    }
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.hold_data = false;
        let id = f.held.pop_front().unwrap();
        complete(m, id, 0);
    });
    h.pump();
    if !h.device.link_up()
        || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&uplink))
        || narf_net::iface::lookup(&h.name)
            .is_none_or(|i| i.carrier_up_count != 1 || i.carrier_down_count != 0)
    {
        return TestResult::Fail(
            "actual rekey terminal receipt lost carrier or withheld queued data",
        );
    }
    inject_aggregate(&h, aggregate(&h, subframes(&downlink, 2), 2));
    if !h.received(&downlink)
        || !h.received(&downlink)
        || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before + 2
    {
        return TestResult::Fail(
            "current reopened rekey port did not admit fresh native aggregate",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_same_drain_rekey_withholds_aggregate_until_current_port
);

fn smoke_ath10k_ht_initial_held_m4_never_publishes_aggregate_or_carrier() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    enable(&h);
    if let Err(error) = h.scan() {
        return TestResult::Fail(error);
    }
    let (_, downlink) = packets();
    let key = narf_wireless::eapol::wpa_pmk_to_ptk(
        narf_wireless::eapol::KeyMgmt::Psk,
        &PMK,
        &AP,
        &OWN,
        &ANONCE,
        &[0x73; 32],
        16,
    );
    let mut frame = vec![0; 26];
    frame[0] = 0x88;
    frame[1] = 0x42;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[24] = 0x80;
    let body = narf_wireless::ccmp::protect(
        &Ccm,
        &frame,
        key.tk.as_slice().try_into().unwrap(),
        1,
        0,
        0,
        false,
        &mut subframes(&downlink, 2),
    )
    .unwrap();
    frame.extend_from_slice(&body);
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.hold_m4 = true;
        f.rx_phy = Some((8, 7, 0x80));
        f.queue.push_back(frame);
    });
    let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
    {
        let mut future = core::pin::pin!(h.device.associate_for_test(h.request(), [0x73; 32]));
        if !drive(future.as_mut()).is_pending()
            || !h.never_opened()
            || h.received(&downlink)
            || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
        {
            return TestResult::Fail(
                "initial held native M4 admitted aggregate or initial carrier",
            );
        }
    }
    h.pump();
    if !h.never_opened() || h.received(&downlink) || !retained_native_dma(&h) {
        return TestResult::Fail("cancelled initial M4 published late aggregate or released DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_initial_held_m4_never_publishes_aggregate_or_carrier
);

static CALLBACK_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static CALLBACK_LOCKS_OK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);
fn reentrant_stack_callback(name: &str, bytes: &mut [u8]) {
    use core::sync::atomic::Ordering;
    let device = { ACTIVE_TEST.lock().clone() };
    if let Some(device) = device.filter(|d| d.name() == name) {
        let (uplink, _) = packets();
        if !device.callback_locks_available_for_test()
            || narf_net::iface::send_on(name, &uplink).is_err()
        {
            CALLBACK_LOCKS_OK.store(false, Ordering::Release);
        }
        CALLBACK_COUNT.fetch_add(1, Ordering::AcqRel);
    }
    narf_net::tcp_stack::rx_handler(name, bytes);
}
struct RestoreStackHandler;
impl Drop for RestoreStackHandler {
    fn drop(&mut self) {
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
    }
}
fn smoke_ath10k_ht_aggregate_actual_stack_callback_can_reenter_unlocked_driver() -> TestResult {
    use core::sync::atomic::Ordering;
    let h = Harness::new(4, Dialect::Tlv, true);
    enable(&h);
    if let Err(error) = h.join() {
        return TestResult::Fail(error);
    }
    CALLBACK_COUNT.store(0, Ordering::Release);
    CALLBACK_LOCKS_OK.store(true, Ordering::Release);
    let _restore = RestoreStackHandler;
    narf_net::iface::install_rx_handler(reentrant_stack_callback);
    let (_, downlink) = packets();
    inject_aggregate(&h, aggregate(&h, subframes(&downlink, 2), 1));
    if CALLBACK_COUNT.load(Ordering::Acquire) != 2
        || !CALLBACK_LOCKS_OK.load(Ordering::Acquire)
        || !h.device.link_up()
        || !h.model(|m| m.data.as_ref().unwrap().uplink.len() >= 2)
    {
        return TestResult::Fail(
            "actual aggregate callback held driver locks or blocked synchronous replies",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_ht_aggregate_actual_stack_callback_can_reenter_unlocked_driver
);
