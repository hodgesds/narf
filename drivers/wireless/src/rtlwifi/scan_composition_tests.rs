// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual physical channel filtering, native probes/RX, fresh owner and DHCP.
use super::channel_tests::{idle_receipt, peer_channel};
use super::*;
fn request(channels: &[u32], active: bool) -> ScanRequest {
    ScanRequest {
        ssids: vec![SSID.to_vec()],
        frequencies_mhz: channels.iter().map(|channel| 2407 + channel * 5).collect(),
        channels: channels.to_vec(),
        active,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: Some(1),
        duration_mandatory: true,
        extra_ies: Vec::new(),
    }
}
fn active(protected: bool) -> TestResult {
    let h = Harness::new(protected);
    peer_channel(&h, 6);
    idle_receipt(&h);
    let result = complete(h.device.scan(request(&[1, 6, 11], true)));
    if !result.is_ok_and(|b| b.len() == 1 && b[0].channel == 6 && b[0].bssid == PEER)
        || h.device.channel_for_test() != 1
        || h.packet.radio.rf(0x18) & 255 != 1
        || h.device.scan_information_elements(PEER).is_none()
        || h.device.link_up()
    {
        return TestResult::Fail(
            "EE multi-channel scan lost physical BSS, owned IEs or home channel",
        );
    }
    let probes = h.peer.lock().probes.len();
    let mut join = h.request();
    join.channel = 6;
    join.frequency_mhz = 2437;
    if complete(h.device.associate(join)).is_err()
        || !h.device.link_up()
        || h.peer.lock().probes.len() <= probes
        || h.packet.radio.rf(0x18) & 255 != 6
    {
        return TestResult::Fail("EE scan-selected join lacked fresh physical target reception");
    }
    let plan = h.peer.lock().plan;
    if !narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
        .is_ok_and(|lease| plan.matches_lease(&lease))
    {
        return TestResult::Fail("EE multi-channel selected Open/WPA2 owner failed actual DHCP");
    }
    TestResult::Pass
}
fn smoke_rtl8188ee_multichannel_active_open_fresh_join_dhcp() -> TestResult {
    active(false)
}
fn smoke_rtl8188ee_multichannel_active_wpa2_fresh_join_dhcp() -> TestResult {
    active(true)
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_multichannel_active_open_fresh_join_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_multichannel_active_wpa2_fresh_join_dhcp
);
fn smoke_rtl8188ee_multichannel_passive_default_plan_and_physical_reception() -> TestResult {
    let h = Harness::new(false);
    peer_channel(&h, 11);
    idle_receipt(&h);
    if h.device.get_wireless_info().bands[0].channels != (1..=11).collect::<Vec<u32>>() {
        return TestResult::Fail("EE discovery differs from currently qualified channel set");
    }
    if !complete(h.device.scan(request(&[], false)))
        .is_ok_and(|b| b.len() == 1 && b[0].channel == 11 && b[0].frequency_mhz == 2462)
        || h.device.channel_for_test() != 1
        || !h.peer.lock().probes.is_empty()
        || h.packet
            .model
            .lock()
            .observed
            .iter()
            .any(|frame| frame.first() == Some(&0x40))
    {
        return TestResult::Fail("EE passive scan transmitted or received an off-channel peer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_multichannel_passive_default_plan_and_physical_reception
);
fn smoke_rtl8188ee_multichannel_prevalidation_and_stale_display_cache() -> TestResult {
    let h = Harness::new(false);
    let generation = h.device.generation_for_test();
    let accesses = h.packet.radio.accesses();
    let mut invalid = request(&[1, 6], true);
    invalid.frequencies_mhz = vec![2412];
    if complete(h.device.scan(invalid)).is_ok()
        || h.device.generation_for_test() != generation
        || h.packet.radio.accesses() != accesses
    {
        return TestResult::Fail("EE conflicting scan selectors mutated native radio");
    }
    peer_channel(&h, 6);
    idle_receipt(&h);
    if complete(h.device.scan(request(&[1, 6, 11], true))).is_err()
        || h.device.scan_information_elements(PEER).is_none()
    {
        return TestResult::Fail("EE fixture failed to retain scan display metadata");
    }
    peer_channel(&h, 11); // The BSSID moved after the displayed scan result.
    let mut join = h.request();
    join.channel = 6;
    join.frequency_mhz = 2437;
    let before = h.packet.model.lock().observed.len();
    if complete(h.device.associate(join)).is_ok()
        || h.device.link_up()
        || h.packet.model.lock().observed[before..]
            .iter()
            .any(|frame| matches!(frame.first(), Some(0xb0 | 0)))
    {
        return TestResult::Fail(
            "EE display cache substituted for fresh RX or published authentication",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_multichannel_prevalidation_and_stale_display_cache
);
fn smoke_rtl8188ee_multichannel_cancel_keeps_owned_transition_and_no_partial_cache() -> TestResult {
    let h = Harness::new(false);
    h.scan();
    idle_receipt(&h);
    h.packet.model.lock().wait = true;
    let mut scan = Box::pin(h.device.scan(request(&[1, 6, 11], true)));
    for _ in 0..64 {
        if scan
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("EE held multi-channel scan unexpectedly completed");
        }
        if h.closed() {
            break;
        }
    }
    drop(scan);
    if !h.closed() || h.device.scan_information_elements(PEER).is_some() {
        return TestResult::Fail(
            "EE cancelled multi-channel scan exposed partial display metadata",
        );
    }
    h.packet.model.lock().wait = false;
    for _ in 0..20000 {
        h.device
            .poll_transition(&mut Context::from_waker(Waker::noop()));
        if h.passive() {
            break;
        }
    }
    if !h.passive() {
        return TestResult::Fail("EE cancelled multi-channel scan lost retained retune");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_multichannel_cancel_keeps_owned_transition_and_no_partial_cache
);
