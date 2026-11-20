// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact-channel signed programs over actual reset/RF/HT/RSNA/DHCP owners.
use super::super::super::super::super::super::{fallback, ht};
use super::channel_tests::{idle_receipt, peer_channel};
use super::*;
fn qualify(h: &Harness, channel: u8) {
    let base = power::calibration_for_channel(&power::factory(), channel);
    let firmware = h.firmware.identity().unwrap();
    *h.device.environment_for_test().ht_channel.lock() = Some((
        channel,
        ht::tests::artifact_on_channel(&base, firmware, channel),
        narf_capabilities::Cap::bootstrap(),
    ));
    *h.device.environment_for_test().fallback_channel.lock() = Some((
        channel,
        fallback::tests::artifact_on_channel(&base, firmware, channel),
        narf_capabilities::Cap::bootstrap(),
    ));
}
fn composition(protected: bool) -> TestResult {
    let h = Harness::new_profile(protected, true);
    for channel in [6, 11] {
        qualify(&h, channel);
        idle_receipt(&h);
        peer_channel(&h, channel);
        if complete(h.device.set_config(narf_wireless::WirelessConfig {
            channel: u32::from(channel),
            tx_power_dbm: None,
        }))
        .is_err()
            || !h.device.get_wireless_info().hw_caps.ht_supported
            || h.packet.radio.rf(0x18) & 255 != u32::from(channel)
        {
            return TestResult::Fail("EE exact-channel HT program did not admit fresh RF owner");
        }
        if !complete(h.device.scan(ScanRequest {
            ssids: vec![SSID.to_vec()],
            frequencies_mhz: vec![2407 + u32::from(channel) * 5],
            channels: vec![u32::from(channel)],
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(1),
            duration_mandatory: true,
            extra_ies: Vec::new(),
        }))
        .is_ok_and(|bss| bss.len() == 1 && bss[0].channel == u32::from(channel))
        {
            return TestResult::Fail(
                "EE HT channel scan lacked actual channel-bound probe reception",
            );
        }
        let mut request = h.request();
        request.channel = u32::from(channel);
        request.frequency_mhz = 2407 + u32::from(channel) * 5;
        if complete(h.device.associate(request)).is_err()
            || !h.device.link_up()
            || h.device.fallback_for_test() != Some(true)
        {
            return TestResult::Fail("EE noninitial HT/NEFB native association failed");
        }
        let expected = if channel == 6 {
            [0x19191919, 0x17191919]
        } else {
            [0x14141414; 2]
        };
        if [h.packet.radio.word(0xe10), h.packet.radio.word(0xe14)] != expected {
            return TestResult::Fail("EE actual HT gains reused another channel's measurements");
        }
        let plan = h.peer.lock().plan;
        if !narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .is_ok_and(|lease| plan.matches_lease(&lease))
        {
            return TestResult::Fail("EE channel-qualified HT Open/WPA2 path failed actual DHCP");
        }
        let data = h.packet.model.lock().descriptors.last().unwrap().clone();
        if word(&data, 16) & 0x500 != 0x100 {
            return TestResult::Fail("EE current fallback grant did not clear actual DATA DISFB");
        }
        complete(h.device.disassociate()).unwrap();
    }
    let cap = h
        .device
        .environment_for_test()
        .ht_channel
        .lock()
        .as_ref()
        .unwrap()
        .2;
    cap.revoke();
    h.device.drain();
    if !h.closed() || h.device.link_up() {
        return TestResult::Fail("EE revoked channel HT grant did not close native owner");
    }
    TestResult::Pass
}
fn smoke_rtl8188ee_channel_ht_open_native_dhcp_and_fallback() -> TestResult {
    composition(false)
}
fn smoke_rtl8188ee_channel_ht_wpa2_native_dhcp_and_fallback() -> TestResult {
    composition(true)
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht_channels",
    smoke_rtl8188ee_channel_ht_open_native_dhcp_and_fallback
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht_channels",
    smoke_rtl8188ee_channel_ht_wpa2_native_dhcp_and_fallback
);
