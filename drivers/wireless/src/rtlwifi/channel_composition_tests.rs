// SPDX-License-Identifier: GPL-2.0-or-later
//! Public configuration with real reset, NEPC, RF18, packet, MLME and DHCP.
//! Inert envelopes are never installed in the physical firmware registry.
use super::*;
use narf_wireless::WirelessConfig;
fn config(channel: u8) -> WirelessConfig {
    WirelessConfig {
        channel: u32::from(channel),
        tx_power_dbm: None,
    }
}
fn idle_receipt(h: &Harness) {
    h.packet.radio.hardware_byte(0x286, 2);
    for reg in 0x5f8..=0x5fb {
        h.packet.radio.hardware_byte(reg, 0);
    }
}
fn peer_channel(h: &Harness, channel: u8) {
    let mut peer = h.peer.lock();
    let protected = peer.ap.protected();
    peer.ap = if protected {
        FakeAp::wpa2(peer.plan, SSID, channel, 42, PMK, ANONCE)
    } else {
        FakeAp::open(peer.plan, SSID, channel, 42)
    }
    .unwrap()
    .with_basic_1mbps()
    .unwrap();
    peer.ptk = None;
    peer.replay.last_seen_pn = 0;
    peer.pn = 1;
}
fn scan(
    h: &Harness,
    channel: u8,
) -> Result<Vec<narf_wireless::BssInfo>, narf_wireless::WirelessError> {
    complete(h.device.scan(ScanRequest {
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
}
fn channel_dhcp(protected: bool) -> TestResult {
    let h = Harness::new(protected);
    for channel in [6, 11, 1] {
        idle_receipt(&h);
        peer_channel(&h, channel);
        let old_ring = h.packet.radio.word(LINUX_RX_BASE);
        if complete(h.device.set_config(config(channel))).is_err()
            || !h.passive()
            || h.device.channel_for_test() != channel
            || h.packet.radio.rf(0x18) & 0xfff != 0xc00 | u32::from(channel)
            || h.packet.radio.word(LINUX_RX_BASE) == old_ring
            || ((h.packet.radio.word(0xe08) >> 8) & 255) != u32::from(31 - channel)
        {
            return TestResult::Fail("EE retune missed current RF18/gain/fresh DMA owner");
        }
        if !scan(&h, channel).is_ok_and(|b| {
            b.len() == 1
                && b[0].channel == u32::from(channel)
                && b[0].frequency_mhz == 2407 + u32::from(channel) * 5
        }) {
            return TestResult::Fail(
                "EE retuned active probe/BSS identity differs from actual channel",
            );
        }
        let mut request = h.request();
        request.channel = u32::from(channel);
        request.frequency_mhz = 2407 + u32::from(channel) * 5;
        if complete(h.device.associate(request)).is_err() || !h.device.link_up() {
            return TestResult::Fail("EE retuned fresh native association failed");
        }
        let plan = h.peer.lock().plan;
        if !narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .is_ok_and(|lease| plan.matches_lease(&lease))
        {
            return TestResult::Fail("EE actual DHCP failed on noninitial qualified channel");
        }
        if complete(
            h.device
                .set_config(config(if channel == 6 { 11 } else { 6 })),
        )
        .is_ok()
        {
            return TestResult::Fail(
                "EE channel change moved an associated station without disconnect",
            );
        }
        complete(h.device.disassociate()).unwrap();
    }
    TestResult::Pass
}
fn smoke_rtl8188ee_channel_retune_open_native_dhcp() -> TestResult {
    channel_dhcp(false)
}
fn smoke_rtl8188ee_channel_retune_wpa2_native_dhcp() -> TestResult {
    channel_dhcp(true)
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/channel",
    smoke_rtl8188ee_channel_retune_open_native_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/channel",
    smoke_rtl8188ee_channel_retune_wpa2_native_dhcp
);

fn smoke_rtl8188ee_retune_prevalidates_policy_and_retains_unproven_dma() -> TestResult {
    let h = Harness::new(false);
    h.scan();
    let generation = h.device.generation_for_test();
    let accesses = h.packet.radio.accesses();
    h.env.power.store(-128, Ordering::Release);
    if complete(h.device.set_config(config(6))).is_ok()
        || complete(h.device.set_config(config(12))).is_ok()
        || h.packet.radio.accesses() != accesses
        || h.device.generation_for_test() != generation
    {
        return TestResult::Fail("EE denied retune changed native radio before permission");
    }
    h.env.power.store(17, Ordering::Release);
    let drops = h.packet.drops.load(Ordering::Acquire);
    h.packet.radio.hardware_byte(0x286, 0);
    if complete(h.device.set_config(config(6))).is_ok()
        || !h.closed()
        || h.packet.drops.load(Ordering::Acquire) != drops
    {
        return TestResult::Fail("EE retune discarded DMA without actual old-owner idle");
    }
    idle_receipt(&h);
    if complete(h.device.set_config(config(6))).is_err() || !h.passive() {
        return TestResult::Fail("EE retune failed after actual idle receipt became available");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/channel",
    smoke_rtl8188ee_retune_prevalidates_policy_and_retains_unproven_dma
);

fn smoke_rtl8188ee_retune_waiter_drop_and_qualified_channel_ips_resume() -> TestResult {
    use super::super::super::super::super::super::interface::supervisor::Operation;
    let h = Harness::new(false);
    h.scan();
    idle_receipt(&h);
    peer_channel(&h, 6);
    h.packet.model.lock().wait = true;
    let mut set = Box::pin(h.device.set_config(config(6)));
    if set
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    {
        return TestResult::Fail("EE retune did not retain actual held native transition");
    }
    drop(set);
    h.packet.model.lock().wait = false;
    for _ in 0..20000 {
        h.device
            .poll_transition(&mut Context::from_waker(Waker::noop()));
        if h.passive() {
            break;
        }
    }
    if !h.passive() || h.device.channel_for_test() != 6 {
        return TestResult::Fail("EE dropped retune lost fresh passive owner");
    }
    idle_receipt(&h);
    complete(h.device.schedule(Operation::Idle).unwrap()).unwrap();
    if !scan(&h, 6).is_ok_and(|b| b.len() == 1) || h.packet.radio.rf(0x18) & 0xfff != 0xc06 {
        return TestResult::Fail("EE IPS wake lost desired channel/current NEPC envelope");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/channel",
    smoke_rtl8188ee_retune_waiter_drop_and_qualified_channel_ips_resume
);
