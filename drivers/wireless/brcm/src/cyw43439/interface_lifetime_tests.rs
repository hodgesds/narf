// SPDX-License-Identifier: GPL-2.0-or-later
//! Common final publication fences through actual CYW SDPCM/BDC progress.
use super::*;

fn downlink() -> Vec<u8> {
    let p = network_plan();
    udp_ipv4(
        OWN,
        AP,
        p.server_ip,
        p.lease_ip,
        12345,
        54321,
        b"cyw-native-final-boundary",
    )
}
fn no_vht() -> Result<(), &'static str> {
    for secured in [false, true] {
        let h = Harness::new_features(secured, None, None, Some((1, 0)))?;
        h.scan_and_associate(secured)?;
        let state = h.device.state.try_lock().unwrap();
        if state.station.vht_capabilities() != [None, None]
            || state.station.vht_connection()
            || h.device.get_wireless_info().hw_caps.vht_supported
            || h.device
                .phy_capabilities(2400)
                .is_none_or(|c| c.vht.is_some())
            || h.device.phy_capabilities(5000).is_some()
            || h.bus
                .firmware
                .lock()
                .mfp_commands()
                .iter()
                .any(|(_, b)| b.starts_with(b"vhtmode\0") || b.starts_with(b"txstreams\0"))
        {
            return Err("CYW43439 inherited another FullMAC family's VHT probe or capability");
        }
    }
    Ok(())
}
fn smoke_cyw_native_ht20_never_promotes_bcm_vht_capabilities() -> TestResult {
    no_vht().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht20",
    smoke_cyw_native_ht20_never_promotes_bcm_vht_capabilities
);

fn final_boundary() -> Result<(), &'static str> {
    for point in [
        ReceivePoint::AfterFrameAllocation,
        ReceivePoint::BeforeCallback,
    ] {
        let h = Harness::new_features(true, None, None, Some((1, 0)))?;
        h.scan_and_associate(true)?;
        let packet = downlink();
        h.bus.downlink(&packet);
        h.bus.downlink(&packet);
        let captured = h.device.step();
        if captured.len() != 2 {
            return Err("native SDPCM pair missing at final boundary");
        }
        let hit = Arc::new(AtomicBool::new(false));
        let once = hit.clone();
        let bus = h.bus.clone();
        *h.device.receive_hook.lock() = Some(Arc::new(move |at| {
            if at == point && !once.swap(true, Ordering::AcqRel) {
                bus.lose_link();
            }
        }));
        if h.device.deliver_received(captured)
            || !hit.load(Ordering::Acquire)
            || h.device.link_up()
            || h.received(&packet)
        {
            return Err("current native link event missed final IPC/callback fence");
        }
        *h.device.receive_hook.lock() = None;
    }
    let h = Harness::new_features(true, None, None, Some((1, 0)))?;
    h.scan_and_associate(true)?;
    let packet = downlink();
    h.bus.downlink(&packet);
    let captured = h.device.step();
    ready(h.device.disassociate())?.map_err(|_| "native SDPCM teardown")?;
    h.scan_and_associate(true)?;
    if h.device.deliver_received(captured) || h.received(&packet) {
        return Err("same-peer native CYW rejoin authorized an old receive batch");
    }
    h.bus.downlink(&packet);
    for _ in 0..4 {
        h.device.drain();
    }
    if !h.received(&packet) {
        return Err("current CYW receive epoch lost its positive native control");
    }
    Ok(())
}
fn smoke_cyw_native_final_link_receipts_and_same_peer_receive_epoch() -> TestResult {
    final_boundary().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht20",
    smoke_cyw_native_final_link_receipts_and_same_peer_receive_epoch
);
