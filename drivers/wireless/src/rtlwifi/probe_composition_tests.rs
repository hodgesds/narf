// SPDX-License-Identifier: GPL-2.0-or-later
//! Public scan -> native management descriptor -> independently observed
//! Probe Request -> real raw RX -> ordinary station scan cache.
use super::*;
fn request(ssids: Vec<Vec<u8>>) -> ScanRequest {
    ScanRequest {
        ssids,
        frequencies_mhz: vec![2412],
        channels: vec![1],
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: Some(1),
        duration_mandatory: true,
        extra_ies: Vec::new(),
    }
}
fn active(protected: bool) -> TestResult {
    let h = Harness::new(protected);
    h.device
        .environment_for_test()
        .beacon
        .store(true, Ordering::Release); // No passive injection.
    let result =
        complete(
            h.device
                .scan(request(vec![Vec::new(), SSID.to_vec(), b"other".to_vec()])),
        );
    if !result.is_ok_and(|b| b.len() == 1 && b[0].bssid == PEER && b[0].ssid == SSID)
        || h.peer.lock().probes.len() != 3
        || h.device.link_up()
    {
        return TestResult::Fail("EE active scan did not use actual probe/RX conversation");
    }
    let expected = [
        0, 0, 1, 8, 2, 4, 11, 22, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108, 3, 1, 1,
    ];
    if h.peer.lock().probes[0][24..] != expected {
        return TestResult::Fail(
            "EE native wildcard probe body differs from source legacy profile",
        );
    }
    let model = h.packet.model.lock();
    if model.descriptors.len() != 3
        || model.descriptors.iter().any(|d| {
            word(d, 0) & (1 << 24) == 0
                || word(d, 4) != 0x1200
                || word(d, 16) != 0x500
                || word(d, 20) & 0x7f != 0
        })
    {
        return TestResult::Fail("EE probe lacks real broadcast MGMT/basic1 descriptor");
    }
    TestResult::Pass
}
fn smoke_rtl8188ee_active_probe_open_native_scan() -> TestResult {
    active(false)
}
fn smoke_rtl8188ee_active_probe_wpa2_native_scan() -> TestResult {
    active(true)
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_active_probe_open_native_scan
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_active_probe_wpa2_native_scan
);

fn smoke_rtl8188ee_probe_waits_real_retirement_and_cancel_retains_dma() -> TestResult {
    let h = Harness::new(false);
    h.device
        .environment_for_test()
        .beacon
        .store(true, Ordering::Release);
    h.peer.lock().hold_probe = true;
    let mut scan = Box::pin(h.device.scan(request(vec![SSID.to_vec()])));
    if scan
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
        || h.packet.model.lock().held.is_none()
        || h.peer.lock().probes.len() != 1
    {
        return TestResult::Fail("EE active scan finished before actual probe TX receipt");
    }
    h.packet.release_held();
    if !complete(scan).is_ok_and(|b| b.len() == 1) {
        return TestResult::Fail("EE active scan did not finish after real probe receipt");
    }
    let mut scan = Box::pin(h.device.scan(request(vec![SSID.to_vec()])));
    if scan
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    {
        return TestResult::Fail("EE second held probe lost retained TX owner");
    }
    let drops = h.packet.drops.load(Ordering::Acquire);
    drop(scan);
    h.device.drain();
    if !h.closed()
        || h.packet.model.lock().master
        || h.packet.drops.load(Ordering::Acquire) != drops
        || h.packet.model.lock().held.is_none()
    {
        return TestResult::Fail("EE cancelled probe reopened station or freed unproven DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_probe_waits_real_retirement_and_cancel_retains_dma
);

fn smoke_rtl8188ee_probe_prevalidates_before_native_emission() -> TestResult {
    let h = Harness::new(false);
    for bad in [request(vec![Vec::new(); 5]), request(vec![vec![0; 33]])] {
        if complete(h.device.scan(bad)).is_ok() {
            return TestResult::Fail("EE invalid probe request admitted");
        }
    }
    if !h.packet.model.lock().observed.is_empty() || h.packet.model.lock().master {
        return TestResult::Fail("EE invalid probe request mutated native radio");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/scan",
    smoke_rtl8188ee_probe_prevalidates_before_native_emission
);
