// SPDX-License-Identifier: GPL-2.0-or-later
//! Bus power prepares through the real retained Device before its actual
//! packet/MLME/RSNA/DHCP path. Only PCI config/MMIO/DMA/peer are inert.
use super::super::super::super::super::super::interface::supervisor::Operation;
use super::*;
fn composition(protected: bool) -> TestResult {
    let h = Harness::new(protected);
    let bus = Arc::new(aspm::tests::Model::new());
    *h.device.environment_for_test().bus_power.lock() = Some(bus.clone());
    if h.packet.model.lock().master || bus.control.load(Ordering::Acquire) != 0x43 {
        return TestResult::Fail(
            "EE pre-admission fixture started packet DMA or changed host config",
        );
    }
    h.join();
    if bus.control.load(Ordering::Acquire) != 0x143 || !h.device.link_up() {
        return TestResult::Fail(
            "EE native bus preparation did not precede live station admission",
        );
    }
    let plan = h.peer.lock().plan;
    if !narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
        .is_ok_and(|lease| plan.matches_lease(&lease))
    {
        return TestResult::Fail("EE ASPM-prepared Open/WPA2 owner failed actual DHCP");
    }
    complete(h.device.disassociate()).unwrap();
    super::channel_tests::idle_receipt(&h);
    h.device.fail_for_test();
    complete(h.device.schedule(Operation::Recover).unwrap()).unwrap();
    // Actual parent policy loss precedes a fresh station preparation.
    bus.parent.store(0x40, Ordering::Release);
    super::channel_tests::idle_receipt(&h);
    h.device.fail_for_test();
    complete(h.device.schedule(Operation::Recover).unwrap()).unwrap();
    if bus.control.load(Ordering::Acquire) != 0x40 || !h.passive() || h.device.link_up() {
        return TestResult::Fail(
            "EE fresh owner ignored withdrawn parent policy or restored old carrier",
        );
    }
    TestResult::Pass
}
fn smoke_rtl8188ee_aspm_open_native_dhcp_and_fresh_parent_policy() -> TestResult {
    composition(false)
}
fn smoke_rtl8188ee_aspm_wpa2_native_dhcp_and_fresh_parent_policy() -> TestResult {
    composition(true)
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_rtl8188ee_aspm_open_native_dhcp_and_fresh_parent_policy
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_rtl8188ee_aspm_wpa2_native_dhcp_and_fresh_parent_policy
);
