// SPDX-License-Identifier: GPL-2.0-or-later
//! Two retained firmware/radio/MLME owners through the real context send
//! trampoline and shared stack drain. MMIO/DMA/peers remain inert.
use super::*;
fn smoke_rtl8188ee_two_native_radios_route_independent_dhcp_and_survive_removal() -> TestResult {
    let a = Harness::with_routes(false, false, None, true);
    let b = Harness::with_routes(true, false, None, true);
    a.join();
    b.join();
    if a.device.name() == b.device.name()
        || a.packet.radio.word(LINUX_RX_BASE) == b.packet.radio.word(LINUX_RX_BASE)
    {
        return TestResult::Fail("EE independent radios reused a logical interface identity");
    }
    for h in [&a, &b] {
        let plan = h.peer.lock().plan;
        if !narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .is_ok_and(|lease| plan.matches_lease(&lease))
        {
            return TestResult::Fail(
                "EE one of two physical owners failed actual context-routed DHCP",
            );
        }
        if h.peer.lock().server.observations().requests != 1 {
            return TestResult::Fail("EE DHCP send callback reached another radio's peer");
        }
    }
    let bytes = udp_ipv4(
        PEER,
        a.device.mac(),
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        b"radio-a",
    );
    let before_b = b.peer.lock().uplink.len();
    if narf_net::iface::send_on(a.device.name(), &bytes).is_err() {
        return TestResult::Fail("EE context send refused first radio");
    }
    narf_net::iface::drain_pump();
    if a.peer.lock().uplink.last() != Some(&bytes) || b.peer.lock().uplink.len() != before_b {
        return TestResult::Fail("EE first-radio send published into another physical ring");
    }
    a.packet.radio.hardware_byte(0x286, 2);
    for reg in 0x5f8..=0x5fb {
        a.packet.radio.hardware_byte(reg, 0);
    }
    if !complete(a.device.remove()) || !b.device.link_up() {
        return TestResult::Fail(
            "EE removing one radio withdrew a second logical or physical owner",
        );
    }
    let bytes = udp_ipv4(
        PEER,
        b.device.mac(),
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        b"radio-b",
    );
    if narf_net::iface::send_on(a.device.name(), &bytes).is_ok()
        || narf_net::iface::send_on(b.device.name(), &bytes).is_err()
    {
        return TestResult::Fail(
            "EE retired interface remained routable or surviving radio lost its route",
        );
    }
    narf_net::iface::drain_pump();
    if b.peer.lock().uplink.last() != Some(&bytes) {
        return TestResult::Fail(
            "EE surviving radio lost actual WPA2 native data after peer removal",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/multi_radio",
    smoke_rtl8188ee_two_native_radios_route_independent_dhcp_and_survive_removal
);
