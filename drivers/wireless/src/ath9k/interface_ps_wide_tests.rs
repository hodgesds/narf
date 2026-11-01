// SPDX-License-Identifier: GPL-2.0-or-later
//! PS continuation consumes the real freshly calibrated H3 owner and retains
//! all existing optional child source/readback and cold-generation fences.
use super::*;
fn smoke_ar9285_station_ps_fresh40_both_extensions_open_wpa2_timer_buffered_data() -> TestResult {
    let _policy = policy();
    for width in [Width::FortyAbove, Width::FortyBelow] {
        for protected in [false, true] {
            let mut selected = spec(width, 3, protected);
            selected.power_save = true;
            let owner = Owner::new(selected);
            if owner.join().is_err() || network(&owner).is_err() {
                return TestResult::Fail("PS actual fresh40 native setup");
            }
            let device = owner.device();
            let model = owner.model();
            let peer = owner.peer();
            let plan = peer.lock().plan;
            let iface: &dyn WirelessNetIface = &*device;
            if iface.power_save_default() != Some(false) || iface.set_power_save(true).is_err() {
                return TestResult::Fail("H3 PS source/public setting missing");
            }
            owner.pump();
            let make_beacon = |timestamp: u64, unicast: bool| {
                let mut bytes = peer.lock().beacon();
                bytes[24..32].copy_from_slice(&timestamp.to_le_bytes());
                // Same actual shared association AID42 (octet5/bit2).
                bytes.extend_from_slice(&[5, 5, 0, 2, 4, 0, if unicast { 4 } else { 0 }]);
                bytes
            };
            model.inject(&make_beacon(102400, false), 0).unwrap();
            owner.pump();
            if !model.ps_sleeping.get() || device.channel_geometry() != Some(selected.geometry) {
                return TestResult::Fail("S source did not compose actual40 sleep/geometry");
            }
            let down = udp_ipv4(
                plan.station,
                AP,
                plan.server_ip,
                plan.lease_ip,
                7,
                4950,
                b"actual full40 PS-Poll original",
            );
            peer.lock().ps_buffered.push_back(down.clone());
            model.fire_tim();
            owner.pump();
            model.inject(&make_beacon(204800, true), 0).unwrap();
            owner.pump();
            let mut slot = device.rx_ring().lock();
            let ring = slot.as_mut().unwrap();
            let mut found = false;
            while let Ok(Some(frame)) = ring.try_recv() {
                found |= frame.payload() == down;
            }
            if !found
                || peer.lock().ps_polls.len() != 1
                || !model.ps_sleeping.get()
                || model
                    .wide
                    .borrow()
                    .as_ref()
                    .is_none_or(|actual| actual.geometry != selected.geometry)
            {
                return TestResult::Fail(
                    "full40 current-power PS-Poll/RX/GI/child source receipt mismatch",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/station-ps",
    smoke_ar9285_station_ps_fresh40_both_extensions_open_wpa2_timer_buffered_data
);
