// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual public PS preference/admin source, retained worker, native Core and
//! real WPA2/CCMP data on either side of the same retained LPS manager.
use super::*;
fn frame(h: &Harness, tag: u16) -> Vec<u8> {
    udp_ipv4(
        AP,
        OWN,
        h.plan.lease_ip,
        h.plan.server_ip,
        tag,
        9,
        b"awake LPS source",
    )
}
fn setup() -> Harness {
    NEXT_SLEEP.store(true, Ordering::Release);
    let h = Harness::profile(true, true);
    h.join().unwrap();
    h.pump();
    complete(h.device.apply_edca());
    h.pump();
    h
}
fn pn(frame: &[u8]) -> u64 {
    let p = &frame[26..34];
    u64::from_le_bytes([p[0], p[1], p[4], p[5], p[6], p[7], 0, 0])
}
fn smoke_rtw8852b_public_lps_original_up_worker_queued_data_keeps_ccmp_pn_sn() -> TestResult {
    let h = setup();
    if h.device.power_save_default() != Some(false) {
        return TestResult::Fail("actual LPS program absent from public preference");
    }
    let first = frame(&h, 45001);
    narf_net::iface::send_on(h.device.name(), &first).unwrap();
    h.pump();
    let before = h.model(|io| io.packets.transmitted.last().unwrap().clone());
    h.device.set_power_save(true).unwrap();
    h.pump();
    let before_entry_line = h.device.line().raised();
    if !complete(h.device.sleep_service(true, false)) {
        return TestResult::Fail("public worker skipped actual idle LPS receipts");
    }
    let calls = h.model(|io| io.sleep.as_ref().unwrap().1.h2c.len());
    if h.device.line().raised() <= before_entry_line {
        return TestResult::Fail("entry did not raise actual shared receipt line");
    }
    // Poll the actual production worker through its settled receipt baseline.
    // Own consumed DONE MSIs must reach its sleep wait without a NULL wake.
    for _ in 0..3 {
        let mut service = alloc::boxed::Box::pin(h.device.service_once());
        if !matches!(
            service.as_mut().poll(&mut core::task::Context::from_waker(
                core::task::Waker::noop()
            )),
            core::task::Poll::Pending
        ) {
            return TestResult::Fail("consumed entry DONE caused worker wake/enter churn");
        }
        drop(service);
        if h.model(|io| io.sleep.as_ref().unwrap().1.h2c.len()) != calls
            || h.model(|io| io.sleep.as_ref().unwrap().1.restored) != 0
        {
            return TestResult::Fail("quiet own IRQ receipts emitted redundant wake");
        }
    }
    // Repeated synchronous stack drains must not poll ordinary/BB while deep.
    h.pump();
    if h.model(|io| io.sleep.as_ref().unwrap().1.h2c.len()) != calls {
        return TestResult::Fail("synchronous drain woke sleeping Native");
    }
    // Polled mode observes the actual native RX producer without a software
    // kick/IRQ, wakes/restores, then lets the ordinary owner process it.
    let mut beacon = h.peer.lock().ap.beacon();
    beacon.extend_from_slice(&WMM);
    h.model(|io| io.packets.inject(&beacon)).unwrap();
    if complete(h.device.sleep_service(false, false)) {
        return TestResult::Fail("native RX producer did not wake polled sleeper");
    }
    h.pump();
    if !complete(h.device.sleep_service(true, false)) {
        return TestResult::Fail("ordinary RX processing did not restore idle PS eligibility");
    }
    let next = frame(&h, 45002);
    narf_net::iface::send_on(h.device.name(), &next).unwrap();
    if complete(h.device.sleep_service(false, true)) {
        return TestResult::Fail("queued DATA did not force actual wake/leave/restore");
    }
    h.pump();
    let after = h.model(|io| io.packets.transmitted.last().unwrap().clone());
    let before_sn = u16::from_le_bytes([before[22], before[23]]) >> 4;
    let after_sn = u16::from_le_bytes([after[22], after[23]]) >> 4;
    if pn(&after) != pn(&before) + 1
        || after_sn != (before_sn + 1) & 4095
        || h.peer.lock().uplink.last() != Some(&next)
        || !h.device.link_up()
    {
        return TestResult::Fail(
            "autonomous null templates consumed DATA PN/SN or lost actual association",
        );
    }
    if h.model(|io| io.sleep.as_ref().unwrap().1.restored) != 2 {
        return TestResult::Fail("actual PHY restore receipt missing before native DATA");
    }
    h.device.set_power_save(false).unwrap();
    if h.device.power_save_default() != Some(false) {
        return TestResult::Fail("public PS preference did not persist actual metadata choice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/runtime_sleep",
    smoke_rtw8852b_public_lps_original_up_worker_queued_data_keeps_ccmp_pn_sn
);
fn smoke_rtw8852b_public_lps_down_up_cannot_rebind_old_sleep_or_emit_leave() -> TestResult {
    let h = setup();
    h.device.set_power_save(true).unwrap();
    h.pump();
    if !complete(h.device.sleep_service(true, false)) {
        return TestResult::Fail("original public LPS entry failed");
    }
    let calls = h.model(|io| io.sleep.as_ref().unwrap().1.h2c.len());
    narf_net::iface::set_link_state(h.device.name(), false);
    narf_net::iface::set_link_state(h.device.name(), true);
    let _ = complete(h.device.sleep_service(false, true));
    if h.model(|io| io.sleep.as_ref().unwrap().1.h2c.len()) != calls
        || h.model(|io| io.sleep.as_ref().unwrap().1.resets) != 1
        || h.device.link_up()
    {
        return TestResult::Fail(
            "DOWN/UP revived original sleeper or emitted unauthorized NULL leave",
        );
    }
    drop(h);
    // The next registered generation inherits actual UP; no set_link_state
    // is issued for it. Only the exact current observation binds its target.
    NEXT_SLEEP.store(true, Ordering::Release);
    let first = Harness::preserved_up_function(OWN, None);
    narf_net::iface::set_link_state(first.device.name(), true);
    let old_snapshot = narf_net::iface::snapshot_all()
        .into_iter()
        .find(|entry| entry.name == first.device.name())
        .unwrap();
    let old_token = narf_net::iface::OpenStopEvent::observe(&old_snapshot)
        .unwrap()
        .native_identity()
        .unwrap();
    let name = crate::rtw89::interface::withdraw_keep_name(&first.device);
    complete(first.device.wait_withdrawn());
    if !first
        .lifecycle
        .retained
        .try_lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .retire()
    {
        return TestResult::Fail("preserved-UP old generation retained unknown DMA");
    }
    NEXT_SLEEP.store(true, Ordering::Release);
    let replacement = Harness::preserved_up_function(OWN, Some(&name));
    if !narf_net::iface::lookup(&name).is_some_and(|entry| entry.link_up)
        || old_token.current()
        || narf_net::iface::OpenStopEvent::observe(&old_snapshot).is_some()
    {
        return TestResult::Fail("rebind failed exact preserved-UP/nonreviving identity contract");
    }
    replacement.join().unwrap();
    replacement.pump();
    complete(replacement.device.apply_edca());
    replacement.pump();
    replacement.device.set_power_save(true).unwrap();
    if !complete(replacement.device.sleep_service(true, false)) {
        return TestResult::Fail(
            "preserved-UP new generation needed fabricated DOWN/UP before native LPS",
        );
    }
    drop(replacement);
    drop(first);
    for credit_wait in [false, true] {
        let h = setup();
        let controls = h.model(|io| io.packets.controls.clone());
        let line = h.device.line().clone();
        let mut deauth = vec![0xc0, 0, 0, 0];
        deauth.extend_from_slice(&OWN);
        deauth.extend_from_slice(&AP);
        deauth.extend_from_slice(&AP);
        deauth.extend_from_slice(&[0, 0, 3, 0]);
        let effect = Arc::new(move || {
            controls.incoming.lock().push_back(deauth.clone());
            line.raise();
        });
        h.model(|io| {
            let firmware = &mut io.sleep.as_mut().unwrap().1;
            if credit_wait {
                firmware.before_enter = Some(effect);
            } else {
                firmware.on_coex_off = Some(effect);
            }
        });
        h.device.set_power_save(true).unwrap();
        h.pump();
        if complete(h.device.sleep_service(true, false)) {
            return TestResult::Fail("late native loss opened deep sleep owner");
        }
        if h.model(|io| {
            io.sleep
                .as_ref()
                .unwrap()
                .1
                .h2c
                .iter()
                .any(|wire| wire.get(8..) == Some(&crate::rtw89::lps_wire::parameters(true)[..]))
        }) {
            return TestResult::Fail(
                "native deauth at OFF-DONE/credit wait escaped ENTER publication fence",
            );
        }
        h.pump();
        if !h.closed() {
            return TestResult::Fail("deferred original native loss was not retired");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/runtime_sleep",
    smoke_rtw8852b_public_lps_down_up_cannot_rebind_old_sleep_or_emit_leave
);
