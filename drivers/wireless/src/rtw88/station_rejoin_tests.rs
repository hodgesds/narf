//! Preserved original netdev, actual native reset/firmware/keys and explicit SME.
use super::*;
use crate::rtw88::{endpoints, operating_reset, rejoin};
fn replace(old: &Harness, protected: bool) -> Harness {
    old.device.withdraw_for_rebind().unwrap();
    let retired = complete(operating_reset::retire(&old.device, &old.lifecycle)).unwrap();
    let name = old.device.rebound_name().unwrap();
    crate::rtw88::power::reset_tests::cycle(retired).unwrap();
    let fresh = Harness::build_named(protected, OWN, true, false, Some(name));
    fresh.env.nonce_seed.store(0x44, Ordering::Release);
    fresh
}
fn connect(fresh: &Harness) -> Result<(), rejoin::Error> {
    complete(rejoin::associate_fresh(
        &fresh.device,
        rejoin::Pending::new(fresh.request())?,
        || true,
    ))
}
fn smoke_rtw8822ce_safe_rejoin_preserves_original_ifindex_fresh_keys_and_dhcp() -> TestResult {
    for protected in [false, true] {
        let old = Harness::build(protected, OWN, true);
        old.join();
        let snapshot = narf_net::iface::lookup(old.device.name()).unwrap();
        let event = narf_net::iface::OpenStopEvent::observe(&snapshot).unwrap();
        let cookie = endpoints::cookie(old.device.name()).unwrap();
        let old_key = old.peer.lock().ap.pairwise_tk();
        if protected {
            complete(old.device.disassociate()).unwrap();
        }
        let fresh = replace(&old, protected);
        let rebound = narf_net::iface::lookup(fresh.device.name()).unwrap();
        if fresh.device.name() != old.device.name()
            || snapshot.ifindex != rebound.ifindex
            || !rebound.link_up
            || event.current()
            || endpoints::cookie(fresh.device.name()) == Some(cookie)
            || connect(&fresh).is_err()
        {
            return TestResult::Fail(
                "native stable netdev rejoin retained an old identity or failed",
            );
        }
        if protected && old_key == fresh.peer.lock().ap.pairwise_tk() {
            return TestResult::Fail("rejoin replayed old pairwise key");
        }
        let lease = narf_net::dhcp::dhcp_acquire(fresh.device.name(), 0).unwrap();
        if !fresh.plan.matches_lease(&lease)
            || !multi_tests::routed(&fresh, b"fresh-stable-rejoin")
            || endpoints::send(cookie, &[], TxMeta::default()).is_ok()
        {
            return TestResult::Fail("fresh native DHCP/dispatch or stale original cookie");
        }
        old.device.withdraw();
        old.device.drain();
        old.calibration.revoke();
        if !multi_tests::routed(&fresh, b"old-cleanup-cannot-close-rejoined-port") {
            return TestResult::Fail("old generation changed rejoined carrier/data");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rejoin",
    smoke_rtw8822ce_safe_rejoin_preserves_original_ifindex_fresh_keys_and_dhcp
);
fn smoke_rtw8822ce_safe_rejoin_m4_cancel_retains_original_native_terminal() -> TestResult {
    let old = Harness::build(true, OWN, true);
    old.join();
    let fresh = replace(&old, true);
    fresh.peer.lock().hold_m4 = true;
    let controls = fresh.model(|io| io.packets.controls.clone());
    let retained = fresh.model(|io| io.packets.payload_identity());
    let mut future = Box::pin(rejoin::associate_fresh(
        &fresh.device,
        rejoin::Pending::new(fresh.request()).unwrap(),
        || true,
    ));
    let mut held = false;
    for _ in 0..16384 {
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("rejoin did not reach held actual M4 CCX");
        }
        if controls.held.load(Ordering::Acquire) {
            held = true;
            break;
        }
    }
    drop(future);
    if !held || !fresh.device.closed() {
        return TestResult::Fail("cancel reopened fresh rejoin admission");
    }
    controls.release.store(true, Ordering::Release);
    fresh.pump();
    if fresh.device.link_up() || fresh.model(|io| io.packets.payload_identity()) != retained {
        return TestResult::Fail("late M4 terminal resurrected rejoin or released ambiguous DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rejoin",
    smoke_rtw8822ce_safe_rejoin_m4_cancel_retains_original_native_terminal
);
fn smoke_rtw8822ce_safe_rejoin_original_up_loss_before_native_doorbell_cannot_revive() -> TestResult
{
    let old = Harness::build(true, OWN, true);
    old.join();
    let fresh = replace(&old, true);
    if connect(&fresh).is_err() {
        return TestResult::Fail("native rejoin fixture");
    }
    let name = alloc::string::String::from(fresh.device.name());
    fresh.model(|io| {
        io.packets.after_descriptor = Some(Arc::new(move || {
            narf_net::iface::set_link_state(&name, false);
            narf_net::iface::set_link_state(&name, true);
        }))
    });
    if multi_tests::routed(&fresh, b"must-not-ring-after-original-down") {
        return TestResult::Fail("old UP observation revived at actual native doorbell");
    }
    fresh.pump();
    if fresh.device.link_up() {
        return TestResult::Fail("original UP loss left rejoin port live");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rejoin",
    smoke_rtw8822ce_safe_rejoin_original_up_loss_before_native_doorbell_cannot_revive
);
fn smoke_rtw8822ce_safe_rejoin_waits_old_ingress_and_preserves_operator_down() -> TestResult {
    let old = Harness::build(false, OWN, true);
    old.join();
    let delivery = old.device.delivery_for_test();
    narf_net::iface::set_link_state(old.device.name(), false);
    old.device.withdraw_for_rebind().unwrap();
    let mut wait = Box::pin(old.device.wait_withdrawn());
    if wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
        || old.device.rebound_name().is_some()
    {
        return TestResult::Fail("rejoin reused name during old callback");
    }
    drop(wait);
    drop(delivery);
    let retired = complete(operating_reset::retire(&old.device, &old.lifecycle)).unwrap();
    let name = old.device.rebound_name().unwrap();
    crate::rtw88::power::reset_tests::cycle(retired).unwrap();
    let fresh = Harness::build_named(false, OWN, true, false, Some(name));
    if narf_net::iface::lookup(fresh.device.name())
        .unwrap()
        .link_up
    {
        return TestResult::Fail("operator DOWN was not preserved by original name rebind");
    }
    if connect(&fresh).is_ok() || fresh.device.link_up() {
        return TestResult::Fail("rejoin enabled original operator-DOWN interface");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rejoin",
    smoke_rtw8822ce_safe_rejoin_waits_old_ingress_and_preserves_operator_down
);
