// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual retained firmware/radio/CCMP/packet owners on the production
//! multi-function publisher, with separate original qualification caps.
use super::*;
use crate::rtw88::endpoints;
const SECOND: [u8; 6] = [2, 4, 6, 8, 10, 14];

fn routed(h: &Harness, body: &[u8]) -> bool {
    let ethernet = udp_ipv4(
        AP,
        h.plan.station,
        h.plan.lease_ip,
        h.plan.server_ip,
        7002,
        9,
        body,
    );
    let before = { h.peer.lock().uplink.len() };
    let queued = narf_net::iface::send_on(h.device.name(), &ethernet).is_ok();
    endpoints::drain();
    h.pump();
    let delivered = {
        let peer = h.peer.lock();
        peer.uplink.len() == before + 1 && peer.uplink.last() == Some(&ethernet)
    };
    queued && delivered
}
fn smoke_rtw88_multiple_native_functions_keep_qualification_keys_and_receipts_independent(
) -> TestResult {
    let first = Harness::build(true, OWN, true);
    let second = Harness::build(true, SECOND, true);
    first.join();
    second.join();
    let first_key = { first.peer.lock().ap.pairwise_tk() };
    let second_key = { second.peer.lock().ap.pairwise_tk() };
    if first_key.is_none()
        || second_key.is_none()
        || first_key == second_key
        || !routed(&first, b"first")
        || !routed(&second, b"second")
    {
        return TestResult::Fail("native multi-function keys/context dispatch differed");
    }
    first.peer.lock().hold_data = true;
    if !routed(&first, b"first-native-terminal-held")
        || !routed(&second, b"second-native-terminal-independent")
    {
        return TestResult::Fail("one function's TX terminal wait blocked another");
    }
    first.calibration.revoke();
    first.pump();
    if first.device.link_up() || !routed(&second, b"second-original-qualification-still-current") {
        return TestResult::Fail("qualification loss crossed retained function/key lifetimes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/multiple",
    smoke_rtw88_multiple_native_functions_keep_qualification_keys_and_receipts_independent
);

fn smoke_rtw88_function_removal_waits_for_old_ingress_and_cannot_alias_fresh_dispatch() -> TestResult
{
    let first = Harness::build(true, OWN, true);
    let second = Harness::build(true, SECOND, true);
    first.join();
    second.join();
    let old = endpoints::cookie(first.device.name()).unwrap();
    let second_cookie = endpoints::cookie(second.device.name()).unwrap();
    let delivery = first.device.delivery_for_test();
    first.device.withdraw();
    let mut wait = Box::pin(first.device.wait_withdrawn());
    let waiting = wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending();
    if !waiting
        || narf_net::iface::lookup(first.device.name()).is_none()
        || endpoints::cookie(first.device.name()) != Some(old)
        || !routed(&second, b"second-during-first-old-ingress")
    {
        return TestResult::Fail("old ingress lost its name or blocked another function");
    }
    drop(delivery);
    complete(wait);
    if !complete(first.lifecycle.remove()) {
        return TestResult::Fail("removed native function did not prove DMA reclamation");
    }
    let fresh = Harness::build(true, OWN, true);
    fresh.join();
    if endpoints::cookie(fresh.device.name()) == Some(old)
        || endpoints::cookie(second.device.name()) != Some(second_cookie)
        || endpoints::send(old, &[0; 14], TxMeta::plain()).is_ok()
        || !routed(&fresh, b"fresh-function")
        || !routed(&second, b"second-survived")
    {
        return TestResult::Fail("retired dispatch aliased fresh or unrelated native owner");
    }
    first.device.withdraw();
    first.device.drain();
    if !routed(&fresh, b"old-worker-cannot-close-fresh-carrier") {
        return TestResult::Fail("late old-shell cleanup changed a fresh carrier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/multiple",
    smoke_rtw88_function_removal_waits_for_old_ingress_and_cannot_alias_fresh_dispatch
);
