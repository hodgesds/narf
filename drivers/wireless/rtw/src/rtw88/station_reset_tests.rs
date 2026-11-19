//! Real old/native stop proof, source card cycle, fresh firmware/key/DMA owner.
use super::*;
use crate::rtw88::{endpoints, power::reset_tests::cycle};
fn smoke_rtw8822ce_operating_reset_native_owner_new_keys_and_stale_dispatch() -> TestResult {
    for protected in [false, true] {
        let old = Harness::build(protected, OWN, true);
        old.join();
        if !multi_tests::routed(&old, b"before-native-reset") {
            return TestResult::Fail("old original native owner not running");
        }
        let cookie = endpoints::cookie(old.device.name()).unwrap();
        let old_key = old.peer.lock().ap.pairwise_tk();
        let original = udp_ipv4(
            OWN,
            AP,
            old.plan.server_ip,
            old.plan.lease_ip,
            9,
            7002,
            b"old-key-RX",
        );
        let old_cipher = old.peer.lock().downlink(&original).unwrap();
        let retired = match complete(crate::rtw88::operating_reset::retire(
            &old.device,
            &old.lifecycle,
        )) {
            Ok(retired) => retired,
            Err(_) => return TestResult::Fail("actual original DMA/callback retirement failed"),
        };
        if cycle(retired).is_err()
            || endpoints::send(cookie, &original, TxMeta::default()).is_ok()
            || old.lifecycle.retained.try_lock().unwrap().is_some()
        {
            return TestResult::Fail("native old DMA/callback/reset boundary not retired");
        }
        let fresh = Harness::build(protected, OWN, true);
        fresh.env.nonce_seed.store(0x44, Ordering::Release);
        if fresh.device.link_up() || endpoints::cookie(fresh.device.name()) == Some(cookie) {
            return TestResult::Fail("cold replacement inherited port/endpoint authority");
        }
        fresh.join();
        let lease = narf_net::dhcp::dhcp_acquire(fresh.device.name(), 0).unwrap();
        if !fresh.plan.matches_lease(&lease) || !multi_tests::routed(&fresh, b"after-native-reset")
        {
            return TestResult::Fail("fresh original firmware/key/DHCP composition");
        }
        let _ = fresh.received();
        if protected {
            if old_key == fresh.peer.lock().ap.pairwise_tk() {
                return TestResult::Fail("fresh entropy did not create a new pairwise key");
            }
            fresh.model(|io| io.packets.receive(&old_cipher, false, false));
            fresh.pump();
            if !fresh.received().is_empty() {
                return TestResult::Fail("old-generation CCMP reached new key");
            }
        }
        old.calibration.revoke();
        old.device.withdraw();
        old.device.drain();
        if !multi_tests::routed(&fresh, b"late-old-owner-denied") {
            return TestResult::Fail("old-generation qualification/cleanup closed fresh owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/reset",
    smoke_rtw8822ce_operating_reset_native_owner_new_keys_and_stale_dispatch
);
fn smoke_rtw8822ce_operating_reset_unproven_old_rx_dma_remains_pinned() -> TestResult {
    let old = Harness::build(true, OWN, true);
    old.join();
    let foreign = Lifecycle::<RadioIo>::new(0xc822);
    if complete(crate::rtw88::operating_reset::retire(&old.device, &foreign)).is_ok()
        || !old.device.link_up()
        || foreign.removed()
    {
        return TestResult::Fail("foreign empty lifecycle minted original native retirement");
    }
    let core = old.model(|io| {
        io.rx_dma_busy = true;
        io.packets.payload_identity()
    });
    if complete(crate::rtw88::operating_reset::retire(
        &old.device,
        &old.lifecycle,
    ))
    .is_ok()
        || core.is_none()
        || !old.lifecycle.removed()
        || old.device.link_up()
        || old.lifecycle.retained.try_lock().unwrap().is_some()
    {
        return TestResult::Fail("unproven original RXDMA reset was admitted");
    }
    // Lifecycle removed the failed owner; Native Drop retains its published
    // allocations. No card cycle or replacement constructor is called.
    if complete(crate::rtw88::operating_reset::retire(
        &old.device,
        &old.lifecycle,
    ))
    .is_ok()
    {
        return TestResult::Fail("empty slot after unproven DMA minted a second retirement token");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/reset",
    smoke_rtw8822ce_operating_reset_unproven_old_rx_dma_remains_pinned
);
