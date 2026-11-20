// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual BE station queue -> coexistence/LPS H2C -> native descriptor boundary.
use super::super::packet::be8723::tests::{station_fixture, BePort, Block};
use super::*;
use core::{
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Env;
impl Environment for Env {
    fn now_ms(&self) -> u64 {
        0
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        Some([0x33; 32])
    }
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
        Ok(crate::rtlwifi::rtl8723be::tests::be_us_domain())
    }
    async fn pause(&self) {
        narf_scheduler::yield_now().await;
    }
}
fn reply() -> Vec<u8> {
    // A source-classified unprotected EAPOL MPDU. Cryptographic reply/M4
    // retirement is already covered by the native shared Security tests.
    let own = crate::rtlwifi::rtl8723be::tests::be_factory().mac;
    let peer = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mut bytes = vec![8, 1, 0, 0];
    bytes.extend_from_slice(&peer);
    bytes.extend_from_slice(&own);
    bytes.extend_from_slice(&peer);
    bytes.extend_from_slice(&[0, 0, 0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 2, 3, 0, 0]);
    bytes
}
fn fixture() -> Option<(Prepared<BePort, Block>, BePort)> {
    let (mut owner, port) = station_fixture()?;
    owner.station.phase = Phase::FourWay;
    owner.station.deadline = 10_000;
    // Source rtl_lps_leave must issue a real SETPWRMODE H2C before EAPOL.
    let coex = owner.rtl8723be_coex.as_deref_mut()?;
    coex.lps.linked = true;
    coex.lps.report_linked = true;
    coex.lps.active = false;
    Some((owner, port))
}
fn complete<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    for _ in 0..1024 {
        if let Poll::Ready(value) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return value;
        }
    }
    panic!("bounded native special fixture did not complete");
}
fn smoke_be_eapol_is_parked_until_source_lps_h2c_then_native_tx() -> TestResult {
    let Some((mut owner, port)) = fixture() else {
        return TestResult::Fail("BE fixture");
    };
    let before = port.special_events().len();
    if owner
        .queue_station(reply(), Kind::Eapol, 0, false, &Env)
        .is_err()
        || owner.station.pending.is_some()
        || owner.station.deferred_eapol.is_none()
        || port.special_events().len() != before
    {
        return TestResult::Fail("synchronous EAPOL queue emitted before coexistence preflight");
    }
    if complete(owner.flush_station_eapol(&Env)).is_err()
        || owner.station.deferred_eapol.is_some()
        || owner.station.pending.is_none()
    {
        return TestResult::Fail("notified exact EAPOL did not reach native descriptor");
    }
    let events = port.special_events();
    let h2c = events[before..]
        .iter()
        .position(|event| *event == (false, 0x1d0));
    let kick = events[before..].iter().position(|event| event.0);
    if h2c.is_none()
        || kick.is_none()
        || h2c >= kick
        || !owner.rtl8723be_coex.as_ref().unwrap().btc.wifi.in_4way
    {
        return TestResult::Fail("LPS H2C did not precede native kick or in_4way was lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_be_eapol_is_parked_until_source_lps_h2c_then_native_tx
);

fn smoke_be_cancelled_special_h2c_keeps_eapol_unsubmitted_and_closes_generation() -> TestResult {
    let Some((mut owner, port)) = fixture() else {
        return TestResult::Fail("BE fixture");
    };
    owner
        .queue_station(reply(), Kind::Eapol, 0, false, &Env)
        .unwrap();
    port.stall_special();
    let before = port.special_events();
    {
        let future = owner.flush_station_eapol(&Env);
        let mut future = pin!(future);
        if !future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
        {
            return TestResult::Fail("actual source mailbox wait did not pend");
        }
    }
    if owner.station_phase() != Phase::Failed
        || owner.station.pending.is_some()
        || port.special_events()[before.len()..]
            .iter()
            .any(|event| event.0)
        || owner
            .queue_station(reply(), Kind::Eapol, 0, false, &Env)
            .is_ok()
    {
        return TestResult::Fail("cancelled coexistence wait emitted/reopened EAPOL");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_be_cancelled_special_h2c_keeps_eapol_unsubmitted_and_closes_generation
);

fn smoke_be_source_loss_during_special_wait_never_publishes_eapol() -> TestResult {
    let Some((mut owner, port)) = fixture() else {
        return TestResult::Fail("BE fixture");
    };
    owner
        .queue_station(reply(), Kind::Eapol, 0, false, &Env)
        .unwrap();
    port.stall_special();
    let before = port.special_events();
    let future = owner.flush_station_eapol(&Env);
    let mut future = pin!(future);
    if !future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
    {
        return TestResult::Fail("source H2C wait did not pend");
    }
    port.deny_special();
    if complete(future).is_ok()
        || port.special_events()[before.len()..]
            .iter()
            .any(|event| event.0)
    {
        return TestResult::Fail("revoked native source emitted a delayed EAPOL descriptor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_be_source_loss_during_special_wait_never_publishes_eapol
);
