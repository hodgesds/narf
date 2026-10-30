//! Actual nl80211 parse/authority/dispatcher plus an explicitly held
//! interface callback. Native MT76 MCU and DMA receipts have separate tests.
use super::*;
use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};

fn attr(out: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
    out.extend_from_slice(&((bytes.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(bytes);
    out.resize((out.len() + 3) & !3, 0);
}
fn request(fixture: &Fixture) -> Vec<u8> {
    let mut attrs = Vec::new();
    let index = narf_net::iface::lookup(fixture.radio.name())
        .unwrap()
        .ifindex;
    attr(&mut attrs, 3, &index.to_ne_bytes());
    attr(&mut attrs, 12, &100u32.to_ne_bytes());
    attr(&mut attrs, 13, &1u32.to_ne_bytes());
    attr(&mut attrs, 38, &2412u32.to_ne_bytes());
    attr(&mut attrs, 52, b"actual-async-ap");
    let mut head = alloc::vec![0; 36];
    head[0] = 0x80;
    head[4..10].fill(0xff);
    head[10..16].copy_from_slice(&fixture.radio.mac());
    head[16..22].copy_from_slice(&fixture.radio.mac());
    head[32..34].copy_from_slice(&100u16.to_le_bytes());
    attr(&mut attrs, 14, &head);
    let mut message = Vec::new();
    message.extend_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    message.extend_from_slice(&5u16.to_ne_bytes());
    message.extend_from_slice(&0x76ab_1234u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&[15, 1, 0, 0]);
    message.extend_from_slice(&attrs);
    message
}
fn start(fixture: &Fixture) -> Result<(), &'static str> {
    let _ = crate::nl80211::register();
    let replies = build_replies_with_endpoint(
        &request(fixture),
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&fixture.admin),
            portid: 77,
            ..RequestContext::default()
        },
        fixture.source.clone(),
    )
    .map_err(|_| "async AP native request framing")?;
    if !replies.is_empty() || fixture.radio.start_polls.load(Ordering::Acquire) != 0 {
        return Err("AP request acknowledged or polled before deferred admission");
    }
    narf_scheduler::poll_one_round();
    if fixture.radio.start_polls.load(Ordering::Acquire) == 0
        || fixture.radio.starts.load(Ordering::Acquire) != 0
        || !fixture.source.1.lock().is_empty()
    {
        return Err("AP callback did not remain pending without a native terminal ACK");
    }
    Ok(())
}
fn finish(fixture: &Fixture) {
    fixture.radio.start_ready.store(true, Ordering::Release);
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
        if fixture.radio.start_drops.load(Ordering::Acquire) != 0 {
            break;
        }
    }
}
fn check(fixture: &Fixture, errno: i32, starts: u32) -> Result<(), &'static str> {
    if fixture.radio.start_drops.load(Ordering::Acquire) != 1
        || fixture.radio.starts.load(Ordering::Acquire) != starts
    {
        return Err("AP callback ownership did not retire in the expected generation");
    }
    let messages = fixture.source.1.lock();
    if messages.len() != 1
        || messages[0][16..20] != (-errno).to_ne_bytes()
        || messages[0][8..12] != 0x76ab_1234u32.to_ne_bytes()
    {
        return Err("AP terminal result lost its original errno, sequence or exact source");
    }
    Ok(())
}

fn nl80211_ap_ack_waits_for_the_actual_async_callback() -> TestResult {
    let fixture = match fixture() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = start(&fixture) {
        return TestResult::Fail(error);
    }
    finish(&fixture);
    check(&fixture, 0, 1).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_ap_ack_waits_for_the_actual_async_callback
);

fn nl80211_ap_pending_callback_rechecks_delegated_capability() -> TestResult {
    let fixture = match fixture() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = start(&fixture) {
        return TestResult::Fail(error);
    }
    fixture.daemon.revoke();
    finish(&fixture);
    check(&fixture, 1, 0).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_ap_pending_callback_rechecks_delegated_capability
);

fn nl80211_ap_pending_callback_cannot_survive_mode_aba() -> TestResult {
    let fixture = match fixture() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = start(&fixture) {
        return TestResult::Fail(error);
    }
    fixture.radio.mode.store(2, Ordering::Release);
    fixture.radio.generation.store(2, Ordering::Release);
    fixture.radio.mode.store(3, Ordering::Release);
    fixture.radio.generation.store(3, Ordering::Release);
    finish(&fixture);
    check(&fixture, 1, 0).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_ap_pending_callback_cannot_survive_mode_aba
);

fn nl80211_ap_closed_source_cancels_its_borrowed_callback_without_success() -> TestResult {
    let fixture = match fixture() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = start(&fixture) {
        return TestResult::Fail(error);
    }
    fixture.source.0.store(false, Ordering::Release);
    finish(&fixture);
    if fixture.radio.starts.load(Ordering::Acquire) != 0
        || fixture.radio.start_drops.load(Ordering::Acquire) != 1
        || !fixture.source.1.lock().is_empty()
    {
        return TestResult::Fail(
            "closed source published AP state or retained its callback waiter",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_ap_closed_source_cancels_its_borrowed_callback_without_success
);
