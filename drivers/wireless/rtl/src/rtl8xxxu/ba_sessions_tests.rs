//! Gen2 host Block Ack session regressions. Expectations follow mac80211
//! `agg-rx.c`/`agg-tx.c` as rtl8xxxu `rtl8xxxu_ampdu_action` sees them;
//! nothing here is a hardware receipt.

use alloc::{vec, vec::Vec};

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{Sessions, Work};

fn addba_request(token: u8, p: u16, timeout: u16, ssn: u16) -> Vec<u8> {
    let mut body = vec![3, 0, token];
    body.extend_from_slice(&p.to_le_bytes());
    body.extend_from_slice(&timeout.to_le_bytes());
    body.extend_from_slice(&(ssn << 4).to_le_bytes());
    body
}

/// Recipient: `__ieee80211_start_rx_ba_session` statuses, window 0 → 64,
/// immediate policy with A-MSDU clear, reordering, DELBA purge, timeout.
fn smoke_rtl8xxxu_gen2_ba_recipient() -> TestResult {
    let mut ba = Sessions::<u16>::default();
    // TID 2, immediate, window 0 (=> 64), timeout 0, SSN 100.
    let Some(response) = ba.action(&addba_request(7, 2 | 2 << 2, 0, 100), 0) else {
        return TestResult::Fail("ADDBA response");
    };
    let params = 2u16 | 2 << 2 | 64 << 6;
    let mut expect = vec![3, 1, 7, 0, 0];
    expect.extend_from_slice(&params.to_le_bytes());
    expect.extend_from_slice(&[0, 0]);
    if response != expect || ba.rx_tids() != 1 << 2 {
        return TestResult::Fail("accepted response body");
    }
    // Delayed policy => 38; TSPEC TID => 37; oversized window => 38.
    let status = |r: Option<Vec<u8>>| r.map(|b| u16::from_le_bytes([b[3], b[4]]));
    if status(ba.action(&addba_request(8, 3 << 2, 0, 0), 0)) != Some(38)
        || status(ba.action(&addba_request(9, 2 | 9 << 2, 0, 0), 0)) != Some(37)
        || status(ba.action(&addba_request(10, 2 | 3 << 2 | 65 << 6, 0, 0), 0)) != Some(38)
    {
        return TestResult::Fail("refusal statuses");
    }
    // Same token with a changed timeout is declined; the session stays.
    if status(ba.action(&addba_request(7, 2 | 2 << 2, 5, 100), 0)) != Some(37)
        || ba.rx_tids() != 1 << 2
    {
        return TestResult::Fail("same-token update");
    }
    // Out-of-order 101 is held; 100 releases both in order.
    if ba.reorder(2, 101, 1, 101) != Ok(vec![]) || ba.reorder(2, 100, 1, 100) != Ok(vec![100, 101])
    {
        return TestResult::Fail("reorder release");
    }
    if ba.reorder(3, 0, 1, 7) != Err(7) {
        return TestResult::Fail("no session passes through");
    }
    // A held hole releases after the 100 ms reorder timeout.
    let _ = ba.reorder(2, 103, 10, 103);
    let (released, delba) = ba.service(200);
    if released != vec![103] || !delba.is_empty() {
        return TestResult::Fail("reorder timeout release");
    }
    // Initiator DELBA purges the recipient session.
    if ba.action(&[3, 2, 0, 2 << 4 | 1 << 3, 1, 0], 0).is_some() || ba.rx_tids() != 0 {
        return TestResult::Fail("originator DELBA");
    }
    // A nonzero timeout without traffic ends with a QSTA_TIMEOUT DELBA.
    let _ = ba.action(&addba_request(11, 2 | 1 << 2, 100, 0), 1000);
    let (_, delba) = ba.service(1000 + 103);
    if delba != vec![vec![3, 2, 0, 1 << 4, 39, 0]] || ba.rx_tids() != 0 {
        return TestResult::Fail("recipient inactivity DELBA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_ba_recipient
);

/// Originator: TX_START work, ADDBA Request body, operational on success,
/// TX_STOP work and initiator DELBA on response timeout, retry gating.
fn smoke_rtl8xxxu_gen2_ba_originator() -> TestResult {
    let mut ba = Sessions::<u16>::default();
    ba.note_tx(5, 0);
    if ba.work() != Some(Work::Start(5)) || ba.operational() != 0 {
        return TestResult::Fail("TX_START pending");
    }
    let Some(request) = ba.requested(5, 42, 0) else {
        return TestResult::Fail("ADDBA request");
    };
    let mut expect = vec![3, 0, 1];
    expect.extend_from_slice(&(2u16 | 5 << 2 | 64 << 6).to_le_bytes());
    expect.extend_from_slice(&[0, 0]);
    expect.extend_from_slice(&(42u16 << 4).to_le_bytes());
    if request != expect || ba.work().is_some() || !ba.tx_started() {
        return TestResult::Fail("ADDBA request body");
    }
    // A response with another token is ignored; the matching one succeeds.
    let response = |token: u8, status: u16| {
        let mut b = vec![3, 1, token];
        b.extend_from_slice(&status.to_le_bytes());
        b.extend_from_slice(&(2u16 | 5 << 2 | 32 << 6).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b
    };
    let _ = ba.action(&response(9, 0), 10);
    if ba.operational() != 0 {
        return TestResult::Fail("foreign token");
    }
    let _ = ba.action(&response(1, 0), 10);
    if ba.operational() != 1 << 5 {
        return TestResult::Fail("operational TID");
    }
    // Recipient DELBA (initiator bit clear) stops without our own DELBA.
    let _ = ba.action(&[3, 2, 0, 5 << 4, 37, 0], 20);
    if ba.work() != Some(Work::Stop(5)) || ba.operational() != 0 || ba.stopped(5).is_some() {
        return TestResult::Fail("peer stop");
    }
    // No response within ADDBA_RESP_INTERVAL: local stop with DELBA.
    ba.note_tx(1, 100);
    let _ = ba.requested(1, 0, 100);
    let _ = ba.service(1100);
    if ba.work() != Some(Work::Stop(1)) {
        return TestResult::Fail("response timeout");
    }
    let mut delba = vec![3, 2];
    delba.extend_from_slice(&(1u16 << 12 | 1 << 11).to_le_bytes());
    delba.extend_from_slice(&37u16.to_le_bytes());
    if ba.stopped(1) != Some(delba) {
        return TestResult::Fail("initiator DELBA");
    }
    // HT_AGG_BURST_RETRIES within the retry period gates new requests.
    for _ in 0..3 {
        ba.note_tx(1, 2000);
        let _ = ba.requested(1, 0, 2000);
        let _ = ba.service(3000);
        let _ = ba.stopped(1);
    }
    ba.note_tx(1, 3000);
    if ba.work().is_some() {
        return TestResult::Fail("burst retry gate");
    }
    ba.retire();
    if ba.tx_started() || ba.rx_tids() != 0 {
        return TestResult::Fail("retire");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_ba_originator
);

/// BlockAckReq (gen2 F9): a session releases buffered MPDUs up to the
/// BAR SSN and refreshes its inactivity timer; a TID without a session
/// earns exactly one recipient DELBA (`WLAN_REASON_QSTA_REQUIRE_SETUP`),
/// never one per BAR; TIDs >= 8 are ignored; `retire` resets the
/// once-per-TID DELBA bits.
fn smoke_rtl8xxxu_gen2_ba_block_ack_req() -> TestResult {
    let mut ba = Sessions::<u16>::default();
    // TID 2, immediate policy, window 64, timeout 10 TU, SSN 100.
    let Some(_) = ba.action(&addba_request(7, 2 | 2 << 2, 10, 100), 0) else {
        return TestResult::Fail("ADDBA response");
    };
    if ba.reorder(2, 101, 1, 777) != Ok(vec![]) {
        return TestResult::Fail("buffer out-of-order 101");
    }
    let (released, delba) = ba.bar(2, 102, 50);
    if released != vec![777] || !delba.is_empty() {
        return TestResult::Fail("BAR advance releases buffered 101");
    }
    // A stale BAR behind the advanced head releases nothing.
    if ba.bar(2, 101, 60) != (vec![], vec![]) {
        return TestResult::Fail("stale BAR ignored");
    }
    // Timer refresh: without it the session (last_rx 0, timeout 10 TU)
    // would purge at now 15; the BAR at 50 moved last_rx to 50.
    let (_, delba) = ba.service(15);
    if !delba.is_empty() || ba.rx_tids() != 1 << 2 {
        return TestResult::Fail("BAR refreshes inactivity timer");
    }
    let (_, delba) = ba.service(60);
    if delba.len() != 1 || delba[0][..2] != [3, 2] || ba.rx_tids() != 0 {
        return TestResult::Fail("inactivity purge after refresh");
    }
    // No session on TID 3: one DELBA, then silence for further BARs.
    let mut expect = vec![3, 2];
    expect.extend_from_slice(&(3u16 << 12).to_le_bytes());
    expect.extend_from_slice(&38u16.to_le_bytes());
    let (released, delba) = ba.bar(3, 100, 0);
    if !released.is_empty() || delba != vec![expect] {
        return TestResult::Fail("unexpected-TID DELBA once");
    }
    if ba.bar(3, 200, 0) != (vec![], vec![]) {
        return TestResult::Fail("unexpected-TID DELBA not repeated");
    }
    if ba.bar(9, 100, 0) != (vec![], vec![]) {
        return TestResult::Fail("TSPEC TID ignored");
    }
    // A session on TID 3 clears the bit: its BAR advances, no DELBA.
    let Some(_) = ba.action(&addba_request(8, 2 | 3 << 2, 0, 50), 0) else {
        return TestResult::Fail("ADDBA TID 3");
    };
    let (released, delba) = ba.bar(3, 50, 0);
    if !released.is_empty() || !delba.is_empty() {
        return TestResult::Fail("session BAR advances without DELBA");
    }
    // Retire resets the bits: a fresh unexpected BAR earns a DELBA again.
    ba.retire();
    let (released, delba) = ba.bar(3, 100, 0);
    if !released.is_empty() || delba.len() != 1 {
        return TestResult::Fail("retire resets DELBA bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_ba_block_ack_req
);
