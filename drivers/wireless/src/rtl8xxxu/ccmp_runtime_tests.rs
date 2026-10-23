use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn header(sender: [u8; 6], tid: Option<u8>) -> Vec<u8> {
    let mut h = alloc::vec![0; if tid.is_some() { 26 } else { 24 }];
    h[0] = if tid.is_some() { 0x88 } else { 8 };
    h[1] = if sender == LOCAL { 0x41 } else { 0x42 };
    h[4..10].copy_from_slice(&if sender == LOCAL { PEER } else { LOCAL });
    h[10..16].copy_from_slice(&sender);
    h[16..22].copy_from_slice(&PEER);
    if let Some(tid) = tid {
        h[24] = tid;
    }
    h
}
fn wire(key: &[u8; 16], h: &[u8], pn: u64, id: u8) -> Vec<u8> {
    let mut body = [0x42; 31];
    ccmp::protect(
        &Ccm,
        h,
        key,
        pn,
        id,
        shape(h).unwrap().priority,
        false,
        &mut body,
    )
}
fn smoke_rtl_ccmp_forgery_cannot_poison_key_tid() -> TestResult {
    let h = header(PEER, Some(7));
    let tk = [5; 16];
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 3).unwrap();
    let mut forged = wire(&tk, &h, MAX_PN, 0);
    *forged.last_mut().unwrap() ^= 1;
    let saved = forged.clone();
    if key.unprotect(&h, &mut forged) != Err(Error::Crypto(CcmpError::AuthFailed))
        || forged != saved
        || key.receive[7].last_seen_pn != 3
    {
        return TestResult::Fail("bad MIC changed ciphertext or key/TID replay state");
    }
    let mut valid = wire(&tk, &h, 4, 0);
    if key.unprotect(&h, &mut valid) != Ok(alloc::vec![0x42; 31])
        || key.receive[7].last_seen_pn != 4
    {
        return TestResult::Fail("forged high PN blocked authentic frame");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ccmp",
    smoke_rtl_ccmp_forgery_cannot_poison_key_tid
);
fn smoke_rtl_ccmp_replay_is_per_key_and_tid() -> TestResult {
    let tk = [5; 16];
    let gtk = [6; 16];
    let mut pair = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let mut group = Key::new(&gtk, 2, Role::Group, LOCAL, PEER, 0).unwrap();
    for tid in [Some(0), Some(1), Some(15), None] {
        let h = header(PEER, tid);
        let original = wire(&tk, &h, 1, 0);
        let mut frame = original.clone();
        if pair.unprotect(&h, &mut frame).is_err() {
            return TestResult::Fail("different TID/non-QoS PN rejected");
        }
        let mut duplicate = original.clone();
        if pair.unprotect(&h, &mut duplicate) != Err(Error::Crypto(CcmpError::Replay))
            || duplicate != original
        {
            return TestResult::Fail("same key/TID duplicate changed ciphertext or passed");
        }
        let mut h = h;
        h[4..10].fill(0xff);
        let original = wire(&gtk, &h, 1, 2);
        let mut frame = original.clone();
        if pair.unprotect(&h, &mut frame) != Err(Error::Key) || frame != original {
            return TestResult::Fail("wrong key ID reached pairwise replay");
        }
        if group.unprotect(&h, &mut frame).is_err() {
            return TestResult::Fail("separate GTK/TID replay state");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ccmp",
    smoke_rtl_ccmp_replay_is_per_key_and_tid
);
fn smoke_rtl_ccmp_tx_pn_exhaustion_and_failed_admission() -> TestResult {
    let tk = [8; 16];
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let h = header(LOCAL, None);
    key.tx_pn = MAX_PN - 1;
    let last = key.protect(&h, &[1, 2, 3]).unwrap();
    if ccmp::decode_ccmp_header(last[..8].try_into().unwrap()) != Ok((MAX_PN, 0))
        || key.protect(&h, &[1, 2, 3]) != Err(Error::Exhausted)
        || key.tx_pn != MAX_PN
    {
        return TestResult::Fail("48-bit TX PN wrapped or last PN malformed");
    }
    let mut fresh = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let mut invalid = h.clone();
    invalid[1] &= !0x40;
    if fresh.protect(&invalid, &[1]) != Err(Error::Header)
        || fresh.protect(&h, &alloc::vec![0; MAX_BODY + 1]) != Err(Error::Length)
        || fresh.tx_pn != 0
    {
        return TestResult::Fail("invalid header/length consumed PN or reached encryption");
    }
    let first = fresh.protect(&h, &[1]).unwrap(); // Drop before USB submission.
    let second = fresh.protect(&h, &[1]).unwrap();
    if first[..8] == second[..8] || fresh.tx_pn != 2 {
        return TestResult::Fail("failed/dropped TX can reuse PN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ccmp",
    smoke_rtl_ccmp_tx_pn_exhaustion_and_failed_admission
);
fn smoke_rtl_ccmp_reinstall_preserves_live_counters() -> TestResult {
    let tk = [9; 16];
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let outgoing = header(LOCAL, Some(3));
    key.protect(&outgoing, &[1]).unwrap();
    let incoming = header(PEER, Some(3));
    let mut frame = wire(&tk, &incoming, 10, 0);
    key.unprotect(&incoming, &mut frame).unwrap();
    if key.reinstall(&tk, 0) != Ok(false) || key.tx_pn != 1 || key.receive[3].last_seen_pn != 10 {
        return TestResult::Fail("identical-key retransmission reset PN/replay");
    }
    let changed = [10; 16];
    if key.reinstall(&changed, 4) != Ok(true)
        || key.tx_pn != 0
        || key.receive.iter().any(|r| r.last_seen_pn != 4)
    {
        return TestResult::Fail("changed-key RSC initialization");
    }
    let mut old = wire(&tk, &incoming, 11, 0);
    let saved = old.clone();
    if key.unprotect(&incoming, &mut old) != Err(Error::Crypto(CcmpError::AuthFailed))
        || old != saved
        || key.receive[3].last_seen_pn != 4
    {
        return TestResult::Fail("old-key frame modified new-key state");
    }
    let mut valid = wire(&changed, &incoming, 5, 0);
    if key.unprotect(&incoming, &mut valid).is_err() {
        return TestResult::Fail("new-key frame above RSC rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ccmp",
    smoke_rtl_ccmp_reinstall_preserves_live_counters
);
fn smoke_rtl_ccmp_strict_header_and_key_admission() -> TestResult {
    let tk = [11; 16];
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let h = header(PEER, Some(2));
    let good = wire(&tk, &h, 1, 0);
    let mut bad_headers = alloc::vec![h[..23].to_vec(), h[..25].to_vec()];
    for (offset, mask) in [
        (0, 1),
        (0, 4),
        (1, 0x40),
        (1, 4),
        (22, 1),
        (24, 0x80),
        (10, 2),
    ] {
        let mut bad = h.clone();
        bad[offset] ^= mask;
        bad_headers.push(bad);
    }
    for bad in bad_headers {
        let mut candidate = good.clone();
        if key.unprotect(&bad, &mut candidate).is_ok() || candidate != good {
            return TestResult::Fail("malformed/fragment/A-MSDU/peer header mutated wire");
        }
    }
    for (offset, mask) in [(2, 1), (3, 1), (3, 0x20), (3, 0x40)] {
        let mut bad = good.clone();
        bad[offset] ^= mask;
        let saved = bad.clone();
        if key.unprotect(&h, &mut bad) != Err(Error::Key) || bad != saved {
            return TestResult::Fail("reserved CCMP/ExtIV/key ID reached crypto");
        }
    }
    let mut oversized = alloc::vec![0;MAX_BODY+17];
    if key.unprotect(&h, &mut oversized) != Err(Error::Length) || key.receive[2].last_seen_pn != 0 {
        return TestResult::Fail("oversized CCMP admitted or bad input changed replay");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ccmp",
    smoke_rtl_ccmp_strict_header_and_key_admission
);

fn smoke_rtl_ccmp_station_role_and_address_admission() -> TestResult {
    let tk = [12; 16];
    for id in 1..=3 {
        if !matches!(
            Key::new(&tk, id, Role::Pairwise, LOCAL, PEER, 0),
            Err(Error::Key)
        ) {
            return TestResult::Fail("unnegotiated Extended Key ID admitted");
        }
    }
    let mut pair = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let mut gtk_zero = Key::new(&tk, 0, Role::Group, LOCAL, PEER, 0).unwrap();
    let tx = header(LOCAL, None);
    if gtk_zero.protect(&tx, &[1]) != Err(Error::Key) || gtk_zero.tx_pn != 0 {
        return TestResult::Fail("GTK KeyID0 granted pairwise transmit ownership");
    }
    for (offset, mask) in [(0, 0x10), (0, 0x40), (1, 1), (1, 2), (4, 2), (10, 2)] {
        let mut bad = tx.clone();
        bad[offset] ^= mask;
        if pair.protect(&bad, &[1]).is_ok() || pair.tx_pn != 0 {
            return TestResult::Fail("TX wrong subtype/direction/RA/TA admitted");
        }
    }
    let rx = header(PEER, None);
    let authentic = wire(&tk, &rx, 1, 0);
    for (offset, mask) in [
        (0, 0x10),
        (0, 0x40),
        (1, 1),
        (1, 2),
        (4, 2),
        (10, 2),
        (16, 1),
    ] {
        let mut bad = rx.clone();
        bad[offset] ^= mask;
        let mut frame = authentic.clone();
        if pair.unprotect(&bad, &mut frame).is_ok()
            || frame != authentic
            || pair.receive[NON_QOS].last_seen_pn != 0
        {
            return TestResult::Fail("RX wrong subtype/direction/RA/TA/SA admitted");
        }
    }
    let mut frame = authentic.clone();
    if gtk_zero.unprotect(&rx, &mut frame) != Err(Error::Key) || frame != authentic {
        return TestResult::Fail("GTK admitted unicast receiver");
    }
    let mut multicast = rx.clone();
    multicast[4..10].fill(0xff);
    let mut frame = wire(&tk, &multicast, 1, 0);
    if pair.unprotect(&multicast, &mut frame) != Err(Error::Key) {
        return TestResult::Fail("PTK admitted multicast receiver");
    }
    if gtk_zero.unprotect(&multicast, &mut frame).is_err() {
        return TestResult::Fail("valid GTK0 multicast rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ccmp",
    smoke_rtl_ccmp_station_role_and_address_admission
);
