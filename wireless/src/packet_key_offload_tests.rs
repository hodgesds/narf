//! Device key offload forms of `Key`: header-only transmit and the PN-only
//! check of device-decrypted receive share the software key's counters.
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
/// A device-decrypted payload: CCMP header then plaintext, MIC removed.
fn decrypted(pn: u64, id: u8, body: &[u8]) -> Vec<u8> {
    let mut out = ccmp::build_ccmp_header(pn, id).to_vec();
    out.extend_from_slice(body);
    out
}

fn smoke_station_ccmp_offload_header_only_shares_tx_pn() -> TestResult {
    let tk = [5; 16];
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let h = header(LOCAL, Some(3));
    let body = [0x42; 20];
    let Ok(first) = key.protect_header(&h, &body) else {
        return TestResult::Fail("header-only transmit refused");
    };
    if first[..8] != ccmp::build_ccmp_header(1, 0) || first[8..] != body {
        return TestResult::Fail("not CCMP header + plaintext (mac80211 GENERATE_IV)");
    }
    // The next software MPDU continues the same PN space.
    let Ok(sealed) = key.protect(&h, &body) else {
        return TestResult::Fail("software protect after offload");
    };
    if ccmp::decode_ccmp_header(sealed[..8].try_into().unwrap()) != Ok((2, 0)) {
        return TestResult::Fail("software and offload PNs diverged");
    }
    let mut group = Key::new(&[6; 16], 1, Role::Group, LOCAL, PEER, 0).unwrap();
    if group.protect_header(&h, &body) != Err(Error::Key) {
        return TestResult::Fail("receive-only GTK transmitted");
    }
    key.tx_pn = MAX_PN;
    if key.protect_header(&h, &body) != Err(Error::Exhausted) {
        return TestResult::Fail("offload PN wrapped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/offload",
    smoke_station_ccmp_offload_header_only_shares_tx_pn
);

fn smoke_station_ccmp_offload_decrypted_receive_keeps_replay() -> TestResult {
    let tk = [5; 16];
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 4).unwrap();
    let h = header(PEER, Some(6));
    let body = [0x33; 12];
    // The installed RSC still bounds the device-decrypted path.
    if key.accept_decrypted(&h, &decrypted(4, 0, &body)) != Err(Error::Crypto(CcmpError::Replay)) {
        return TestResult::Fail("RSC-equal PN accepted");
    }
    if key.accept_decrypted(&h, &decrypted(5, 0, &body)).as_deref() != Ok(&body[..]) {
        return TestResult::Fail("fresh decrypted PN refused");
    }
    if key.accept_decrypted(&h, &decrypted(5, 0, &body)) != Err(Error::Crypto(CcmpError::Replay)) {
        return TestResult::Fail("decrypted replay accepted");
    }
    // Software and device receive share one per-TID window.
    let mut sealed = ccmp::protect(&Ccm, &h, &tk, 5, 0, 6, false, &mut body.clone()).unwrap();
    if key.unprotect(&h, &mut sealed) != Err(Error::Crypto(CcmpError::Replay)) {
        return TestResult::Fail("software replay of a device-accepted PN");
    }
    if key.accept_decrypted(&h, &decrypted(9, 1, &body)) != Err(Error::Key)
        || key.receive[6].last_seen_pn != 5
    {
        return TestResult::Fail("wrong key ID committed");
    }
    let mut bad = decrypted(9, 0, &body);
    bad[3] &= !0x20;
    if key.accept_decrypted(&h, &bad) != Err(Error::Key) {
        return TestResult::Fail("ExtIV-clear header accepted");
    }
    if key.accept_decrypted(&h, &decrypted(6, 0, &body)).is_err()
        || key.receive[3].last_seen_pn != 4
    {
        return TestResult::Fail("other TID window moved");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/offload",
    smoke_station_ccmp_offload_decrypted_receive_keeps_replay
);

fn smoke_station_ccmp_offload_management_uses_management_counter() -> TestResult {
    let mut key = Key::new(&[5; 16], 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let mut h = alloc::vec![0; 24];
    h[0] = 0xc0;
    h[1] = 0x40;
    h[4..10].copy_from_slice(&LOCAL);
    h[10..16].copy_from_slice(&PEER);
    h[16..22].copy_from_slice(&PEER);
    if key
        .accept_decrypted_management(&h, &decrypted(2, 0, &[3, 0]))
        .as_deref()
        != Ok(&[3, 0][..])
    {
        return TestResult::Fail("decrypted deauthentication refused");
    }
    if key.accept_decrypted_management(&h, &decrypted(2, 0, &[3, 0]))
        != Err(Error::Crypto(CcmpError::Replay))
        || key.receive[MGMT].last_seen_pn != 2
        || key.receive[NON_QOS].last_seen_pn != 0
    {
        return TestResult::Fail("management replay or counter separation");
    }
    let mut out = h.clone();
    out[4..10].copy_from_slice(&PEER);
    out[10..16].copy_from_slice(&LOCAL);
    let Ok(wire) = key.protect_management_header(&out, &[8, 1, 9, 9]) else {
        return TestResult::Fail("header-only management transmit refused");
    };
    if wire[..8] != ccmp::build_ccmp_header(1, 0) || wire[8..] != [8, 1, 9, 9] {
        return TestResult::Fail("management GENERATE_IV form");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/offload",
    smoke_station_ccmp_offload_management_uses_management_counter
);
