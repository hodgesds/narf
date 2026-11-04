//! Actual AES-CCM ownership regressions. Native RX/TX composition is separate.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0x76, 0x20];
const PEER: [u8; 6] = [2, 0, 0, 0, 0x76, 0x21];
fn header(from_ap: bool, tid: Option<u8>) -> Vec<u8> {
    let mut h = vec![0; if tid.is_some() { 26 } else { 24 }];
    h[0] = if tid.is_some() { 0x88 } else { 0x08 };
    h[1] = 0x40 | if from_ap { 2 } else { 1 };
    h[4..10].copy_from_slice(&if from_ap { PEER } else { OWN });
    h[10..16].copy_from_slice(&if from_ap { OWN } else { PEER });
    h[16..22].copy_from_slice(&[2, 0, 0, 0, 0x76, 0x30]);
    if let Some(tid) = tid {
        h[24] = tid;
    }
    h
}
fn sealed(tk: &[u8; 16], h: &[u8], pn: u64, body: &[u8]) -> Vec<u8> {
    ccmp::protect(
        &Ccm,
        h,
        tk,
        pn,
        0,
        if h.len() == 26 { h[24] & 15 } else { 0 },
        false,
        &mut body.to_vec(),
    )
    .unwrap()
}
fn counters() -> Result<(), &'static str> {
    let mut keys = Keys::default();
    let tk = [0x55; 16];
    let target = Target::Pairwise(PEER);
    if keys.install(target, &tk, 0) != Ok(true) {
        return Err("AP new actual CCMP key");
    }
    for tid in (0..16).map(Some).chain(core::iter::once(None)) {
        let h = header(false, tid);
        let wire = sealed(&tk, &h, 1, b"native ciphertext");
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        if keys.unprotect(OWN, PEER, &h, &bad) != Err(Error::Authentication)
            || keys.unprotect(OWN, PEER, &h, &wire) != Ok(b"native ciphertext".to_vec())
            || keys.unprotect(OWN, PEER, &h, &wire) != Err(Error::Replay)
        {
            return Err("AP MIC/replay ownership failed or one TID suppressed another");
        }
    }
    let h = header(true, None);
    let first = keys
        .protect(OWN, target, &h, b"native TX")
        .map_err(|_| "AP CCMP native TX")?;
    if keys.install(target, &tk, 0) != Ok(false) {
        return Err("AP identical key install replaced counter owner");
    }
    let second = keys
        .protect(OWN, target, &h, b"native TX")
        .map_err(|_| "AP CCMP native TX retry")?;
    if ccmp::decode_ccmp_header(first[..8].try_into().unwrap())
        .unwrap()
        .0
        != 1
        || ccmp::decode_ccmp_header(second[..8].try_into().unwrap())
            .unwrap()
            .0
            != 2
    {
        return Err("AP reinstall reused native TX nonce");
    }
    keys.remove(target).map_err(|_| "AP key removal")?;
    if keys.install(target, &tk, 0) != Err(Error::Key)
        || keys.install(Target::Group(1), &tk, 0) != Err(Error::Key)
    {
        return Err("AP retired/cross-role material returned with reset PN");
    }
    keys.install(target, &[0x56; 16], 0)
        .map_err(|_| "AP replacement fresh key")?;
    let h = header(false, None);
    let old = sealed(&tk, &h, 90, b"late old native packet");
    if keys.unprotect(OWN, PEER, &h, &old) != Err(Error::Authentication) {
        return Err("AP late old-key ciphertext became current plaintext");
    }
    let fresh = sealed(&[0x56; 16], &h, 1, b"fresh native packet");
    if keys.unprotect(OWN, PEER, &h, &fresh) != Ok(b"fresh native packet".to_vec()) {
        return Err("AP old-key forged PN poisoned fresh key");
    }
    keys.clear_active();
    if keys.install(target, &[0x56; 16], 0) != Err(Error::Key) {
        return Err("AP role reset erased retired key evidence");
    }
    Ok(())
}
fn mt76_ap_software_ccmp_all_tids_reinstall_retirement_and_real_mic() -> TestResult {
    counters().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_software_ccmp_all_tids_reinstall_retirement_and_real_mic
);
fn bindings() -> Result<(), &'static str> {
    let mut keys = Keys::default();
    keys.install(Target::Pairwise(PEER), &[0x31; 16], 0)
        .unwrap();
    let h = header(false, Some(15));
    let wire = sealed(&[0x31; 16], &h, 1, b"bound");
    for index in [1, 4, 10, 16, 22, 24] {
        let mut bad = h.clone();
        bad[index] ^= 1;
        if keys.unprotect(OWN, PEER, &bad, &wire).is_ok() {
            return Err("AP CCMP accepted wrong DS/address/fragment/TID");
        }
    }
    if keys.unprotect(OWN, PEER, &h, &wire) != Ok(b"bound".to_vec()) {
        return Err("AP foreign header changed replay owner");
    }
    let mut group = header(true, None);
    group[4..10].fill(0xff);
    keys.install(Target::Group(2), &[0x32; 16], 0).unwrap();
    let protected = keys
        .protect(OWN, Target::Group(2), &group, b"group payload")
        .map_err(|_| "AP group TX CCMP")?;
    if ccmp::decode_ccmp_header(protected[..8].try_into().unwrap()).unwrap() != (1, 2) {
        return Err("AP group TX selected pairwise key ID or PN owner");
    }
    let mut replay = ReplayWindow { last_seen_pn: 0 };
    let mut protected = protected;
    if ccmp::unprotect(
        &Ccm,
        &group,
        &[0x32; 16],
        0,
        false,
        &mut replay,
        &mut protected,
    ) != Ok(b"group payload".to_vec())
    {
        return Err("AP group TX did not use actual AES-CCM");
    }
    Ok(())
}
fn mt76_ap_software_ccmp_exact_addresses_direction_and_group_tx() -> TestResult {
    bindings().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_software_ccmp_exact_addresses_direction_and_group_tx
);
