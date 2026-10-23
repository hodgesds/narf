use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Ccm;
impl AesCcm for Ccm {
    fn encrypt(&self, key: &[u8; 16], nonce: &[u8; 13], aad: &[u8], body: &mut [u8]) -> [u8; 8] {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body).expect("bounded fixture")
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag).map_err(|_| CcmpError::AuthFailed)
    }
}
fn header() -> [u8; 36] {
    let mut h = [0; 36];
    h[0] = 0xf8; // QoS data; subtype bits4..6 must be muted.
    h[1] = 0xbb; // A4, Retry/PM/MoreData, Order, Protected initially clear.
    h[2..4].copy_from_slice(&[0xcd, 0xab]);
    for (target, start) in [(4, 0x10), (10, 0x20), (16, 0x30), (24, 0x40)] {
        for i in 0..6 {
            h[target + i] = start + i as u8;
        }
    }
    h[22..24].copy_from_slice(&[0xb0, 0xfe]);
    h[30..32].copy_from_slice(&[0x67, 0xa5]);
    h[32..].copy_from_slice(&[0x55; 4]); // HT Control is not authenticated.
    h
}
fn smoke_ccmp_independent_aad_and_nonce_vectors() -> TestResult {
    let h = header();
    let expected = [
        0x88, 0x43, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 7, 0,
    ];
    if build_aad(&h) != expected
        || build_nonce(
            7,
            false,
            &[0x20, 0x21, 0x22, 0x23, 0x24, 0x25],
            0x010203040506,
        ) != [7, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 1, 2, 3, 4, 5, 6]
    {
        return TestResult::Fail("independent QoS/A4 AAD or PN-order nonce vector");
    }
    let mut base = [0; 24];
    base.copy_from_slice(&h[..24]);
    base[0] = 0x78;
    base[1] = 0xb9;
    let aad = build_aad(&base);
    if aad.len() != 22 || aad[..2] != [0x08, 0xc1] {
        return TestResult::Fail("non-QoS Order retained, data subtype muted, Protected forced");
    }
    base[0] = 0xd0; // Management Action subtype must not be muted.
    if build_aad(&base)[..2] != [0xd0, 0xc1] {
        return TestResult::Fail("management subtype must remain authenticated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp",
    smoke_ccmp_independent_aad_and_nonce_vectors
);

fn smoke_ccmp_composed_independent_ciphertext_vector() -> TestResult {
    // Python cryptography/OpenSSL AESCCM, frozen independently of these helpers:
    // key00..0f, nonce07202122232425010203040506, AAD as above, message00..13.
    let expected = [
        0x29, 0x20, 0x9e, 0x94, 0xa2, 0xb9, 0x49, 0xde, 0xae, 0x26, 0x01, 0xe9, 0xb7, 0xc7, 0x37,
        0x86, 0xf8, 0x5b, 0x62, 0xf0, 0x03, 0xb7, 0x43, 0x90, 0xa1, 0x25, 0xbd, 0x6b,
    ];
    let mut key = [0; 16];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut body = [0; 20];
    for (i, b) in body.iter_mut().enumerate() {
        *b = i as u8;
    }
    let plain = body;
    let h = header();
    let mut wire = protect(&Ccm, &h, &key, 0x010203040506, 2, 7, false, &mut body);
    if wire[..8] != [6, 5, 0, 0xa0, 4, 3, 2, 1] || wire[8..] != expected {
        return TestResult::Fail("independent CCMP ciphertext/header/MIC vector");
    }
    let mut replay = ReplayWindow::default();
    if unprotect(&Ccm, &h, &key, 7, false, &mut replay, &mut wire) != Ok(plain.to_vec())
        || replay.last_seen_pn != 0x010203040506
    {
        return TestResult::Fail("composed CCM open/replay commit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp",
    smoke_ccmp_composed_independent_ciphertext_vector
);

fn smoke_ccmp_forged_high_pn_keeps_ciphertext_and_replay() -> TestResult {
    let h = header();
    let key = [7; 16];
    let mut replay = ReplayWindow { last_seen_pn: 9 };
    let mut body = [0x42; 20];
    let mut bad = protect(&Ccm, &h, &key, 0xabcdef, 0, 7, false, &mut body);
    *bad.last_mut().unwrap() ^= 1;
    let saved = bad.clone();
    if unprotect(&Ccm, &h, &key, 7, false, &mut replay, &mut bad) != Err(CcmpError::AuthFailed)
        || bad != saved
        || replay.last_seen_pn != 9
    {
        return TestResult::Fail("forged MIC changed ciphertext or replay state");
    }
    let mut body = [0x42; 20];
    let mut good = protect(&Ccm, &h, &key, 10, 0, 7, false, &mut body);
    let original = good.clone();
    if unprotect(&Ccm, &h, &key, 7, false, &mut replay, &mut good).is_err()
        || replay.last_seen_pn != 10
    {
        return TestResult::Fail("forged high PN blocked later authentic lower PN");
    }
    let mut duplicate = original;
    let saved = duplicate.clone();
    if unprotect(&Ccm, &h, &key, 7, false, &mut replay, &mut duplicate) != Err(CcmpError::Replay)
        || duplicate != saved
    {
        return TestResult::Fail("replayed authentic frame was decrypted/mutated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp",
    smoke_ccmp_forged_high_pn_keeps_ciphertext_and_replay
);

fn smoke_ccmp_muted_fields_do_not_break_authentication() -> TestResult {
    let h = header();
    let key = [3; 16];
    let mut body = [0x5a; 13];
    let wire = protect(&Ccm, &h, &key, 1, 0, 7, false, &mut body);
    let mut changed = h;
    changed[0] ^= 0x70;
    changed[1] ^= 0xb8;
    changed[2..4].fill(0);
    changed[22] ^= 0xf0;
    changed[23] ^= 0xff;
    changed[30] ^= 0x60;
    changed[31] ^= 0xff;
    changed[32..].fill(0);
    let mut candidate = wire.clone();
    if unprotect(
        &Ccm,
        &changed,
        &key,
        7,
        false,
        &mut ReplayWindow::default(),
        &mut candidate,
    )
    .is_err()
    {
        return TestResult::Fail("muted retransmission/QoS/HTC fields entered AAD");
    }
    for offset in [4, 10, 16, 24, 30] {
        let mut changed = h;
        changed[offset] ^= 1;
        let mut candidate = wire.clone();
        let mut replay = ReplayWindow::default();
        if unprotect(&Ccm, &changed, &key, 7, false, &mut replay, &mut candidate)
            != Err(CcmpError::AuthFailed)
            || candidate != wire
            || replay.last_seen_pn != 0
        {
            return TestResult::Fail("address or QoS TID was not authenticated");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp",
    smoke_ccmp_muted_fields_do_not_break_authentication
);
