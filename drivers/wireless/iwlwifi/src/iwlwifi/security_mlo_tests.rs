//! Native Session uses independently authored MLO KDEs and logical-PTK bytes.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::association::mlo::{BasicMultiLink, Context, Local};
const OWN_LINK: [u8; 6] = [2, 0x71, 2, 3, 4, 5];
const AP_LINK: [u8; 6] = [2, 0x72, 2, 3, 4, 5];
const OWN_MLD: [u8; 6] = [2, 0xa1, 2, 3, 4, 5];
const AP_MLD: [u8; 6] = [2, 0xa2, 2, 3, 4, 5];
// Python3 hmac/hashlib KDF-Hash-Length, PMK11*32/ANonce22*32/SNonce33*32,
// label Pairwise key expansion, sorted logical MACs/nonces, 384bits.
const KCK: [u8; 16] = [
    0x6d, 0xd1, 0x88, 0xfa, 0xe3, 0xe3, 0xce, 0x8e, 0x0c, 0x52, 0x22, 0xb5, 0xce, 0xc3, 0xbb, 0x1c,
];
const KEK: [u8; 16] = [
    0x2d, 0x07, 0x8e, 0xc0, 0x6e, 0xf2, 0x72, 0x50, 0x88, 0x9c, 0x94, 0x6b, 0x6f, 0x5e, 0xf9, 0xc2,
];
const TK: [u8; 16] = [
    0xbb, 0x83, 0x98, 0xb8, 0x54, 0x23, 0xf6, 0x7b, 0x95, 0xc4, 0x75, 0x4f, 0x3f, 0x42, 0xbd, 0xd0,
];
fn context() -> Context {
    let mut basic = vec![0x10, 0, 8];
    basic.extend_from_slice(&AP_MLD);
    basic.push(3);
    Local::single_link(OWN_MLD)
        .unwrap()
        .context(OWN_LINK, AP_LINK, &BasicMultiLink::parse(&basic).unwrap())
        .unwrap()
}
fn rsne() -> Vec<u8> {
    let body = narf_wireless::rsn::RsnIe::wpa3_sae_ccmp().encode_body();
    let mut out = vec![48, body.len() as u8];
    out.extend_from_slice(&body);
    out
}
fn session() -> Session {
    Session::new(
        Akm::Wpa3Sae,
        [0x11; 32],
        AP_LINK,
        OWN_LINK,
        [0x33; 32],
        rsne()[2..].to_vec(),
    )
    .with_mld(context())
    .unwrap()
}
fn mac(address: [u8; 6]) -> Vec<u8> {
    let mut out = vec![221, 10, 0, 15, 172, 3];
    out.extend_from_slice(&address);
    out
}
fn message1(address: [u8; 6], nonce: u8, counter: u64) -> Vec<u8> {
    let mut key = KeyFrame::empty(16);
    key.key_information = KI_KEY_ACK | KI_KEY_TYPE_PAIRWISE;
    key.key_length = 16;
    key.key_nonce = [nonce; 32];
    key.replay_counter = counter;
    key.key_data = mac(address);
    key.into_eapol()
}
fn clear(link: u8, legacy: bool) -> Vec<u8> {
    let mut out = mac(AP_MLD);
    let rsne = rsne();
    out.extend_from_slice(&[221, (4 + 7 + rsne.len()) as u8, 0, 15, 172, 19, 0x10 | link]);
    out.extend_from_slice(&AP_LINK);
    out.extend_from_slice(&rsne);
    out.extend_from_slice(&[221, 27, 0, 15, 172, 16, 0x31, 6, 5, 4, 3, 2, 1]);
    out.extend_from_slice(&[0x77; 16]);
    out.extend_from_slice(&[221, 29, 0, 15, 172, 17, 5, 0, 16, 15, 14, 13, 12, 11, 0x30]);
    out.extend_from_slice(&[0x6b; 16]);
    if legacy {
        out.extend_from_slice(&[221, 22, 0, 15, 172, 1, 1, 0]);
        out.extend_from_slice(&[0x88; 16]);
    }
    out
}
fn authenticated(mut data: Vec<u8>, group: bool, counter: u64) -> Vec<u8> {
    if data.len() % 8 != 0 {
        data.push(221);
    }
    while data.len() % 8 != 0 {
        data.push(0);
    }
    let mut key = KeyFrame::empty(16);
    key.key_information = KI_KEY_ACK
        | KI_KEY_MIC
        | KI_SECURE
        | KI_ENCRYPTED_KEY_DATA
        | if group {
            0
        } else {
            KI_KEY_TYPE_PAIRWISE | KI_INSTALL
        };
    key.key_length = 16;
    key.replay_counter = counter;
    key.key_nonce = if group { [0; 32] } else { [0x22; 32] };
    key.key_rsc = [0xff; 8]; // MLO must take MLGTK's selected-link PN instead.
    key.key_data = narf_crypto::aes_kw::aes_wrap(&KEK, &data).unwrap();
    let mut pdu = key.into_eapol();
    let mic = narf_crypto::cmac_aes128::cmac_aes128(&KCK, &pdu);
    pdu[81..97].copy_from_slice(&mic);
    pdu
}
fn smoke_iwl_mld_session_logical_ptk_selected_link_pn_and_retransmission() -> TestResult {
    let mut owner = session();
    let reply = match owner.process(&message1(AP_MLD, 0x22, 1)) {
        Ok(r) => r,
        Err(e) => return TestResult::Fail(e),
    };
    if reply.keys.is_some() || owner.complete() || owner.ptk.as_ref().unwrap().tk != TK {
        return TestResult::Fail("native MLD PTK used physical addresses or M1 opened port");
    }
    let m2 = KeyFrame::decode(&reply.bytes[4..], 16).unwrap();
    if !m2.key_data.ends_with(&mac(OWN_MLD)) {
        return TestResult::Fail("native MLD M2 lost own MAC KDE");
    }
    let m3 = authenticated(clear(3, false), false, 2);
    let reply = match owner.process(&m3) {
        Ok(r) => r,
        Err(e) => return TestResult::Fail(e),
    };
    let Some(keys) = reply.keys else {
        return TestResult::Fail("native MLD M3 omitted selected keys");
    };
    if keys.pairwise != Some(TK)
        || keys.group != [0x77; 16]
        || keys.group_rx_pn != 0x0102_0304_0506
        || keys.igtk != Some(([0x6b; 16], 5, 0x0b0c_0d0e_0f10))
    {
        return TestResult::Fail("native MLD selected-link keys or PN floor changed");
    }
    if owner.process(&m3).unwrap().keys.is_some() {
        return TestResult::Fail("native MLD repeated M3 reinstalled keys");
    }
    let group = authenticated(clear(3, false), true, 3);
    if owner.process(&group).unwrap().keys.is_none()
        || owner.process(&group).unwrap().keys.is_some()
    {
        return TestResult::Fail("native MLD group rekey lost cached receipt ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_session_logical_ptk_selected_link_pn_and_retransmission
);

fn smoke_iwl_mld_session_wrong_m1_and_authenticated_link_kdes_preserve_retry() -> TestResult {
    let mut owner = session();
    if owner.process(&message1(AP_LINK, 0x22, 1)).is_ok() || owner.ptk.is_some() {
        return TestResult::Fail("native MLD physical alias M1 consumed nonce/PTK state");
    }
    for (link, legacy) in [(4, false), (3, true)] {
        let mut owner = session();
        owner.process(&message1(AP_MLD, 0x22, 1)).unwrap();
        if owner
            .process(&authenticated(clear(link, legacy), false, 2))
            .is_ok()
            || owner.complete()
            || owner.replay != 1
        {
            return TestResult::Fail(
                "native MLD authenticated wrong-link/mixed-key data consumed replay",
            );
        }
        if owner
            .process(&authenticated(clear(3, false), false, 2))
            .is_err()
        {
            return TestResult::Fail("native MLD negative poisoned valid same-counter M3");
        }
        let requested = core::cell::Cell::new(false);
        if owner
            .process_with_nonce(&message1(AP_LINK, 0x55, 4), || {
                requested.set(true);
                Ok([0x66; 32])
            })
            .is_ok()
            || requested.get()
            || !owner.complete()
        {
            return TestResult::Fail("native MLD rekey M1 sampled nonce before peer MAC check");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_session_wrong_m1_and_authenticated_link_kdes_preserve_retry
);
