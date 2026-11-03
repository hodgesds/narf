//! Device key offload on the retained owner: commit-time installs, token
//! gating and the shared PN/replay state (unexecuted until the coordinated
//! native run).
use super::*;

fn offload_established() -> Security {
    let mut s = Security::new(OWN, AP, &PMK, &rsne(), &rsne(), None, 2)
        .unwrap()
        .with_hardware_keys()
        .unwrap();
    let p = ptk(AN, SN);
    assert_eq!(
        s.receive(&mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false)), SN),
        Ok(Rx::ReplyReady)
    );
    deliver(&mut s);
    assert!(s.take_key_installs().is_empty());
    assert_eq!(
        s.receive(
            &mpdu(native(
                &key_frame(0x13ca, 2, AN, &kde(GTK), Some(&p)),
                false
            )),
            SN
        ),
        Ok(Rx::ReplyReady)
    );
    deliver(&mut s);
    s
}
/// A device-decrypted unicast DATA MPDU: Protected kept, CCMP header kept,
/// plaintext body, MIC removed.
fn decrypted(plain: &[u8], pn: u64) -> Vec<u8> {
    let mut out = plain[..24].to_vec();
    out[1] |= 0x40;
    out.extend_from_slice(&crate::ccmp::build_ccmp_header(pn, 0));
    out.extend_from_slice(&plain[24..]);
    out
}
fn ip_frame() -> Vec<u8> {
    let mut plain = native(&[0x45; 20], false);
    plain[30..32].copy_from_slice(&0x0800u16.to_be_bytes());
    plain
}

fn smoke_station_offload_installs_follow_commit_and_gate_receive() -> TestResult {
    let mut s = offload_established();
    let installs = s.take_key_installs();
    let p = ptk(AN, SN);
    if installs.len() != 2
        || !installs[0].pairwise
        || installs[0].key_id != 0
        || installs[0].material[..] != p.tk[..]
        || installs[1].pairwise
        || installs[1].key_id != 2
        || *installs[1].material != GTK
        || !s.take_key_installs().is_empty()
    {
        return TestResult::Fail("PTK-then-GTK install entries at M4 commit");
    }
    let plain = ip_frame();
    // Unconfirmed: the device may hold another key; nothing is admitted.
    if s.receive_decrypted_with_nonce(&mpdu(decrypted(&plain, 1)), || None) != Ok(Rx::Ignored)
        || s.pairwise_offloaded()
    {
        return TestResult::Fail("unconfirmed slot admitted device-decrypted data");
    }
    if s.key_installed(installs[0].token.wrapping_add(100)) {
        return TestResult::Fail("foreign token confirmed a slot");
    }
    if !s.key_installed(installs[0].token) || !s.pairwise_offloaded() {
        return TestResult::Fail("matching confirmation");
    }
    if !matches!(
        s.receive_decrypted_with_nonce(&mpdu(decrypted(&plain, 1)), || None),
        Ok(Rx::Data(_))
    ) || s.receive_decrypted_with_nonce(&mpdu(decrypted(&plain, 1)), || None) != Ok(Rx::Ignored)
    {
        return TestResult::Fail("decrypted PN not admitted once");
    }
    // Software receive shares the same per-TID window.
    if s.receive(&mpdu(encrypt(&plain, &p.tk, 1, 0)), [0; 32]) != Ok(Rx::Ignored) {
        return TestResult::Fail("software replay of a device-accepted PN");
    }
    if !matches!(
        s.receive(&mpdu(encrypt(&plain, &p.tk, 2, 0)), [0; 32]),
        Ok(Rx::Data(_))
    ) {
        return TestResult::Fail("software fallback stopped after offload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/offload",
    smoke_station_offload_installs_follow_commit_and_gate_receive
);

fn smoke_station_offload_header_only_tx_shares_pn_and_needs_confirmation() -> TestResult {
    let mut s = offload_established();
    let installs = s.take_key_installs();
    let mut eth = vec![2, 0, 0, 0, 0, 3];
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&[0x08, 0x00, 1, 2, 3]);
    if s.transmit_ethernet_offload(&eth, None) != Err(Error::State) {
        return TestResult::Fail("header-only TX before confirmation");
    }
    let sealed = s.transmit_ethernet(&eth).unwrap();
    if sealed[24..32] != crate::ccmp::build_ccmp_header(1, 0) {
        return TestResult::Fail("software PN");
    }
    s.key_install_failed(installs[1].token);
    s.key_installed(installs[0].token);
    let Ok(wire) = s.transmit_ethernet_offload(&eth, Some(5)) else {
        return TestResult::Fail("confirmed header-only TX refused");
    };
    if wire[..2] != [0x88, 0x41]
        || wire[24] != 5
        || wire[26..34] != crate::ccmp::build_ccmp_header(2, 0)
        || wire[34..40] != [0xaa, 0xaa, 3, 0, 0, 0]
        || wire[40..] != [0x08, 0x00, 1, 2, 3]
    {
        return TestResult::Fail("GENERATE_IV form or PN continuity");
    }
    if s.transmit_ethernet_offload(&eth, Some(16)) != Err(Error::Profile) {
        return TestResult::Fail("invalid TID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/offload",
    smoke_station_offload_header_only_tx_shares_pn_and_needs_confirmation
);

fn smoke_station_offload_entry_points_refused_without_opt_in() -> TestResult {
    let mut s = established();
    if s.receive_decrypted_with_nonce(&mpdu(decrypted(&ip_frame(), 1)), || None)
        != Err(Error::State)
        || s.receive_management_decrypted(&mpdu(vec![0xc0; 40])) != Err(Error::State)
        || s.hardware_keys()
        || !s.take_key_installs().is_empty()
        || s.key_installed(1)
    {
        return TestResult::Fail("software owner exposed offload state");
    }
    let mut eth = vec![2, 0, 0, 0, 0, 3];
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&[0x08, 0x00, 1]);
    if s.transmit_ethernet_offload(&eth, None) != Err(Error::State) {
        return TestResult::Fail("software owner sent header-only data");
    }
    if established().with_hardware_keys().is_ok() {
        return TestResult::Fail("opt-in after keys exist");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/offload",
    smoke_station_offload_entry_points_refused_without_opt_in
);
