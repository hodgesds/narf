//! Native-WiFi decap conversion cases (mac.c `ath10k_tx_h_nwifi`, htt_rx.c
//! `ath10k_htt_rx_h_undecap_nwifi`); unexecuted until the coordinated
//! native run.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const BSSID: [u8; 6] = [2, 0, 0, 0, 0, 0xaa];
const REMOTE: [u8; 6] = [2, 0, 0, 0, 0, 0x55];

/// One native-WiFi MSDU; `status` (the original header + CCMP header) is
/// placed in `rx_hdr_status` only by the caller for the first MSDU.
fn msdu(first: bool, last: bool, body: &[u8], status: &[u8], enctype: u32) -> Msdu {
    let mut descriptor = [0u8; 300];
    set_word(&mut descriptor, 4, (1 << 31) | 3);
    set_word(
        &mut descriptor,
        12,
        1800 | (1 << 11) | (7 << 16) | (enctype << 28),
    );
    set_word(&mut descriptor, 20, 5 << 28);
    let mut payload = vec![0x08, 0x02, 0, 0];
    payload.extend_from_slice(&OWN);
    payload.extend_from_slice(&BSSID);
    payload.extend_from_slice(&REMOTE);
    payload.extend_from_slice(&[0x70, 0]);
    payload.extend_from_slice(body);
    set_word(&mut descriptor, 24, payload.len() as u32);
    set_word(&mut descriptor, 32, 1 << 8);
    set_word(
        &mut descriptor,
        56,
        if first { 1 << 14 } else { 0 } | if last { 1 << 15 } else { 0 },
    );
    descriptor[236..236 + status.len()].copy_from_slice(status);
    Msdu {
        descriptor,
        payload,
        offload: None,
    }
}
fn original(amsdu: bool, protected: bool) -> Vec<u8> {
    let mut h = vec![0x88, if protected { 0x42 } else { 0x02 }, 0, 0];
    h.extend_from_slice(&OWN);
    h.extend_from_slice(&BSSID);
    h.extend_from_slice(&BSSID);
    h.extend_from_slice(&[0x70, 0, 5 | if amsdu { 0x80 } else { 0 }, 0]);
    h.extend_from_slice(&[0, 0]); // decap alignment to 28
    if protected {
        h.extend_from_slice(&[9, 0, 0, 0x20, 0, 0, 0, 0]);
    }
    h
}

/// `ath10k_tx_h_nwifi`: QoS Control leaves the header and the QoS subtype
/// is cleared; non-QoS, Protected and the body are kept.
fn smoke_ath10k_nwifi_transmit_strips_qos_control() -> TestResult {
    let mut qos = vec![0x88, 0x41, 0, 0];
    qos.extend_from_slice(&BSSID);
    qos.extend_from_slice(&OWN);
    qos.extend_from_slice(&REMOTE);
    qos.extend_from_slice(&[0x30, 0, 6, 0, 0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
    let Some(native) = transmit(qos.clone()) else {
        return TestResult::Fail("QoS data refused");
    };
    let mut expected = qos[..24].to_vec();
    expected[0] = 0x08;
    expected.extend_from_slice(&qos[26..]);
    if native != expected {
        return TestResult::Fail("QoS Control not stripped");
    }
    if transmit(expected.clone()) != Some(expected.clone()) {
        return TestResult::Fail("non-QoS data changed");
    }
    let mut from_ds = expected;
    from_ds[1] = 0x02;
    if transmit(from_ds).is_some() || transmit(vec![0x88, 0x01]).is_some() {
        return TestResult::Fail("non-station or short frame accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/nwifi",
    smoke_ath10k_nwifi_transmit_strips_qos_control
);

/// A decrypted single MSDU regains its original header, DA/SA and CCMP
/// header, plus MIC/FCS space, and becomes a RAW-shaped first+last MSDU.
fn smoke_ath10k_nwifi_undecap_single_decrypted_msdu() -> TestResult {
    let status = original(false, true);
    let body = [0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 0x45, 0];
    let Some(raw) = undecap(&[msdu(true, true, &body, &status, 6)]) else {
        return TestResult::Fail("decrypted MSDU refused");
    };
    let mut expected = status[..26].to_vec();
    expected[16..22].copy_from_slice(&REMOTE);
    expected.extend_from_slice(&status[28..36]);
    expected.extend_from_slice(&body);
    expected.extend_from_slice(&[0; 12]);
    if raw.payload != expected {
        return TestResult::Fail("rebuilt MPDU");
    }
    if word(&raw.descriptor, 24) & 0x3fff != expected.len() as u32
        || decap_format(&raw.descriptor) != 0
        || word(&raw.descriptor, 56) & 0xc000 != 0xc000
        || word(&raw.descriptor, 12) != word(&status_descriptor(), 12)
    {
        return TestResult::Fail("rebuilt descriptor");
    }
    if undecap(&[msdu(true, true, &body, &status, 4)]).is_some() {
        return TestResult::Fail("non-CCMP protected MSDU accepted");
    }
    let mut no_ext = status.clone();
    no_ext[31] = 0;
    if undecap(&[msdu(true, true, &body, &no_ext, 6)]).is_some() {
        return TestResult::Fail("CCMP header without ExtIV accepted");
    }
    TestResult::Pass
}
fn status_descriptor() -> [u8; 300] {
    msdu(true, true, &[], &original(false, true), 6).descriptor
}
kernel_test_in!(
    "drivers/wireless/ath10k/nwifi",
    smoke_ath10k_nwifi_undecap_single_decrypted_msdu
);

/// The MSDUs of an A-MSDU become one aggregate: the original QoS header
/// (A-MSDU present), one CCMP header and padded subframe headers.
fn smoke_ath10k_nwifi_undecap_amsdu_aggregate() -> TestResult {
    let status = original(true, true);
    let one = [0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1];
    let two = [0xaa, 0xaa, 3, 0, 0, 0, 8, 6, 2, 2];
    let group = [
        msdu(true, false, &one, &status, 6),
        msdu(false, true, &two, &[], 6),
    ];
    let Some(raw) = undecap(&group) else {
        return TestResult::Fail("A-MSDU refused");
    };
    let mut expected = status[..26].to_vec();
    expected.extend_from_slice(&status[28..36]);
    for (body, pad) in [(&one[..], 1), (&two[..], 0)] {
        expected.extend_from_slice(&OWN);
        expected.extend_from_slice(&REMOTE);
        expected.extend_from_slice(&(body.len() as u16).to_be_bytes());
        expected.extend_from_slice(body);
        expected.extend_from_slice(&[0; 3][..pad]);
    }
    expected.extend_from_slice(&[0; 12]);
    if raw.payload != expected {
        return TestResult::Fail("rebuilt aggregate");
    }
    if undecap(&group[..1]).is_some() || undecap(&group[1..]).is_some() {
        return TestResult::Fail("incomplete A-MSDU accepted");
    }
    let single = original(false, true);
    let split = [
        msdu(true, false, &one, &single, 6),
        msdu(false, true, &two, &[], 6),
    ];
    if undecap(&split).is_some() {
        return TestResult::Fail("multi-MSDU without A-MSDU bit accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/nwifi",
    smoke_ath10k_nwifi_undecap_amsdu_aggregate
);
