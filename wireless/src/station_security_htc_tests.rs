//! +HTC QoS DATA receive: the HT Control field after QoS Control is skipped
//! and the Order bit is masked from the CCMP AAD (mac80211 `ccmp_gcmp_aad`).
use super::*;

/// Protected QoS DATA from the AP (TID 5) with a four-octet HE-variant HT
/// Control field when `htc` (Order bit set). CCMP is computed over the
/// 26-octet header; the AAD excludes HT Control and masks Order.
fn qos(htc: bool, pn: u64, tk: &[u8]) -> Vec<u8> {
    let mut header = vec![0x88, 0x42 | if htc { 0x80 } else { 0 }, 0, 0];
    header.extend_from_slice(&OWN);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&[0x10, 0, 5, 0]);
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00];
    body.extend_from_slice(&[0x45; 20]);
    let wire = crate::ccmp::protect(
        &Ccm,
        &header,
        tk.try_into().unwrap(),
        pn,
        0,
        5,
        false,
        &mut body,
    )
    .unwrap();
    if htc {
        header.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    }
    header.extend_from_slice(&wire);
    header
}

fn smoke_station_htc_qos_data_is_received() -> TestResult {
    let mut s = established();
    let p = ptk(AN, SN);
    let Ok(Rx::Data(frame)) = s.receive(&mpdu(qos(true, 1, &p.tk)), [0; 32]) else {
        return TestResult::Fail("+HTC QoS data from the AP was dropped");
    };
    // The admitted MPDU: 26-octet QoS header, Order and Protected clear,
    // no HT Control, then the plaintext LLC/SNAP MSDU.
    if frame.len() != 26 + 8 + 20
        || frame[..2] != [0x88, 0x02]
        || frame[24] != 5
        || frame[26..34] != [0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]
    {
        return TestResult::Fail("+HTC QoS data normalized wrongly");
    }
    // The same PN without HT Control is a replay: one shared TID counter.
    if s.receive(&mpdu(qos(false, 1, &p.tk)), [0; 32]) != Ok(Rx::Ignored) {
        return TestResult::Fail("+HTC frame did not advance the TID replay counter");
    }
    if !matches!(
        s.receive(&mpdu(qos(false, 2, &p.tk)), [0; 32]),
        Ok(Rx::Data(_))
    ) {
        return TestResult::Fail("plain QoS data after +HTC was dropped");
    }
    // A tampered HT Control field is not authenticated but a tampered QoS
    // TID is.
    let mut tid = qos(true, 3, &p.tk);
    tid[24] = 6;
    if s.receive(&mpdu(tid), [0; 32]) != Ok(Rx::Ignored) {
        return TestResult::Fail("modified QoS TID accepted under +HTC");
    }
    let mut htc = qos(true, 4, &p.tk);
    htc[26] = 0x0f;
    if !matches!(s.receive(&mpdu(htc), [0; 32]), Ok(Rx::Data(_))) {
        return TestResult::Fail("HT Control must not be part of the AAD");
    }
    // Order on non-QoS DATA is not an HT Control field and stays refused.
    let mut plain = native(&[0x45; 20], false);
    plain[30..32].copy_from_slice(&0x0800u16.to_be_bytes());
    let mut ordered = encrypt(&plain, &p.tk, 9, 0);
    ordered[1] |= 0x80;
    if s.receive(&mpdu(ordered), [0; 32]) != Ok(Rx::Ignored) {
        return TestResult::Fail("non-QoS Order frame admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/htc",
    smoke_station_htc_qos_data_is_received
);
