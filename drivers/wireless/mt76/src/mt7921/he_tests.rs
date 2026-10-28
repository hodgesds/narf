//! Native HE station admission, records, P-RXV admission and teardown over
//! the production Session (Linux mt7921_init_he_caps / sta_he_tlv / bss_he).
use super::*;
use crate::mt7921::association::TxPermission;

/// AP HE Capabilities (ext 35) and HE Operation (ext 36).
pub(super) fn he_elements(five: bool, color: Option<u8>) -> Vec<u8> {
    let mut cap = vec![255, 22, 35];
    cap.extend_from_slice(&[0x01, 0, 0, 0x02, 0x40, 0]); // HTC, OMI, AMSDU in AMPDU
    let mut phy = [0u8; 11];
    phy[0] = if five { 0x04 } else { 0x02 };
    phy[1] = 0x20; // LDPC
    phy[2] = 0x0c; // STBC TX/RX <= 80MHz
    phy[3] = 0x80; // SU beamformer
    cap.extend_from_slice(&phy);
    cap.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff]);
    let params: u32 = 2
        | (1023 << 4)
        | (u32::from(color.unwrap_or(0)) << 24)
        | if color.is_none() { 1 << 31 } else { 0 };
    let mut op = vec![255, 7, 36];
    op.extend_from_slice(&params.to_le_bytes());
    op.extend_from_slice(&0xfffcu16.to_le_bytes());
    cap.extend_from_slice(&op);
    cap
}
/// HE MU EDCA Parameter Set (ext 38): BE, BK, VI, VO records.
fn mu_edca() -> Vec<u8> {
    vec![
        255, 14, 38, 0, 0x03, 0xa4, 8, 0x27, 0xa4, 9, 0x42, 0x43, 10, 0x62, 0x32, 11,
    ]
}
fn prepared5(color: Option<u8>, edca: bool) -> (Session<Model>, ScanBss, TxPermission) {
    prepared5_with(color, edca, true)
}
fn prepared5_with(
    color: Option<u8>,
    edca: bool,
    secure: bool,
) -> (Session<Model>, ScanBss, TxPermission) {
    let (mut s, mut b, p) = super::vht_tests::prepared(2, secure);
    let he = he_elements(true, color);
    b.information_elements.extend_from_slice(&he);
    let reply = s.backend.vht_reply.as_mut().unwrap();
    reply.extend_from_slice(&he);
    if edca {
        reply.extend_from_slice(&mu_edca());
    }
    (s, b, p)
}
const LOCAL_HE5: [u8; 31] = [
    255, 29, 35, 0x01, 0x08, 0, 0x1a, 0x40, 0, 0x44, 0x70, 0xce, 0x12, 0x0d, 0xc0, 0xb3, 0x06,
    0x42, 0x3f, 0, 0xfa, 0xff, 0xfa, 0xff, 0x79, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71,
];
const STA_REC_HE: [u8; 28] = [
    14, 0, 28, 0, 0x59, 0x06, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0xfa, 0xff, 0, 0, 0, 0, 0,
    0,
];
fn bss_he(f: &[u8]) -> Option<&[u8]> {
    (f.len() == 76 && f[34..36] == [2, 0] && f[52..56] == [5, 0, 16, 0]).then(|| &f[48..76])
}
fn he_data(mode: u32, mcs: u32, nss: u32, gi: u32, pn: u64) -> Vec<u8> {
    let mut packet = super::vht_tests::data(true, 2, 0, 1, pn);
    let rxv = (mode << 24) | (2 << 12) | (gi << 15) | ((nss - 1) << 7) | mcs;
    packet[40..44].copy_from_slice(&rxv.to_le_bytes());
    packet
}

fn native() -> Result<(), &'static str> {
    // PPE thresholds follow mt76_connac_gen_ppe_thresh exactly.
    if crate::mt7921::he::ppe_thresholds(2, true) != [0x79, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71]
        || crate::mt7921::he::ppe_thresholds(1, false) != [0x18, 0x1c, 0x07]
    {
        return Err("mt76_connac_gen_ppe_thresh bytes");
    }
    let (mut s, b, p) = prepared5(Some(5), true);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42) || s.he_profile.is_none() {
        return Err("native HE association");
    }
    let f = &s.backend.frames;
    if !f
        .iter()
        .any(|(_, f)| f.first() == Some(&0) && f.windows(31).any(|ie| ie == LOCAL_HE5))
    {
        return Err("mt7921_init_he_caps station HE Capabilities in request");
    }
    let Some((_, peer)) = f
        .iter()
        .find(|(_, f)| super::vht_tests::record(f, 14) == Some(&STA_REC_HE[..]))
    else {
        return Err("literal STA_REC_HE");
    };
    let mut v2 = vec![0x19, 0, 28, 0, 0x01, 0, 0, 0x02, 0x40, 0];
    v2.extend_from_slice(&[0x04, 0x20, 0x0c, 0x80, 0, 0, 0, 0, 0, 0, 0, 2]);
    v2.extend_from_slice(&[0xfa, 0xff, 0, 0, 0, 0]);
    if super::vht_tests::record(peer, 0x19) != Some(&v2[..])
        || super::vht_tests::record(peer, 0x15).is_none_or(|r| r[6] != 120)
    {
        return Err("STA_REC_HE_V2 / PHY_TYPE_BIT_HE");
    }
    let expected = [
        0, 0, 0, 0, 5, 0, 16, 0, 0xff, 3, 2, 0, 0xfa, 0xff, 0, 0, 0, 0, 0, 0, 4, 0, 8, 0, 1, 5, 0,
        0,
    ];
    if !f.iter().any(|(_, f)| bss_he(f) == Some(&expected[..])) {
        return Err("UNI_BSS_INFO_HE_BASIC + enabled BSS_COLOR");
    }
    if !f.iter().any(|(_, f)| {
        f.len() >= 70 && f[34..36] == [2, 0] && f[52..56] == [0, 0, 32, 0] && f[77] & 0x80 != 0
    }) {
        return Err("BSS basic PHY_MODE_AX_5G");
    }
    let mut mu = [0u8; 72];
    mu[5] = 1;
    // to_aci {VO->1, VI->0, BE->2, BK->3}: cw_min, cw_max, aifsn, acm, timer.
    mu[8..13].copy_from_slice(&[3, 4, 0x42, 0, 10]); // VI
    mu[16..21].copy_from_slice(&[2, 3, 0x62, 0, 11]); // VO
    mu[24..29].copy_from_slice(&[4, 10, 0x03, 0, 8]); // BE
    mu[32..37].copy_from_slice(&[4, 10, 0x27, 0, 9]); // BK
    if !f
        .iter()
        .any(|(_, f)| f.len() == 136 && f[36] == 0xb0 && f[64..136] == mu)
    {
        return Err("SET_MU_EDCA_PARMS from the HE MU EDCA element");
    }
    // HE SU MCS11 two streams and HE MU are admitted; HE TB, MCS12,
    // three streams, ER SU above MCS2 and reserved GI are dropped.
    s.backend.packets.push_back(he_data(8, 11, 2, 0, 9));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("HE SU MCS11 NSS2 receive");
    }
    s.backend.packets.push_back(he_data(11, 7, 1, 2, 10));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("HE MU receive");
    }
    for (pn, (mode, mcs, nss, gi)) in [
        (10, 3, 1, 0),
        (8, 12, 1, 0),
        (8, 3, 3, 0),
        (9, 5, 1, 0),
        (8, 3, 1, 3),
    ]
    .into_iter()
    .enumerate()
    {
        s.backend
            .packets
            .push_back(he_data(mode, mcs, nss, gi, 11 + pn as u64));
        if s.receive_ethernet().ok().flatten().is_some() {
            return Err("invalid HE PPDU admitted");
        }
    }
    let before = s.backend.frames.len();
    run(s.disassociate_station()).map_err(|_| "HE teardown")?;
    let disabled = [
        0, 0, 0, 0, 5, 0, 16, 0, 0xff, 3, 2, 0, 0xfa, 0xff, 0, 0, 0, 0, 0, 0, 4, 0, 8, 0, 0, 0, 0,
        0,
    ];
    if s.he_profile.is_some()
        || !s.backend.frames[before..]
            .iter()
            .any(|(_, f)| bss_he(f) == Some(&disabled[..]))
    {
        return Err("HE teardown retained profile or BSS color");
    }
    Ok(())
}
fn mt76_he_source_caps_sta_bss_mu_edca_rx_and_teardown() -> TestResult {
    native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/he",
    mt76_he_source_caps_sta_bss_mu_edca_rx_and_teardown
);

fn fallback() -> Result<(), &'static str> {
    // AP without HE: no request element, no HE records, HE PPDUs dropped.
    let (mut s, b, p) = super::vht_tests::prepared(2, true);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42) || s.he_profile.is_some() {
        return Err("VHT-only association");
    }
    let f = &s.backend.frames;
    if f.iter().any(|(_, f)| {
        f.first() == Some(&0) && f.windows(3).any(|ie| ie[0] == 255 && ie[2] == 35)
            || super::vht_tests::record(f, 14).is_some()
            || bss_he(f).is_some()
            || f.len() == 136 && f[36] == 0xb0
    }) {
        return Err("HE emitted without an HE AP");
    }
    s.backend.packets.push_back(he_data(8, 3, 1, 0, 9));
    if s.receive_ethernet().ok().flatten().is_some() {
        return Err("HE PPDU admitted without HE");
    }
    // Firmware without HE in its PHY TLV never offers HE.
    let (mut s, b, p) = prepared5(Some(5), false);
    let State::RadioReady(mut info) = s.state else {
        return Err("radio");
    };
    info.capabilities.phy.he = false;
    s.state = State::RadioReady(info);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42) || s.he_profile.is_some() {
        return Err("non-HE firmware still negotiated HE");
    }
    // No MU EDCA element: the all-zero MU EDCA record is still sent.
    let (mut s, b, p) = prepared5(None, false);
    if super::vht_tests::join(&mut s, &b, p, true) != Ok(42) {
        return Err("HE without MU EDCA");
    }
    let mut mu = [0u8; 72];
    mu[5] = 1;
    let f = &s.backend.frames;
    if !f
        .iter()
        .any(|(_, f)| f.len() == 136 && f[36] == 0xb0 && f[64..136] == mu)
        || !f
            .iter()
            .any(|(_, f)| bss_he(f).is_some_and(|b| b[24..26] == [0, 0]))
    {
        return Err("zero MU EDCA / disabled color");
    }
    Ok(())
}
fn mt76_he_absent_on_ap_or_firmware_keeps_vht_and_drops_he_ppdus() -> TestResult {
    fallback().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/he",
    mt76_he_absent_on_ap_or_firmware_keeps_vht_and_drops_he_ppdus
);

fn failure() -> Result<(), &'static str> {
    // An HE offer requires HE in the response.
    let (mut s, mut b, p) = super::vht_tests::prepared(2, true);
    b.information_elements
        .extend_from_slice(&he_elements(true, Some(1)));
    if super::vht_tests::join(&mut s, &b, p, true).is_ok() || s.he_profile.is_some() {
        return Err("HE offer without HE response admitted");
    }
    // A malformed MU EDCA element fails the association closed.
    let (mut s, b, p) = prepared5(Some(1), false);
    s.backend
        .vht_reply
        .as_mut()
        .unwrap()
        .extend_from_slice(&[255, 13, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    if super::vht_tests::join(&mut s, &b, p, true).is_ok() || s.he_profile.is_some() {
        return Err("malformed MU EDCA admitted");
    }
    Ok(())
}
fn mt76_he_response_omission_and_malformed_mu_edca_fail_closed() -> TestResult {
    failure().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/he",
    mt76_he_response_omission_and_malformed_mu_edca_fail_closed
);

fn band24() -> Result<(), &'static str> {
    let (mut s, mut b) = super::ht20_tests::prepared(6, false);
    let he = he_elements(false, Some(9));
    b.information_elements.extend_from_slice(&he);
    s.backend.ht_reply.as_mut().unwrap().extend_from_slice(&he);
    let joined = run(s.associate_station(
        &b,
        b"narf",
        crate::mt7921::association::Security::Open,
        test_permission_for(6),
        &[],
    ));
    if joined.is_err() || s.he_profile.is_none_or(|h| h.five()) {
        return Err("2.4GHz HE association");
    }
    let f = &s.backend.frames;
    // 2.4GHz station: 40MHz-in-2G | RU mapping, two-RU PPE thresholds.
    if !f.iter().any(|(_, f)| {
        f.first() == Some(&0)
            && f.windows(28)
                .any(|ie| ie[..3] == [255, 26, 35] && ie[9] == 0x22)
    }) || !f.iter().any(|(_, f)| {
        super::vht_tests::record(f, 14).is_some_and(|r| r[10] == 1 && r[20..22] == [0xfa, 0xff])
    }) || !f.iter().any(|(_, f)| {
        f.len() >= 70 && f[34..36] == [2, 0] && f[52..56] == [0, 0, 32, 0] && f[77] & 0x40 != 0
    }) {
        return Err("2.4GHz HE request/STA_REC_HE/PHY_MODE_AX_24G");
    }
    run(s.disassociate_station()).map_err(|_| "2.4GHz HE teardown")?;
    if s.he_profile.is_some() {
        return Err("2.4GHz HE teardown");
    }
    Ok(())
}
fn mt76_he_2ghz_station_caps_records_and_teardown() -> TestResult {
    band24().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/he",
    mt76_he_2ghz_station_caps_records_and_teardown
);

fn windows() -> Result<(), &'static str> {
    // mac80211 agg-rx.c: an HE peer's max_buf_size is
    // IEEE80211_MAX_AMPDU_BUF_HE; requested 0 selects it.
    for (requested, window) in [(0u16, 256u16), (256, 256), (300, 256), (100, 100), (65, 65)] {
        let (mut s, b, p) = prepared5_with(Some(5), false, false);
        if super::vht_tests::join(&mut s, &b, p, false) != Ok(42) {
            return Err("HE BA association");
        }
        let before = s.backend.frames.len();
        super::rx_ba_tests::establish_window(&mut s, 3, 4090, 0, requested)?;
        let frames = &s.backend.frames[before..];
        let field = (2 | 3 << 2 | window << 6).to_le_bytes();
        if frames.len() != 3
            || frames[0].1.get(80..82) != Some(window.to_le_bytes().as_slice())
            || frames[1].1.get(66..68) != Some(window.to_le_bytes().as_slice())
            || frames[2].1.get(29..31) != Some(field.as_slice())
        {
            return Err("HE recipient window in WTBL/STA_REC_BA/ADDBA response");
        }
        if requested == 0 {
            // Reorder a full 256-MPDU window across the 12-bit wrap.
            s.backend.tick_step_ns = 1_000;
            for offset in (1..window).rev() {
                s.backend.packets.push_back(super::rx_ba_tests::data_on(
                    36,
                    3,
                    (4090 + offset) & 4095,
                    None,
                    offset as u8,
                ));
                if s.receive_ethernet() != Ok(None) {
                    return Err("HE 256 window bypassed its SSN gap");
                }
            }
            s.backend
                .packets
                .push_back(super::rx_ba_tests::data_on(36, 3, 4090, None, 0));
            for value in 0..window {
                if s.receive_ethernet() != Ok(Some(super::amsdu_rx_tests::ethernet(value as u8, 3)))
                {
                    return Err("HE 256 window reorder lost or misordered a packet");
                }
            }
            s.backend.tick_step_ns = 1_000_000;
        }
        run(s.disassociate_station()).map_err(|_| "HE BA teardown")?;
        if s.rx_ba.active(3) || s.he_profile.is_some() {
            return Err("HE BA teardown retained the agreement");
        }
    }
    // A non-HE (VHT) peer stays at the HT bound.
    let (mut s, b, p) = super::vht_tests::prepared(2, false);
    if super::vht_tests::join(&mut s, &b, p, false) != Ok(42) {
        return Err("VHT BA association");
    }
    let before = s.backend.frames.len();
    super::rx_ba_tests::establish_window(&mut s, 3, 10, 0, 256)?;
    if s.backend.frames[before..]
        .first()
        .and_then(|f| f.1.get(80..82))
        != Some(64u16.to_le_bytes().as_slice())
    {
        return Err("non-HE peer exceeded IEEE80211_MAX_AMPDU_BUF_HT");
    }
    Ok(())
}
fn mt76_rx_ba_he_peer_windows_up_to_256_reorder_and_teardown() -> TestResult {
    windows().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/he",
    mt76_rx_ba_he_peer_windows_up_to_256_reorder_and_teardown
);
