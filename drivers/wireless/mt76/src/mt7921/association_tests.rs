use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn bss(wpa2: bool) -> ScanBss {
    let mut information_elements = vec![
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 6,
    ];
    if wpa2 {
        let rsn = RsnIe::wpa2_psk_ccmp().encode_body();
        information_elements.extend_from_slice(&[48, rsn.len() as u8]);
        information_elements.extend_from_slice(&rsn);
    }
    ScanBss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 6,
        band: None,
        signal_dbm: Some(-50),
        capability: if wpa2 { 0x11 } else { 1 },
        beacon_interval: 100,
        information_elements,
    }
}
fn reply(subtype: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = management(subtype, AP, OWN);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(body);
    frame
}
fn mt76_join_plan_encodes_rates_and_exact_wpa2_rsn() -> TestResult {
    let mut plan = JoinPlan::prepare(
        &bss(true),
        OWN,
        b"narf",
        Security::Wpa2Psk { psk: [0x55; 32] },
    )
    .unwrap();
    if plan.peer_record(42, true) != Err(Error::Busy) {
        return TestResult::Fail("station marked associated before AP response");
    }
    let initial = plan.peer_record(0, false).unwrap();
    if initial[16] != 2 || initial[64] != 0 || initial[18..20] != [0, 0] {
        return TestResult::Fail("initial firmware peer differs from Linux sta_add NONE state");
    }
    let auth = plan.start_authentication().unwrap().to_vec();
    if auth.len() != 30
        || auth[24..] != [0, 0, 1, 0, 0, 0]
        || auth[4..10] != AP
        || auth[10..16] != OWN
    {
        return TestResult::Fail("open auth frame");
    }
    let assoc = plan
        .authentication_response(&reply(0xb0, &[0, 0, 2, 0, 0, 0]))
        .unwrap()
        .unwrap();
    if assoc[..2] != [0, 0]
        || assoc[24..28] != [0x11, 0, 5, 0]
        || assoc[28..40] != [0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96]
    {
        return TestResult::Fail("association missing SSID/rates/privacy");
    }
    if assoc[40] != 48 || RsnIe::decode_body(&assoc[42..]) != Some(RsnIe::wpa2_psk_ccmp()) {
        return TestResult::Fail("RSN negotiation differs from exact PSK/CCMP profile");
    }
    if plan.association_response(&reply(
        0x10,
        &[0x11, 0, 0, 0, 42, 0xc0, 1, 4, 0x82, 0x84, 0x8b, 0x96],
    )) != Ok(Some(42))
        || plan.phase() != (Phase::Associated { aid: 42 })
    {
        return TestResult::Fail("association response state");
    }
    let record = plan.peer_record(42, true).unwrap();
    if record.len() != 120
        || record[..8] != [0, 1, 5, 0, 1, 0, 0, 0]
        || record[8..16] != [0, 0, 20, 0, 2, 0, 1, 0]
        || record[16] != 2
        || record[64] != 2
        || record[18..20] != [42, 0]
        || record[20..26] != AP
        || record[26..28] != [1, 0]
        || record[68..80] != [13, 0, 52, 0, 1, 1, 3, 0, 0, 0, 0, 0]
        || record[112..120] != [6, 0, 8, 0, 1, 0, 1, 0]
    {
        return TestResult::Fail("station/WTBL layout or firmware enabled-peer state");
    }
    let key = [0xabu8; 16];
    let sec_rec = plan.secure_peer_record(42, &key).unwrap();
    if sec_rec.len() != 164
        || sec_rec[..8] != [0, 1, 6, 0, 1, 0, 0, 0]
        || sec_rec[120..128] != [17, 0, 44, 0, 0, 1, 0, 0]
        || sec_rec[128..132] != [5, 36, 0, 16]
        || sec_rec[132..148] != key
        || sec_rec[16] != 2
        || sec_rec[64] != 2
    {
        return TestResult::Fail("secure_peer_record STA_REC_KEY_V2 layout mismatch");
    }
    for len in [0, 1, 15, 17, 32] {
        if plan.secure_peer_record(42, &vec![0x55; len]).is_ok() {
            return TestResult::Fail("short/long CCMP key silently truncated or zero-padded");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_join_plan_encodes_rates_and_exact_wpa2_rsn
);
fn mt76_join_plan_rejects_downgrades_and_unsupported_basic_rates() -> TestResult {
    if !matches!(
        JoinPlan::prepare(&bss(true), OWN, b"narf", Security::Open),
        Err(Error::UnsupportedSecurity)
    ) || !matches!(
        JoinPlan::prepare(
            &bss(false),
            OWN,
            b"narf",
            Security::Wpa2Psk { psk: [0x55; 32] }
        ),
        Err(Error::UnsupportedSecurity)
    ) || !matches!(
        JoinPlan::prepare(
            &bss(true),
            OWN,
            b"wrong",
            Security::Wpa2Psk { psk: [0x55; 32] }
        ),
        Err(Error::InvalidBss)
    ) {
        return TestResult::Fail("SSID/security downgrade accepted");
    }
    let mut ap = bss(true);
    let mut rsn = RsnIe::wpa2_psk_ccmp();
    rsn.rsn_capabilities |= rsn::RSN_CAP_MFP_REQUIRED;
    ap.information_elements.truncate(15);
    let body = rsn.encode_body();
    ap.information_elements
        .extend_from_slice(&[48, body.len() as u8]);
    ap.information_elements.extend_from_slice(&body);
    if !matches!(
        JoinPlan::prepare(&ap, OWN, b"narf", Security::Wpa2Psk { psk: [0x55; 32] }),
        Err(Error::UnsupportedSecurity)
    ) {
        return TestResult::Fail("mandatory PMF silently ignored");
    }
    let mut ap = bss(false);
    ap.information_elements[8] = 0xff;
    if !matches!(
        JoinPlan::prepare(&ap, OWN, b"narf", Security::Open),
        Err(Error::UnsupportedRates)
    ) {
        return TestResult::Fail("unknown mandatory rate accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_join_plan_rejects_downgrades_and_unsupported_basic_rates
);
fn mt76_join_responses_bind_peer_phase_status_and_aid() -> TestResult {
    let mut plan = JoinPlan::prepare(&bss(false), OWN, b"narf", Security::Open).unwrap();
    plan.start_authentication().unwrap();
    let mut wrong = reply(0xb0, &[0, 0, 2, 0, 0, 0]);
    wrong[10] = 4;
    if plan.authentication_response(&wrong) != Ok(None)
        || plan.phase() != Phase::AwaitAuthentication
    {
        return TestResult::Fail("wrong peer advanced authentication");
    }
    if plan.authentication_response(&reply(0xb0, &[0, 0, 2, 0, 17, 0])) != Err(Error::Rejected(17))
        || plan.phase() != Phase::Failed
    {
        return TestResult::Fail("AP rejection lost");
    }
    if plan.start_authentication() != Err(Error::Busy) {
        return TestResult::Fail("failed join replayed");
    }
    let mut plan = JoinPlan::prepare(&bss(false), OWN, b"narf", Security::Open).unwrap();
    plan.start_authentication().unwrap();
    plan.authentication_response(&reply(0xb0, &[0, 0, 2, 0, 0, 0]))
        .unwrap();
    if plan.association_response(&reply(0x10, &[1, 0, 0, 0, 0, 0xc0])) != Err(Error::Protocol)
        || plan.phase() != Phase::Failed
    {
        return TestResult::Fail("zero AID accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_join_responses_bind_peer_phase_status_and_aid
);
fn mt76_join_truncated_response_and_cancel_cannot_advance() -> TestResult {
    for length in 24..30 {
        let mut plan = JoinPlan::prepare(&bss(false), OWN, b"narf", Security::Open).unwrap();
        plan.start_authentication().unwrap();
        let response = reply(0xb0, &[0, 0, 2, 0, 0, 0]);
        if plan.authentication_response(&response[..length]) != Err(Error::Protocol) {
            return TestResult::Fail("truncated matching auth response");
        }
    }
    let mut plan = JoinPlan::prepare(&bss(false), OWN, b"narf", Security::Open).unwrap();
    plan.start_authentication().unwrap();
    plan.cancel();
    if plan.authentication_response(&reply(0xb0, &[0, 0, 2, 0, 0, 0])) != Err(Error::Busy)
        || plan.peer_record(0, false) != Err(Error::Busy)
    {
        return TestResult::Fail("cancelled join resumed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_join_truncated_response_and_cancel_cannot_advance
);
fn mt76_disconnect_record_layout() -> TestResult {
    let disc = disconnect_record(AP);
    if disc.len() != 40
        || disc[..8] != [0, 1, 2, 0, 1, 0, 0, 0]
        || disc[8..16] != [0, 0, 20, 0, 2, 0, 1, 0]
        || disc[16] != 0
        || disc[26..28] != [1, 0]
        || disc[20..26] != AP
        || disc[28..36] != [13, 0, 12, 0, 1, 1, 0, 0]
        || disc[36] != 0
    {
        return TestResult::Fail("disconnect STA_REC wire layout");
    }
    if group_disconnect_record()
        != [
            0, 19, 1, 0, 1, 14, 0, 0, 13, 0, 12, 0, 19, 1, 0, 0, 0, 0, 0, 0,
        ]
    {
        return TestResult::Fail("BMC WTBL reset does not match NULL-station update");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_disconnect_record_layout
);

fn mt76_group_wtbl_and_key_request_match_linux_null_station() -> TestResult {
    let group = group_record(AP, 42).unwrap();
    if group.len() != 60
        || group[..20]
            != [
                0, 19, 1, 0, 1, 14, 0, 0, 13, 0, 52, 0, 19, 1, 3, 0, 0, 0, 0, 0,
            ]
        || group[20..24] != [0, 0, 20, 0]
        || group[24..30] != AP
        || group[30..40] != [14, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        || group[40..52] != [1, 0, 12, 0, 0, 1, 1, 1, 0, 0, 0, 0]
        || group[52..] != [6, 0, 8, 0, 1, 0, 1, 0]
    {
        return TestResult::Fail("VIF/BMC native RX WTBL layout");
    }
    let record = key_record(19, 2, Some(&[0x77; 16])).unwrap();
    if record.len() != 52
        || record[..20]
            != [
                0, 19, 1, 0, 1, 14, 0, 0, 17, 0, 44, 0, 0, 1, 0, 0, 5, 36, 2, 16,
            ]
        || record[20..36] != [0x77; 16]
        || record[36..] != [0; 16]
    {
        return TestResult::Fail("group key MCU request geometry/index/MUAR");
    }
    // mt7921/main.c::mt7921_set_key selects Unified STA_REC_UPDATE;
    // mt76_connac_mcu_sta_key_tlv uses KEY_V2 (17), never MURU (18),
    // and copies enum set_key_cmd: SET_KEY=0, DISABLE_KEY=1.
    let pairwise = key_record(1, 0, Some(&[0x66; 16])).unwrap();
    if pairwise.len() != 52
        || pairwise[..20]
            != [
                0, 1, 1, 0, 1, 0, 0, 0, 17, 0, 44, 0, 0, 1, 0, 0, 5, 36, 0, 16,
            ]
        || pairwise[20..36] != [0x66; 16]
        || pairwise[36..] != [0; 16]
        || key_record(1, 0, None).unwrap() != [0, 1, 1, 0, 1, 0, 0, 0, 17, 0, 8, 0, 1, 0, 0, 0]
        || key_record(19, 0, None).unwrap() != [0, 19, 1, 0, 1, 14, 0, 0, 17, 0, 8, 0, 1, 0, 0, 0]
    {
        return TestResult::Fail("pairwise install or PTK/GTK removal uses wrong native key TLV");
    }
    if key_record(1, 1, Some(&[0; 16])).is_ok()
        || key_record(19, 4, Some(&[0; 16])).is_ok()
        || key_record(19, 0, Some(&[0; 15])).is_ok()
    {
        return TestResult::Fail("invalid CCMP key request accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_group_wtbl_and_key_request_match_linux_null_station
);

fn mt76_sme_ies_bind_security_and_reach_native_assoc_once() -> TestResult {
    let canonical = RsnIe::wpa2_psk_ccmp().encode_body();
    let mut requested = vec![48, canonical.len() as u8];
    requested.extend_from_slice(&canonical);
    let vendor = [221, 5, 0, 1, 2, 3, 4];
    requested.extend_from_slice(&vendor);
    let mut plan =
        JoinPlan::prepare(&bss(true), OWN, b"narf", Security::Wpa2Psk { psk: [7; 32] }).unwrap();
    if plan.append_sme_ies(&requested).is_err() {
        return TestResult::Fail("canonical offload IE rejected");
    }
    plan.start_authentication().unwrap();
    if plan.append_sme_ies(&[]).is_ok() {
        return TestResult::Fail("association elements changed after auth publication");
    }
    let assoc = plan
        .authentication_response(&reply(0xb0, &[0, 0, 2, 0, 0, 0]))
        .unwrap()
        .unwrap();
    if !assoc.ends_with(&vendor) {
        return TestResult::Fail("optional SME IE dropped");
    }
    let mut rsns = 0;
    if ies(&assoc[28..], |id, _| {
        rsns += usize::from(id == 48);
        Ok(())
    })
    .is_err()
        || rsns != 1
    {
        return TestResult::Fail("SME RSNE duplicated rather than negotiated");
    }
    if validate_sme_ies(&requested, false) != Err(Error::UnsupportedSecurity) {
        return TestResult::Fail("RSNE accepted for open connection");
    }
    for bytes in [&[48, 20, 1][..], &[255, 0], &[221, 2, 0, 1], &[0, 1, 0]] {
        if validate_sme_ies(bytes, true) != Err(Error::InvalidBss) {
            return TestResult::Fail("malformed or generated SME IE accepted");
        }
    }
    for bytes in [
        &[244, 1, 0][..],
        &[54, 3, 0, 0, 0],
        &[45, 1, 0],
        &[221, 4, 0, 0x50, 0xf2, 1],
    ] {
        if validate_sme_ies(bytes, true).is_ok() {
            return TestResult::Fail("unsupported security/PHY request silently discarded");
        }
    }
    let mut pmf = RsnIe::wpa2_psk_ccmp();
    pmf.rsn_capabilities = rsn::RSN_CAP_MFP_REQUIRED;
    let mut group = RsnIe::wpa2_psk_ccmp();
    group.group_cipher = Suite::standard(rsn::CIPHER_TKIP);
    let mut cached = RsnIe::wpa2_psk_ccmp();
    cached.pmkids.push([7; 16]);
    for rsn in [RsnIe::wpa3_sae_ccmp(), pmf, group, cached] {
        let body = rsn.encode_body();
        let mut bytes = vec![48, body.len() as u8];
        bytes.extend_from_slice(&body);
        if validate_sme_ies(&bytes, true) != Err(Error::UnsupportedSecurity) {
            return TestResult::Fail("unsupported requested RSNA downgraded");
        }
    }
    let mut duplicate = requested.clone();
    duplicate.extend_from_slice(&requested);
    if validate_sme_ies(&duplicate, true) != Err(Error::InvalidBss) {
        return TestResult::Fail("duplicate RSNE accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_sme_ies_bind_security_and_reach_native_assoc_once
);

fn mt76_all_legacy_basic_rates_encode_native_txd_and_band_records() -> TestResult {
    // Independent literal Linux mt76_rates values: CCK0..3, OFDM hardware codes.
    let hardware = [0u16, 1, 2, 3, 75, 79, 74, 78, 73, 77, 72, 76];
    for (index, (&rate, &expected)) in RATES.iter().zip(hardware.iter()).enumerate() {
        for channel in [6, 36] {
            let mut ap = bss(false);
            ap.channel = channel;
            ap.information_elements = vec![
                0,
                4,
                b'n',
                b'a',
                b'r',
                b'f',
                1,
                1,
                rate | 128,
                3,
                1,
                channel,
            ];
            let result = JoinPlan::prepare(&ap, OWN, b"narf", Security::Open);
            if channel == 36 && index < 4 {
                if !matches!(result, Err(Error::UnsupportedRates)) {
                    return TestResult::Fail("5 GHz accepted mandatory CCK");
                }
                continue;
            }
            let mut plan = match result {
                Ok(plan) => plan,
                Err(_) => return TestResult::Fail("supported basic rate rejected"),
            };
            let selected = plan.management_rate();
            let auth = plan.start_authentication().unwrap();
            let txd = super::super::packet_tx::management(auth, 0x1000, 1, 1, selected).unwrap();
            if u32::from_le_bytes(txd[24..28].try_into().unwrap())
                != 4 | (u32::from(expected) << 16)
            {
                return TestResult::Fail("basic rate did not reach native TXD6");
            }
            let record = plan.peer_record(0, false).unwrap();
            let expected_basic = 1u16 << if channel == 36 { index - 4 } else { index };
            if record[32..34] != expected_basic.to_le_bytes()
                || record[34] != if channel == 36 { 8 } else { 3 }
            {
                return TestResult::Fail("band-local STA PHY/basic rates");
            }
            let record = bss_record(&ap, false).unwrap();
            if record[29] != if channel == 36 { 1 } else { 6 }
                || record[32] != if channel == 36 { 8 } else { 3 }
            {
                return TestResult::Fail("band-specific BSS PHY mode");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_all_legacy_basic_rates_encode_native_txd_and_band_records
);

fn mt76_response_rates_reach_peer_records_and_management_rate() -> TestResult {
    let mut ap = bss(false);
    // Bitmap order places CCK11Mbps before OFDM6Mbps. Both are basic;
    // 12/54Mbps are optional offers that the association response removes.
    ap.information_elements = vec![0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x96, 0x8c, 24, 108];
    let mut plan = JoinPlan::prepare(&ap, OWN, b"narf", Security::Open).unwrap();
    if plan.management_rate().hardware() != 75 {
        return TestResult::Fail("bitmap order selected 11Mbps ahead of actual lower6Mbps");
    }
    let before = plan.peer_record(0, false).unwrap();
    if before[44..46] != [0x48, 0x21] {
        return TestResult::Fail("initial legacy offer differs from literal CONNAC2 rate map");
    }
    plan.start_authentication().unwrap();
    plan.authentication_response(&reply(0xb0, &[0, 0, 2, 0, 0, 0]))
        .unwrap();
    if plan.association_response(&reply(0x10, &[1, 0, 0, 0, 42, 0xc0, 1, 2, 0x96, 0x8c]))
        != Ok(Some(42))
    {
        return TestResult::Fail("supported AP rate downgrade rejected");
    }
    let after = plan.peer_record(42, true).unwrap();
    if after[32..34] != [0x18, 0]
        || after[44..46] != [0x48, 0]
        || plan.management_rate().hardware() != 75
    {
        return TestResult::Fail("firmware peer retained stale scan-time supported/basic rates");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_response_rates_reach_peer_records_and_management_rate
);

fn mt76_uni_station_records_per_link() -> TestResult {
    use crate::mt7925::mcu::{
        MldLink, MldLinks, STA_REC_BASIC_TLV_SIZE, STA_REC_STATE_TLV_SIZE, STA_REQ_HDR_SIZE,
    };
    let mut plan = JoinPlan::prepare(&bss(false), OWN, b"narf", Security::Open).unwrap();
    // Pre-association add: BASIC + STATE, tlv_num 2, STATE NONE.
    let add = plan.peer_record_uni_on(Link::HOME, 0, false, None).unwrap();
    if add.len() != STA_REQ_HDR_SIZE + STA_REC_BASIC_TLV_SIZE + STA_REC_STATE_TLV_SIZE
        || u16::from_le_bytes([add[2], add[3]]) != 2
        || add[16] != 2
        || add[36] != 0
    {
        return TestResult::Fail("UNI pre-association station record wrong");
    }
    // Associated add before the AP response is Busy, as for CONNAC2.
    if plan.peer_record_uni_on(Link::HOME, 42, true, None) != Err(Error::Busy) {
        return TestResult::Fail("UNI station record associated before AP response");
    }
    plan.start_authentication().unwrap();
    plan.authentication_response(&reply(0xb0, &[0, 0, 2, 0, 0, 0]))
        .unwrap();
    // The response's Supported Rates must repeat the BSS's basic set
    // (`bss(false)` advertises 1/2/5.5/11): `negotiate_response`
    // refuses any basic rate missing from the negotiated intersection,
    // so the rates-test reply bytes (11/6 Mbps) do not work here.
    if plan.association_response(&reply(
        0x10,
        &[1, 0, 0, 0, 42, 0xc0, 1, 4, 0x82, 0x84, 0x8b, 0x96],
    )) != Ok(Some(42))
    {
        return TestResult::Fail("UNI test association response rejected");
    }
    let mld = MldLinks {
        own_mac: OWN,
        primary: MldLink {
            wcid_idx: 1,
            bss_idx: 0,
        },
        secondary: Some(MldLink {
            wcid_idx: 2,
            bss_idx: 1,
        }),
        eml_cap: 0,
        emlsr: false,
    };
    let assoc = plan
        .peer_record_uni_on(Link::HOME, 42, true, Some(mld))
        .unwrap();
    if assoc.len() != 84 || u16::from_le_bytes([assoc[2], assoc[3]]) != 4 || assoc[36] != 2 {
        return TestResult::Fail("UNI associated MLD station record wrong");
    }
    // Remove: hdr + REMOVE + MLD_OFF, valid from any phase.
    let remove = plan.sta_remove_uni_on(Link::HOME);
    if remove.len() != 20 || u16::from_le_bytes([remove[2], remove[3]]) != 2 {
        return TestResult::Fail("UNI station remove record wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_uni_station_records_per_link
);

fn mt76_uni_bss_record_per_link() -> TestResult {
    use crate::mt7925::mcu::{
        UniBssHe, UniBssMld, UniBssRlm, UniBssSec, BSS_SEC_MODE_OPEN, RLM_BAND_2G, RLM_BW_20,
        UNI_BSS_UPDATE_BOUND,
    };
    let sec = UniBssSec {
        mode: BSS_SEC_MODE_OPEN,
        status: 1,
        cipher: 0,
    };
    let mld = UniBssMld {
        is_mld: false,
        link_id: 0,
        primary_bss_idx: 0,
        own_mac: OWN,
        eml_enable: false,
    };
    // Disconnected (disable) with no HE: no HE/COLOR/RLM/MBSSID,
    // conn_state 1. Bound minus HE 16, COLOR 8, RLM 16, MBSSID 8.
    let off = bss_record_uni_on(Link::HOME, &bss(false), false, sec, mld, None, None, 20).unwrap();
    if off.len() != UNI_BSS_UPDATE_BOUND - 48 || off[4 + 12] != 1 {
        return TestResult::Fail("UNI BSS record (disable) wrong");
    }
    // Connected 2.4 GHz: BASIC phymode 6, non-HT 3, basic rate 0x000f.
    let rlm = UniBssRlm {
        control_channel: 6,
        center_chan: 6,
        center_chan2: 0,
        bw: RLM_BW_20,
        tx_streams: 2,
        rx_streams: 2,
        band: RLM_BAND_2G,
    };
    let on = bss_record_uni_on(
        Link::HOME,
        &bss(false),
        true,
        sec,
        mld,
        Some(UniBssHe {
            pe_duration: 4,
            rts_thres: 1023,
            max_nss_mcs: [0, 0, 0],
            color_enabled: false,
            color: 0,
        }),
        Some(rlm),
        20,
    )
    .unwrap();
    if on.len() != UNI_BSS_UPDATE_BOUND || on[4 + 12] != 0 {
        return TestResult::Fail("UNI BSS record (enable) wrong");
    }
    // BASIC at 4: phymode 6 at +25, nonht 3 at +28..30, link_idx 0.
    if on[4 + 25] != 6 || u16::from_le_bytes([on[4 + 28], on[4 + 29]]) != 3 {
        return TestResult::Fail("UNI BSS record 2.4 GHz PHY fields wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/association",
    mt76_uni_bss_record_per_link
);
