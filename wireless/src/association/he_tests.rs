use super::*;
use crate::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy, LocalVht};
use crate::association::{Bss, JoinPlan, SecurityMode};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
macro_rules! check {
    ($condition:expr, $message:literal) => {
        if !$condition {
            return Err($message);
        }
    };
}
macro_rules! smoke {
    ($name:ident, $body:ident) => {
        fn $name() -> TestResult {
            match $body() {
                Ok(()) => TestResult::Pass,
                Err(error) => TestResult::Fail(error),
            }
        }
        kernel_test_in!("wireless/association/he", $name);
    };
}
fn ht40() -> LocalHt {
    let gi = HtGi {
        rx20: true,
        tx20: true,
        rx40: true,
        tx40: true,
    };
    let mcs = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    LocalHt::new(mcs, mcs, HtWidth::TwentyForty, gi, 0, 0).unwrap()
}
/// Two-stream MCS0-11 HE station: HTC-HE, TWT requester, 40MHz in 2.4GHz,
/// 40/80MHz in 5GHz, LDPC, STBC RX/TX, SU beamformee.
fn phy() -> [u8; 11] {
    let mut phy = [0; 11];
    phy[0] = PHY0_40_2G | PHY0_40_80_5G;
    phy[1] = PHY1_LDPC;
    phy[2] = PHY2_STBC_TX | PHY2_STBC_RX;
    phy[4] = PHY4_SU_BEAMFORMEE;
    phy
}
fn local_he() -> LocalHe {
    LocalHe::new(
        [MAC0_HTC_HE | MAC0_TWT_REQ, 0, 0, 0, 0, 0],
        phy(),
        0xfffa,
        0xfffa,
    )
    .unwrap()
}
fn local(he: LocalHe, vht160: bool) -> LocalPhy {
    let vht = LocalVht::new(0xfffe, 0xfffe, true, true, 0).unwrap();
    if vht160 {
        LocalPhy::vht160(ht40(), vht.with_160mhz(true, true))
    } else {
        LocalPhy::vht80(ht40(), vht)
    }
    .unwrap()
    .with_he(he)
    .unwrap()
}
/// AP HE capability: one stream (MCS0-9) RX, two streams TX, LDPC, STBC RX,
/// SU beamformer, TWT responder, optional160 support.
fn ap_cap(width160: bool) -> Vec<u8> {
    let mut body = vec![
        EXT_HE_CAPABILITIES,
        MAC0_HTC_HE | MAC0_TWT_RES,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut phy = [0; 11];
    phy[0] = PHY0_40_80_5G | if width160 { PHY0_160_5G } else { 0 };
    phy[1] = PHY1_LDPC;
    phy[2] = PHY2_STBC_RX;
    phy[3] = PHY3_SU_BEAMFORMER;
    body.extend_from_slice(&phy);
    body.extend_from_slice(&[0xfd, 0xff, 0xfa, 0xff]);
    if width160 {
        body.extend_from_slice(&[0xfc, 0xff, 0xfc, 0xff]);
    }
    body
}
fn ap_op(basic: u16, color: u8) -> Vec<u8> {
    let params: u32 = 4 | 1023 << 4 | u32::from(color) << 24;
    let mut body = vec![EXT_HE_OPERATION];
    body.extend_from_slice(&params.to_le_bytes());
    body.extend_from_slice(&basic.to_le_bytes());
    body
}
fn element(bytes: &mut Vec<u8>, id: u8, body: &[u8]) {
    bytes.extend_from_slice(&[id, body.len() as u8]);
    bytes.extend_from_slice(body);
}
/// 5GHz channel36 VHT80 (or160 at center50) AP with optional HE elements.
fn ap(he: Option<(Vec<u8>, Vec<u8>)>, width160: bool, selector: Option<u8>) -> Bss {
    let mut bytes = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x8c, 0x98, 0xb0];
    if let Some(selector) = selector {
        element(&mut bytes, 50, &[selector]);
    }
    element(&mut bytes, 45, &ht40().capability_body());
    let mut op = [0; 22];
    op[0] = 36;
    op[1] = 5;
    element(&mut bytes, 61, &op);
    let vht = LocalVht::new(0xfffe, 0xfffe, true, true, 0).unwrap();
    let vht = if width160 {
        vht.with_160mhz(true, true)
    } else {
        vht
    };
    element(&mut bytes, 191, &vht.capability_body());
    element(
        &mut bytes,
        192,
        &if width160 {
            [1, 42, 50, 0xfc, 0xff]
        } else {
            [1, 42, 0, 0xfc, 0xff]
        },
    );
    if let Some((cap, op)) = he {
        element(&mut bytes, 255, &cap);
        element(&mut bytes, 255, &op);
    }
    Bss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 36,
        band: None,
        signal_dbm: None,
        capability: 1,
        beacon_interval: 100,
        information_elements: bytes,
    }
}
fn he_ap() -> Bss {
    ap(Some((ap_cap(false), ap_op(0xfffc, 5))), false, None)
}
fn response(ap: &Bss) -> Vec<u8> {
    let mut bytes = vec![0; 30];
    bytes[0] = 0x10;
    bytes[4..10].copy_from_slice(&OWN);
    bytes[10..16].copy_from_slice(&AP);
    bytes[16..22].copy_from_slice(&AP);
    bytes[24] = 1;
    bytes[28] = 7;
    bytes[29] = 0xc0;
    bytes.extend_from_slice(&ap.information_elements);
    bytes
}
fn prepare(ap: &Bss, local: LocalPhy) -> Result<JoinPlan, Error> {
    JoinPlan::prepare_with_phy(ap, OWN, b"narf", SecurityMode::Open, local)
}
fn ready(ap: &Bss, local: LocalPhy) -> JoinPlan {
    let mut plan = prepare(ap, local).unwrap();
    plan.start_authentication().unwrap();
    let mut auth = vec![0; 30];
    auth[0] = 0xb0;
    auth[4..10].copy_from_slice(&OWN);
    auth[10..16].copy_from_slice(&AP);
    auth[16..22].copy_from_slice(&AP);
    auth[26] = 2;
    plan.authentication_response(&auth).unwrap().unwrap();
    plan
}

fn capability_wire() -> Result<(), &'static str> {
    let cap = HeCapability::parse(&ap_cap(true)[1..]).map_err(|_| "valid 160 capability")?;
    check!(
        cap.mcs_nss().rx160 == 0xfffc && cap.mcs_nss().rx80p80 == 0xffff,
        "160 MCS/NSS maps misplaced"
    );
    check!(cap.body() == ap_cap(true), "capability did not round-trip");
    let mut long = ap_cap(false);
    long.push(0);
    check!(
        HeCapability::parse(&long[1..]).is_err(),
        "trailing octet accepted"
    );
    let mut short = ap_cap(true);
    short.truncate(short.len() - 2);
    check!(
        HeCapability::parse(&short[1..]).is_err(),
        "truncated160 maps accepted"
    );
    // PPE: one NSS (header bits0..2 = 0), RU bitmask 0b0011 -> 2*1*6+7=19 bits = 3 bytes.
    let mut ppe = ap_cap(false);
    ppe[7 + 6] |= PHY6_PPE_PRESENT;
    ppe.extend_from_slice(&[0x18, 0x1c, 0x07]);
    let parsed = HeCapability::parse(&ppe[1..]).map_err(|_| "valid PPE thresholds")?;
    check!(
        parsed.ppe_thresholds() == [0x18, 0x1c, 0x07] && parsed.body() == ppe,
        "PPE thresholds lost"
    );
    ppe.pop();
    check!(
        HeCapability::parse(&ppe[1..]).is_err(),
        "short PPE thresholds accepted"
    );
    check!(
        ppe_size(0x7f) == 25 && ppe_size(0x08) == 2 && ppe_size(0x18) == 3,
        "ppe size differs from ieee80211_he_ppe_size"
    );
    Ok(())
}
smoke!(smoke_he_capability_extents_and_ppe, capability_wire);

fn operation_wire() -> Result<(), &'static str> {
    let op = HeOperation::parse(&ap_op(0xfffc, 37)[1..]).map_err(|_| "valid operation")?;
    check!(
        op.bss_color() == 37
            && !op.bss_color_disabled()
            && op.default_pe_duration() == 4
            && op.txop_rts_threshold() == 1023
            && op.basic_mcs_nss() == 0xfffc
            && op.vht_operation_information().is_none(),
        "operation facts differ"
    );
    let mut with_vht = ap_op(0xfffc, 1);
    with_vht[2] |= 0x40; // VHT Operation Information Present (bit14).
    with_vht[3] |= 0x01; // ER SU Disable (bit16).
    check!(
        HeOperation::parse(&with_vht[1..]).is_err(),
        "missing VHT Operation Information accepted"
    );
    with_vht.extend_from_slice(&[1, 42, 0]);
    let op = HeOperation::parse(&with_vht[1..]).map_err(|_| "VHT info operation")?;
    check!(
        op.vht_operation_information() == Some([1, 42, 0]) && op.er_su_disabled(),
        "VHT information lost"
    );
    let mut cohosted = ap_op(0xfffc, 1);
    cohosted[2] |= 0x80;
    cohosted.push(3);
    check!(
        HeOperation::parse(&cohosted[1..])
            .is_ok_and(|op| op.max_co_hosted_bssid_indicator() == Some(3)),
        "co-hosted indicator lost"
    );
    let mut six = ap_op(0xfffc, 1);
    six[3] |= 0x02; // 6GHz Operation Information Present (bit17).
    six.extend_from_slice(&[1, 0, 7, 0, 6]);
    check!(
        HeOperation::parse(&six[1..]).is_err(),
        "six-GHz operation admitted on a 2.4/5GHz plan"
    );
    Ok(())
}
smoke!(smoke_he_operation_extents_and_facts, operation_wire);

fn local_validation() -> Result<(), &'static str> {
    let mac = [0; 6];
    check!(
        LocalHe::new(mac, phy(), 0xffff, 0xfffa).is_err()
            && LocalHe::new(mac, phy(), 0xfffa, 0xfff3 | 3).is_err(),
        "missing single-stream MCS0-7 accepted"
    );
    let mut bad = phy();
    bad[0] |= PHY0_160_5G;
    check!(
        LocalHe::new(mac, bad, 0xfffa, 0xfffa).is_err(),
        "caller-owned 160 bit accepted"
    );
    let mut bad = phy();
    bad[4] |= PHY4_MU_BEAMFORMER;
    check!(
        LocalHe::new(mac, bad, 0xfffa, 0xfffa).is_err(),
        "AP-only MU beamformer accepted"
    );
    let mut narrow = phy();
    narrow[0] = 0;
    check!(
        LocalHe::new(mac, narrow, 0xfffa, 0xfffa)
            .unwrap()
            .with_160mhz(0xfffa, 0xfffa)
            .is_err(),
        "160 without 80MHz support accepted"
    );
    check!(
        local_he().with_80p80(0xfffa, 0xfffa).is_err(),
        "80+80 without160 accepted"
    );
    check!(
        local_he().with_ppe_thresholds(&[0x08, 0, 0, 0]).is_err()
            && local_he().with_ppe_thresholds(&[0x00]).is_err(),
        "mis-sized PPE accepted"
    );
    let wide = local_he().with_160mhz(0xfffa, 0xfffa).unwrap();
    check!(
        LocalPhy::vht80(
            ht40(),
            LocalVht::new(0xfffe, 0xfffe, true, true, 0).unwrap()
        )
        .unwrap()
        .with_he(wide)
        .is_err(),
        "HE160 without VHT160 accepted"
    );
    let body = wide.capability_body();
    check!(
        body.len() == 1 + 6 + 11 + 8 && body[7] & PHY0_160_5G != 0,
        "HE160 body layout"
    );
    Ok(())
}
smoke!(smoke_he_local_profile_validation, local_validation);

fn offer_and_response() -> Result<(), &'static str> {
    let scan = he_ap();
    let plan = prepare(&scan, local(local_he(), false)).map_err(|_| "HE AP rejected")?;
    let offer = plan.offered_phy().unwrap();
    let he = offer.he().ok_or("HE not negotiated")?;
    check!(
        he.width() == Width::Eighty
            && he.tx_mcs_map() == 0xfffd
            && he.rx_mcs_map() == 0xfffa
            && he.operation().bss_color() == 5,
        "HE width/maps differ from mac80211 intersection"
    );
    check!(
        he.tx_ldpc()
            && he.rx_ldpc()
            && he.tx_stbc()
            && he.su_beamformee()
            && !he.su_beamformer()
            && !he.mu_beamformee()
            && he.htc_he()
            && he.twt_requester(),
        "HE directional features differ"
    );
    let mut plan = ready(&scan, local(local_he(), false));
    let assoc = {
        let mut probe = prepare(&scan, local(local_he(), false)).unwrap();
        probe.start_authentication().unwrap();
        let mut auth = vec![0; 30];
        auth[0] = 0xb0;
        auth[4..10].copy_from_slice(&OWN);
        auth[10..16].copy_from_slice(&AP);
        auth[16..22].copy_from_slice(&AP);
        auth[26] = 2;
        probe
            .authentication_response(&auth)
            .unwrap()
            .unwrap()
            .to_vec()
    };
    let body = local_he().capability_body();
    let mut needle = vec![255, body.len() as u8];
    needle.extend_from_slice(&body);
    check!(
        assoc.windows(needle.len()).any(|w| w == needle.as_slice()),
        "association request lacks the HE Capabilities element"
    );
    check!(
        plan.association_response(&response(&scan)) == Ok(Some(7)),
        "HE response rejected"
    );
    check!(
        plan.negotiated_phy().and_then(|n| n.he()).is_some(),
        "negotiated HE missing"
    );
    // A response that drops HE fails closed like mac80211.
    let mut plan = ready(&scan, local(local_he(), false));
    check!(
        plan.association_response(&response(&ap(None, false, None)))
            .is_err()
            && plan.negotiated_phy().is_none(),
        "response without HE admitted"
    );
    // A response cannot enable transmit LDPC absent from the scan offer.
    let mut no_ldpc = ap_cap(false);
    no_ldpc[7 + 1] &= !PHY1_LDPC;
    let scan = ap(Some((no_ldpc, ap_op(0xfffc, 5))), false, None);
    let mut plan = ready(&scan, local(local_he(), false));
    check!(
        plan.association_response(&response(&he_ap())) == Ok(Some(7))
            && !plan.negotiated_phy().unwrap().he().unwrap().tx_ldpc(),
        "response expanded HE TX LDPC"
    );
    Ok(())
}
smoke!(
    smoke_he_offer_request_response_and_narrowing,
    offer_and_response
);

fn selectors_and_fallback() -> Result<(), &'static str> {
    let required = ap(Some((ap_cap(false), ap_op(0xfffc, 5))), false, Some(0xfa));
    check!(
        prepare(&required, local(local_he(), false)).is_ok(),
        "HE selector rejected with HE"
    );
    let no_he = LocalPhy::vht80(
        ht40(),
        LocalVht::new(0xfffe, 0xfffe, true, true, 0).unwrap(),
    )
    .unwrap();
    check!(
        prepare(&required, no_he).is_err(),
        "HE selector admitted without local HE"
    );
    // Basic HE-MCS set: three streams required, the station has two.
    let strict = ap(Some((ap_cap(false), ap_op(0xffc0, 5))), false, None);
    let plan = prepare(&strict, local(local_he(), false)).map_err(|_| "VHT fallback")?;
    check!(
        plan.offered_phy().unwrap().he().is_none() && plan.offered_phy().unwrap().vht().is_some(),
        "unsupported basic HE set did not fall back to VHT"
    );
    let strict = ap(Some((ap_cap(false), ap_op(0xffc0, 5))), false, Some(0xfa));
    check!(
        prepare(&strict, local(local_he(), false)).is_err(),
        "mandatory HE admitted after fallback"
    );
    // AP self-inconsistency: its RX map lacks the basic NSS2 tuple.
    let incoherent = ap(Some((ap_cap(false), ap_op(0xfff0, 5))), false, None);
    check!(
        prepare(&incoherent, local(local_he(), false)).is_ok_and(|p| p
            .offered_phy()
            .unwrap()
            .he()
            .is_none()),
        "AP basic set outside its own maps kept HE"
    );
    // Orphans and HE without HT are malformed.
    let mut orphan = he_ap();
    let cap = ap_cap(false);
    orphan.information_elements = ap(None, false, None).information_elements;
    element(&mut orphan.information_elements, 255, &cap);
    check!(
        prepare(&orphan, local(local_he(), false)).is_err(),
        "orphan HE capability admitted"
    );
    let mut bare = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x8c, 0x98, 0xb0];
    element(&mut bare, 255, &ap_cap(false));
    element(&mut bare, 255, &ap_op(0xfffc, 1));
    let mut no_ht = he_ap();
    no_ht.information_elements = bare;
    check!(
        prepare(&no_ht, local(local_he(), false)).is_err(),
        "HE without HT admitted"
    );
    // Embedded VHT information must agree with the VHT Operation element.
    let mut op = ap_op(0xfffc, 1);
    op[2] |= 0x40;
    op.extend_from_slice(&[1, 58, 0]);
    let mismatch = ap(Some((ap_cap(false), op)), false, None);
    check!(
        prepare(&mismatch, local(local_he(), false)).is_err(),
        "conflicting HE VHT information admitted"
    );
    // Legacy (non-PHY) plans still refuse the HE selector.
    check!(
        JoinPlan::prepare(&required, OWN, b"narf", SecurityMode::Open).is_err(),
        "legacy plan admitted HE selector"
    );
    Ok(())
}
smoke!(
    smoke_he_membership_selector_and_mac80211_fallback,
    selectors_and_fallback
);

fn widths() -> Result<(), &'static str> {
    // 160 BSS: HE160 only when both sides advertise B3.
    let wide_ap = ap(Some((ap_cap(true), ap_op(0xfffc, 5))), true, None);
    let wide = local_he().with_160mhz(0xfffa, 0xfffe).unwrap();
    let plan = prepare(&wide_ap, local(wide, true)).map_err(|_| "160 HE")?;
    let he = plan.offered_phy().unwrap().he().unwrap();
    check!(
        he.width() == Width::OneSixty && he.tx_mcs_map() == 0xfffc,
        "HE160 width/map differs"
    );
    let plan = prepare(&wide_ap, local(local_he(), true)).map_err(|_| "80 HE on160")?;
    check!(
        plan.offered_phy().unwrap().width() == Width::OneSixty
            && plan.offered_phy().unwrap().he().unwrap().width() == Width::Eighty,
        "HE did not narrow to its own80MHz limit"
    );
    // 2.4GHz HT40: HE40 needs both sides' B1; the AP above lacks it.
    let mut bytes = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x82, 0x84, 0x8b];
    element(&mut bytes, 45, &ht40().capability_body());
    let mut op = [0; 22];
    op[0] = 1;
    op[1] = 5;
    element(&mut bytes, 61, &op);
    let mut cap24 = ap_cap(false);
    element(&mut bytes, 255, &cap24);
    element(&mut bytes, 255, &ap_op(0xfffc, 2));
    let mut bss = he_ap();
    bss.channel = 1;
    bss.information_elements = bytes.clone();
    let ht_he = LocalPhy::ht40(ht40()).unwrap().with_he(local_he()).unwrap();
    let plan = prepare(&bss, ht_he).map_err(|_| "2.4GHz HE")?;
    check!(
        plan.offered_phy().unwrap().width() == Width::Forty
            && plan.offered_phy().unwrap().he().unwrap().width() == Width::Twenty,
        "2.4GHz HE40 without AP B1"
    );
    cap24[7] |= PHY0_40_2G;
    bytes.truncate(bytes.len() - (2 + ap_cap(false).len()) - (2 + 7));
    element(&mut bytes, 255, &cap24);
    element(&mut bytes, 255, &ap_op(0xfffc, 2));
    bss.information_elements = bytes;
    let plan = prepare(&bss, ht_he).map_err(|_| "2.4GHz HE40")?;
    check!(
        plan.offered_phy().unwrap().he().unwrap().width() == Width::Forty,
        "2.4GHz HE40 not selected"
    );
    // 5GHz HE requires negotiated VHT: an HT-only local profile skips HE.
    let ht_only = LocalPhy::ht40(ht40()).unwrap().with_he(local_he()).unwrap();
    check!(
        prepare(&he_ap(), ht_only).is_ok_and(|p| p.offered_phy().unwrap().he().is_none()),
        "5GHz HE without VHT"
    );
    Ok(())
}
smoke!(smoke_he_width_limits_follow_both_channel_width_sets, widths);
