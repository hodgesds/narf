use super::*;
use crate::association::he::LocalHe;
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
        kernel_test_in!("wireless/association/eht", $name);
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
/// 5GHz HE profile: 40/80MHz (PHY B2), optional160.
fn he_phy(width160: bool) -> [u8; 11] {
    let mut phy = [0; 11];
    phy[0] = HE_PHY0_40_80_5G | if width160 { HE_PHY0_160_5G } else { 0 };
    phy
}
fn local_eht() -> LocalEht {
    let mut phy = [0; 9];
    phy[0] = PHY0_SU_BEAMFORMEE;
    LocalEht::new([0, 0], phy, [0x22, 0x22, 0x11]).unwrap()
}
fn local(eht: Option<LocalEht>) -> LocalPhy {
    let vht = LocalVht::new(0xfffa, 0xfffa, true, true, 0).unwrap();
    let he = LocalHe::new([0; 6], he_phy(false), 0xfffa, 0xfffa).unwrap();
    let phy = LocalPhy::vht80(ht40(), vht).unwrap().with_he(he).unwrap();
    match eht {
        Some(eht) => phy.with_eht(eht).unwrap(),
        None => phy,
    }
}
fn element(bytes: &mut Vec<u8>, id: u8, body: &[u8]) {
    bytes.extend_from_slice(&[id, body.len() as u8]);
    bytes.extend_from_slice(body);
}
fn he_cap() -> Vec<u8> {
    let mut body = vec![35, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&he_phy(false));
    body.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff]);
    body
}
fn he_op() -> Vec<u8> {
    let mut body = vec![36];
    body.extend_from_slice(&(4u32 | 1023 << 4 | 9 << 24).to_le_bytes());
    body.extend_from_slice(&0xfffcu16.to_le_bytes());
    body
}
fn eht_cap() -> Vec<u8> {
    let mut body = vec![EXT_EHT_CAPABILITIES, 0, 0];
    let mut phy = [0; 9];
    phy[0] = PHY0_SU_BEAMFORMER;
    body.extend_from_slice(&phy);
    body.extend_from_slice(&[0x21, 0x11, 0x00]);
    body
}
fn eht_op(params: u8, basic: [u8; 4], tail: &[u8]) -> Vec<u8> {
    let mut body = vec![EXT_EHT_OPERATION, params];
    body.extend_from_slice(&basic);
    body.extend_from_slice(tail);
    body
}
fn ap(eht: Option<(Vec<u8>, Vec<u8>)>, he: bool, selector: Option<u8>) -> Bss {
    let mut bytes = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x8c, 0x98, 0xb0];
    if let Some(selector) = selector {
        element(&mut bytes, 50, &[selector]);
    }
    element(&mut bytes, 45, &ht40().capability_body());
    let mut op = [0; 22];
    op[0] = 36;
    op[1] = 5;
    element(&mut bytes, 61, &op);
    let vht = LocalVht::new(0xfffa, 0xfffa, true, true, 0).unwrap();
    element(&mut bytes, 191, &vht.capability_body());
    element(&mut bytes, 192, &[1, 42, 0, 0xfc, 0xff]);
    if he {
        element(&mut bytes, 255, &he_cap());
        element(&mut bytes, 255, &he_op());
    }
    if let Some((cap, op)) = eht {
        element(&mut bytes, 255, &cap);
        element(&mut bytes, 255, &op);
    }
    Bss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 36,
        signal_dbm: None,
        capability: 1,
        beacon_interval: 100,
        information_elements: bytes,
    }
}
fn eht_ap() -> Bss {
    ap(
        Some((eht_cap(), eht_op(0, [0x11, 0, 0, 0], &[]))),
        true,
        None,
    )
}
fn prepare(ap: &Bss, local: LocalPhy) -> Result<JoinPlan, Error> {
    JoinPlan::prepare_with_phy(ap, OWN, b"narf", SecurityMode::Open, local)
}
fn ready(ap: &Bss, local: LocalPhy) -> (JoinPlan, Vec<u8>) {
    let mut plan = prepare(ap, local).unwrap();
    plan.start_authentication().unwrap();
    let mut auth = vec![0; 30];
    auth[0] = 0xb0;
    auth[4..10].copy_from_slice(&OWN);
    auth[10..16].copy_from_slice(&AP);
    auth[16..22].copy_from_slice(&AP);
    auth[26] = 2;
    let assoc = plan
        .authentication_response(&auth)
        .unwrap()
        .unwrap()
        .to_vec();
    (plan, assoc)
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

fn wire() -> Result<(), &'static str> {
    let body = &eht_cap()[1..];
    check!(
        EhtCapability::parse(body, HE_PHY0_40_80_5G, true).is_ok_and(|c| c.mcs_nss().len() == 3),
        "<=80 AP set size"
    );
    check!(
        EhtCapability::parse(body, HE_PHY0_40_80_5G | HE_PHY0_160_5G, true).is_err(),
        "160 set missing but admitted"
    );
    check!(
        EhtCapability::parse(body, 0, true).is_ok()
            && EhtCapability::parse(body, 0, false).is_err(),
        "20MHz-only AP (3) vs non-AP (4) set sizes"
    );
    check!(
        mcs_nss_size(HE_PHY0_40_2G | HE_PHY0_160_5G, 0, false) == 3
            && mcs_nss_size(HE_PHY0_40_80_5G | HE_PHY0_160_5G, 0, true) == 6
            && mcs_nss_size(HE_PHY0_40_80_5G, PHY0_320_6G, true) == 6,
        "ieee80211_eht_mcs_nss_size differs"
    );
    let mut long = eht_cap();
    long.push(0);
    check!(
        EhtCapability::parse(&long[1..], HE_PHY0_40_80_5G, true).is_err(),
        "trailing octet admitted"
    );
    // PPE: header RU bitmask bit4 (one RU), NSS0 -> 6 + 9 = 15 bits = 2 octets.
    let mut ppe = eht_cap();
    ppe[3 + 5] |= PHY5_PPE_PRESENT;
    ppe.extend_from_slice(&[0x10, 0x00]);
    let cap = EhtCapability::parse(&ppe[1..], HE_PHY0_40_80_5G, true).map_err(|_| "PPE")?;
    check!(
        cap.ppe_thresholds() == [0x10, 0] && cap.body() == ppe,
        "PPE round trip"
    );
    check!(
        ppe_size(0x01ff) == 62 && ppe_size(0x0010) == 2,
        "ieee80211_eht_ppe_size differs"
    );
    let mut huge = eht_cap();
    huge[3 + 5] |= PHY5_PPE_PRESENT;
    huge.extend_from_slice(&[0xff, 0x01]);
    huge.extend_from_slice(&[0; 60]);
    check!(
        EhtCapability::parse(&huge[1..], HE_PHY0_40_80_5G, true).is_err(),
        "PPE above IEEE80211_EHT_PPE_THRES_MAX_LEN admitted"
    );
    let op = EhtOperation::parse(&eht_op(0x45, [0x11, 0, 0, 0], &[2, 42, 0])[1..])
        .map_err(|_| "info operation")?;
    check!(
        op.information() == Some([2, 42, 0])
            && op.disabled_subchannels().is_none()
            && op.default_pe_duration()
            && op.mcs15_disabled(),
        "operation facts"
    );
    check!(
        EhtOperation::parse(&eht_op(0x03, [0x11, 0, 0, 0], &[2, 42, 0])[1..]).is_err()
            && EhtOperation::parse(&eht_op(0x02, [0x11, 0, 0, 0], &[])[1..]).is_ok()
            && EhtOperation::parse(&eht_op(0x00, [0x11, 0, 0, 0], &[0])[1..]).is_err(),
        "ieee80211_eht_oper_size_ok extents"
    );
    Ok(())
}
smoke!(smoke_eht_capability_operation_extents, wire);

fn local_profile() -> Result<(), &'static str> {
    let mut phy = [0; 9];
    phy[0] = PHY0_320_6G;
    check!(
        LocalEht::new([0, 0], phy, [0x11, 0, 0]).is_err(),
        "6GHz 320 bit admitted"
    );
    check!(
        LocalEht::new([0, 0], [0; 9], [0x10, 0, 0]).is_err()
            && LocalEht::new([0, 0], [0; 9], [0x01, 0, 0]).is_err(),
        "missing single-stream MCS0-7 admitted"
    );
    let vht = LocalVht::new(0xfffa, 0xfffa, true, true, 0).unwrap();
    let no_he = LocalPhy::vht80(ht40(), vht).unwrap();
    check!(
        no_he.with_eht(local_eht()).is_err(),
        "EHT without HE admitted"
    );
    let twenty = LocalEht::twenty_only([0, 0], [0; 9], [0x11, 0x11, 0, 0]).unwrap();
    check!(
        local(None).with_eht(twenty).is_err(),
        "20MHz-only set with an 80MHz HE profile admitted"
    );
    check!(
        local(None)
            .with_eht(local_eht().with_160mhz([0x11, 0, 0]).unwrap())
            .is_err(),
        "160 set without HE160 admitted"
    );
    check!(
        local_eht().with_ppe_thresholds(&[0x10, 0, 0]).is_err(),
        "mis-sized PPE admitted"
    );
    Ok(())
}
smoke!(smoke_eht_local_profile_matches_he_widths, local_profile);

fn negotiation() -> Result<(), &'static str> {
    let scan = eht_ap();
    let plan = prepare(&scan, local(Some(local_eht()))).map_err(|_| "EHT AP refused")?;
    let eht = plan
        .offered_phy()
        .unwrap()
        .eht()
        .ok_or("EHT not negotiated")?;
    check!(
        eht.width() == Width::Eighty
            && eht.tx_max_nss() == [1, 1, 1, 0]
            && eht.rx_max_nss() == [2, 2, 2, 1]
            && eht.su_beamformee()
            && !eht.su_beamformer(),
        "EHT limits differ"
    );
    let (mut plan, assoc) = ready(&scan, local(Some(local_eht())));
    let body = local_eht().capability_body();
    let mut needle = vec![255, body.len() as u8];
    needle.extend_from_slice(&body);
    check!(
        assoc.windows(needle.len()).any(|w| w == needle.as_slice()),
        "request lacks EHT Capabilities"
    );
    check!(
        plan.association_response(&response(&scan)) == Ok(Some(7))
            && plan.negotiated_phy().unwrap().eht().is_some(),
        "EHT response refused"
    );
    let (mut plan, _) = ready(&scan, local(Some(local_eht())));
    check!(
        plan.association_response(&response(&ap(None, true, None)))
            .is_err(),
        "response dropping EHT admitted"
    );
    // Without local EHT the request carries no EHT element.
    let (_, assoc) = ready(&scan, local(None));
    check!(
        !assoc.windows(needle.len()).any(|w| w == needle.as_slice()),
        "EHT advertised without opt-in"
    );
    Ok(())
}
smoke!(smoke_eht_offer_request_response, negotiation);

fn fallback() -> Result<(), &'static str> {
    let required = ap(
        Some((eht_cap(), eht_op(0, [0x11, 0, 0, 0], &[]))),
        true,
        Some(0x80 | 121),
    );
    check!(
        prepare(&required, local(Some(local_eht()))).is_ok()
            && prepare(&required, local(None)).is_err(),
        "EHT membership selector"
    );
    let strict = ap(
        Some((eht_cap(), eht_op(0, [0x33, 0, 0, 0], &[]))),
        true,
        None,
    );
    check!(
        prepare(&strict, local(Some(local_eht()))).is_ok_and(|p| {
            let o = p.offered_phy().unwrap();
            o.eht().is_none() && o.he().is_some()
        }),
        "unsupported basic EHT set did not fall back to HE"
    );
    let same = ap(
        Some((eht_cap(), eht_op(1, [0x11, 0, 0, 0], &[2, 42, 0]))),
        true,
        None,
    );
    check!(
        prepare(&same, local(Some(local_eht()))).is_ok_and(|p| p
            .offered_phy()
            .unwrap()
            .eht()
            .is_some()),
        "matching EHT Operation Information refused"
    );
    for tail in [&[3u8, 42, 50][..], &[2, 58, 0][..]] {
        let wider = ap(
            Some((eht_cap(), eht_op(1, [0x11, 0, 0, 0], tail))),
            true,
            None,
        );
        check!(
            prepare(&wider, local(Some(local_eht()))).is_ok_and(|p| p
                .offered_phy()
                .unwrap()
                .eht()
                .is_none()),
            "EHT channel differing from HT/VHT kept EHT"
        );
    }
    let punctured = ap(
        Some((eht_cap(), eht_op(3, [0x11, 0, 0, 0], &[2, 42, 0, 2, 0]))),
        true,
        None,
    );
    check!(
        prepare(&punctured, local(Some(local_eht()))).is_ok_and(|p| p
            .offered_phy()
            .unwrap()
            .eht()
            .is_none()),
        "punctured EHT channel kept EHT"
    );
    let unpunctured = ap(
        Some((eht_cap(), eht_op(3, [0x11, 0, 0, 0], &[2, 42, 0, 0, 0]))),
        true,
        None,
    );
    check!(
        prepare(&unpunctured, local(Some(local_eht()))).is_ok_and(|p| p
            .offered_phy()
            .unwrap()
            .eht()
            .is_some()),
        "empty disabled-subchannel bitmap refused"
    );
    let no_he = ap(
        Some((eht_cap(), eht_op(0, [0x11, 0, 0, 0], &[]))),
        false,
        None,
    );
    check!(
        prepare(&no_he, local(Some(local_eht()))).is_err(),
        "EHT without HE admitted"
    );
    let mut orphan = ap(None, true, None);
    element(&mut orphan.information_elements, 255, &eht_cap());
    check!(
        prepare(&orphan, local(Some(local_eht()))).is_err(),
        "orphan EHT capability admitted"
    );
    check!(
        JoinPlan::prepare(&required, OWN, b"narf", SecurityMode::Open).is_err(),
        "legacy plan admitted EHT selector"
    );
    Ok(())
}
smoke!(smoke_eht_selector_and_he_fallback, fallback);
