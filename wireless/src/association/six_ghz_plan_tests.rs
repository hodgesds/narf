//! 6 GHz `JoinPlan` (`six_ghz::plan`, `JoinPlan::prepare_6ghz`): admission
//! under the regulatory power type, channel/width derivation, EHT 320MHz,
//! the 6 GHz security rule and the association-request elements.
use super::*;
use crate::association::{Bss, JoinOptions, JoinPlan, SaePwe, SecurityMode};
use crate::reg::RegFlags;
use crate::rsn::{self, RsnIe, Suite};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
macro_rules! smoke {
    ($name:ident, $body:ident) => {
        fn $name() -> TestResult {
            match $body() {
                Ok(()) => TestResult::Pass,
                Err(error) => TestResult::Fail(error),
            }
        }
        kernel_test_in!("wireless/association/six_ghz", $name);
    };
}
macro_rules! check {
    ($condition:expr, $message:literal) => {
        if !$condition {
            return Err($message);
        }
    };
}
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const SAE_H2E: SecurityMode = SecurityMode::Wpa3Sae {
    pwe: SaePwe::HashToElement,
};
fn element(bytes: &mut Vec<u8>, id: u8, body: &[u8]) {
    bytes.extend_from_slice(&[id, body.len() as u8]);
    bytes.extend_from_slice(body);
}
fn he_cap() -> Vec<u8> {
    let mut body = vec![he::EXT_HE_CAPABILITIES, 0, 0, 0, 0, 0, 0];
    let mut phy = [0; 11];
    phy[0] = 0x04 | 0x08;
    body.extend_from_slice(&phy);
    body.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff]);
    body
}
fn he_op(six: [u8; 5]) -> Vec<u8> {
    let params: u32 = 1023 << 4 | 0x0002_0000;
    let mut body = vec![he::EXT_HE_OPERATION];
    body.extend_from_slice(&params.to_le_bytes());
    body.extend_from_slice(&0xfffcu16.to_le_bytes());
    body.extend_from_slice(&six);
    body
}
/// AP EHT Capabilities (320MHz-capable when `w320`) and Operation.
fn eht(out: &mut Vec<u8>, w320: bool, info: [u8; 3], disabled: Option<u16>) {
    let mut cap = vec![eht::EXT_EHT_CAPABILITIES, 0, 0];
    let mut phy = [0; 9];
    phy[0] = if w320 { 0x02 } else { 0 };
    cap.extend_from_slice(&phy);
    cap.extend_from_slice(&[0x22; 6]);
    if w320 {
        cap.extend_from_slice(&[0x22; 3]);
    }
    element(out, 255, &cap);
    let mut op = vec![
        eht::EXT_EHT_OPERATION,
        0x01 | if disabled.is_some() { 0x02 } else { 0 },
        0x11,
        0,
        0,
        0,
    ];
    op.extend_from_slice(&info);
    if let Some(bitmap) = disabled {
        op.extend_from_slice(&bitmap.to_le_bytes());
    }
    element(out, 255, &op);
}
fn ap_rsne(akm: u8, caps: u16) -> Vec<u8> {
    RsnIe {
        version: 1,
        group_cipher: Suite::standard(rsn::CIPHER_CCMP_128),
        pairwise_ciphers: vec![Suite::standard(rsn::CIPHER_CCMP_128)],
        akms: vec![Suite::standard(akm)],
        rsn_capabilities: caps,
        pmkids: Vec::new(),
        group_management_cipher: None,
    }
    .encode_body()
}
const MFP: u16 = rsn::RSN_CAP_MFP_CAPABLE | rsn::RSN_CAP_MFP_REQUIRED;
/// A 6 GHz BSS on `six[0]`: OFDM rates, RSNE (`akm`), RSNXE (`rsnxe`),
/// HE + HE 6 GHz elements and `extra` elements.
fn bss_with(six: [u8; 5], akm: u8, rsnxe: u8, privacy: bool, extra: &[u8]) -> Bss {
    let mut ies = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x8c, 0x98, 0xb0];
    if privacy {
        element(&mut ies, 48, &ap_rsne(akm, MFP));
        element(&mut ies, 244, &[rsnxe]);
    }
    element(&mut ies, 255, &he_cap());
    element(&mut ies, 255, &he_op(six));
    ies.extend_from_slice(&He6GhzCapability::new(0x003d).element());
    ies.extend_from_slice(extra);
    Bss {
        bssid: [2, 0, 0, 0, 0, 2],
        ssid: b"narf".to_vec(),
        channel: six[0],
        band: Some(Band::Ghz6),
        signal_dbm: None,
        capability: if privacy { 0x11 } else { 0x01 },
        beacon_interval: 100,
        information_elements: ies,
    }
}
fn sae_bss(six: [u8; 5], extra: &[u8]) -> Bss {
    bss_with(six, rsn::AKM_SAE, 0x20, true, extra)
}
fn rule(flags: RegFlags) -> RegRule {
    RegRule {
        freq_start_mhz: 5925,
        freq_end_mhz: 7125,
        max_bandwidth_mhz: 320,
        max_power_dbm: 24,
        flags,
    }
}
fn local_he(phy0: u8, w160: bool) -> LocalHe {
    let mut phy = [0; 11];
    phy[0] = phy0;
    let he = LocalHe::new([0; 6], phy, 0xfffa, 0xfffa).unwrap();
    if w160 {
        he.with_160mhz(0xfffa, 0xfffa).unwrap()
    } else {
        he
    }
}
fn local(phy0: u8, w160: bool, flags: RegFlags) -> SixGhzLocal {
    // SM PS = static (0) in the device capability; the request sends 3.
    SixGhzLocal::new(
        local_he(phy0, w160),
        He6GhzCapability::new(0x003d),
        rule(flags),
    )
    .unwrap()
}
fn prepare(bss: &Bss, security: SecurityMode, local: &SixGhzLocal) -> Result<JoinPlan, Error> {
    JoinPlan::prepare_6ghz(bss, OWN, b"narf", security, local, JoinOptions::default())
}
/// The association-request elements after the fixed fields.
fn request_ids(plan: &JoinPlan) -> Vec<(u8, Option<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 28;
    while at + 2 <= plan.assoc.len() {
        let len = usize::from(plan.assoc[at + 1]);
        let body = plan.assoc[at + 2..at + 2 + len].to_vec();
        let ext = (plan.assoc[at] == 255).then(|| body[0]);
        out.push((plan.assoc[at], ext, body));
        at += 2 + len;
    }
    out
}

fn he80_plan() -> Result<(), &'static str> {
    // SP AP on primary 37, 80MHz centre 39.
    let bss = sae_bss([37, 2 | 1 << 3, 39, 0, 6], &[]);
    let me = local(0x04, false, RegFlags::empty());
    let plan = prepare(&bss, SAE_H2E, &me).map_err(|_| "6 GHz SAE BSS refused")?;
    let six = plan.six_ghz().ok_or("no 6 GHz state")?;
    check!(six.power_type() == PowerType6Ghz::Sp, "power type");
    check!(six.width() == SixGhzWidth::Eighty, "80MHz width");
    let ch = six.channel();
    check!(
        ch.primary == 37 && ch.primary_mhz == 6135 && ch.center == 39 && ch.center_mhz == 6145,
        "80MHz channel"
    );
    check!(six.operation().primary == 37, "operation");
    check!(six.he().width() == Width::Eighty, "HE width");
    check!(six.eht().is_none(), "EHT without EHT elements");
    check!(
        six.peer_capability().bits() == 0x003d,
        "peer band capability"
    );
    check!(
        six.local_capability().sm_ps() == 3 && six.local_capability().min_mpdu_start() == 5,
        "SM PS disabled in the transmitted band capability"
    );
    check!(six.regulatory_connectivity() == 0x0f, "reg connectivity");
    check!(plan.channel() == 37 && plan.pmf(), "plan channel / PMF");
    check!(plan.offered_phy().is_none(), "no HT/VHT offer on 6 GHz");
    let ids = request_ids(&plan);
    check!(
        !ids.iter()
            .any(|(id, _, _)| matches!(id, 45 | 61 | 191 | 192)),
        "HT/VHT element in a 6 GHz request"
    );
    let order: Vec<_> = ids.iter().filter_map(|(_, ext, _)| *ext).collect();
    check!(
        order
            == [
                he::EXT_HE_CAPABILITIES,
                EXT_HE_6GHZ_CAPABILITIES,
                EXT_NON_AP_STA_REG_CON
            ],
        "6 GHz request element order"
    );
    check!(
        ids.iter()
            .any(|(_, ext, body)| *ext == Some(EXT_HE_6GHZ_CAPABILITIES)
                && body[1..] == (0x003du16 | 3 << 9).to_le_bytes()),
        "HE 6 GHz Band Capabilities body"
    );
    check!(
        ids.iter()
            .any(|(_, ext, body)| *ext == Some(EXT_NON_AP_STA_REG_CON) && body[1..] == [0x0f]),
        "Non-AP STA Regulatory Connectivity"
    );
    // The legacy entry points still refuse a 6 GHz BSS.
    check!(
        JoinPlan::prepare(&bss, OWN, b"narf", SAE_H2E).err() == Some(Error::InvalidBss),
        "legacy prepare admitted a 6 GHz BSS"
    );
    // A 6 GHz plan of a 2.4/5 GHz BSS is refused.
    let mut legacy = bss.clone();
    legacy.band = None;
    check!(
        prepare(&legacy, SAE_H2E, &me).err() == Some(Error::InvalidBss),
        "prepare_6ghz admitted a 5 GHz-numbered BSS"
    );
    Ok(())
}
smoke!(smoke_six_ghz_plan_he80, he80_plan);

fn security_rule() -> Result<(), &'static str> {
    let six = [37, 2, 39, 0, 6];
    let me = local(0x04, false, RegFlags::empty());
    let open = bss_with(six, rsn::AKM_SAE, 0x20, false, &[]);
    check!(
        prepare(&open, SecurityMode::Open, &me).err() == Some(Error::UnsupportedSecurity),
        "open 6 GHz BSS admitted"
    );
    let psk = bss_with(six, rsn::AKM_PSK, 0x20, true, &[]);
    check!(
        prepare(&psk, SecurityMode::Wpa2Psk, &me).err() == Some(Error::UnsupportedSecurity),
        "WPA2-PSK admitted on 6 GHz"
    );
    let sae = sae_bss(six, &[]);
    let hnp = SecurityMode::Wpa3Sae {
        pwe: SaePwe::HuntAndPeck,
    };
    check!(
        prepare(&sae, hnp, &me).err() == Some(Error::UnsupportedSecurity),
        "SAE hunting-and-pecking admitted on 6 GHz"
    );
    let no_h2e = bss_with(six, rsn::AKM_SAE, 0, true, &[]);
    let both = SecurityMode::Wpa3Sae { pwe: SaePwe::Both };
    check!(
        prepare(&no_h2e, both, &me).err() == Some(Error::UnsupportedSecurity),
        "SAE without H2E admitted on 6 GHz"
    );
    check!(
        prepare(&sae, both, &me).is_ok(),
        "SAE H2E (sae_pwe=2) refused"
    );
    let ext = bss_with(six, rsn::AKM_SAE_EXT_KEY, 0x20, true, &[]);
    check!(prepare(&ext, SAE_H2E, &me).is_ok(), "SAE-EXT-KEY refused");
    Ok(())
}
smoke!(smoke_six_ghz_plan_security_rule, security_rule);

fn power_types() -> Result<(), &'static str> {
    // LPI is always allowed.
    let lpi = sae_bss([37, 2, 39, 0, 6], &[]);
    let all = RegFlags::NO_6GHZ_VLP_CLIENT | RegFlags::NO_6GHZ_AFC_CLIENT;
    let plan = prepare(&lpi, SAE_H2E, &local(0x04, false, all)).map_err(|_| "LPI refused")?;
    let six = plan.six_ghz().ok_or("no 6 GHz state")?;
    check!(six.power_type() == PowerType6Ghz::Lpi, "LPI power type");
    // SP needs AFC: no SP value in the connectivity element under NO_AFC.
    check!(
        six.regulatory_connectivity() == 0x07,
        "reg connectivity under NO_AFC"
    );
    let vlp = sae_bss([37, 2 | 2 << 3, 39, 0, 6], &[]);
    check!(
        prepare(
            &vlp,
            SAE_H2E,
            &local(0x04, false, RegFlags::NO_6GHZ_VLP_CLIENT)
        )
        .err()
            == Some(Error::UnsupportedRates),
        "VLP admitted under NO_6GHZ_VLP_CLIENT"
    );
    check!(
        prepare(&vlp, SAE_H2E, &local(0x04, false, RegFlags::empty())).is_ok(),
        "VLP refused"
    );
    let sp = sae_bss([37, 2 | 1 << 3, 39, 0, 6], &[]);
    check!(
        prepare(
            &sp,
            SAE_H2E,
            &local(0x04, false, RegFlags::NO_6GHZ_AFC_CLIENT)
        )
        .err()
            == Some(Error::UnsupportedRates),
        "SP admitted without AFC"
    );
    // Indoor SP falls back to LPI under NO_6GHZ_AFC_CLIENT.
    let indoor = sae_bss([37, 2 | 8 << 3, 39, 0, 6], &[]);
    let plan = prepare(
        &indoor,
        SAE_H2E,
        &local(0x04, false, RegFlags::NO_6GHZ_AFC_CLIENT),
    )
    .map_err(|_| "indoor SP refused")?;
    check!(
        plan.six_ghz().map(SixGhzPlan::power_type) == Some(PowerType6Ghz::Lpi),
        "indoor SP fallback"
    );
    // A rule that does not cover the primary.
    let mut narrow = rule(RegFlags::empty());
    narrow.freq_end_mhz = 6000;
    let me = SixGhzLocal::new(local_he(0x04, false), He6GhzCapability::new(0x3d), narrow)
        .map_err(|_| "local")?;
    check!(
        prepare(&lpi, SAE_H2E, &me).is_err(),
        "uncovered primary admitted"
    );
    check!(
        SixGhzLocal::new(local_he(0x04, false), He6GhzCapability::new(0), rule(all)).is_err(),
        "zero band capability accepted"
    );
    Ok(())
}
smoke!(smoke_six_ghz_plan_power_types, power_types);

fn widths() -> Result<(), &'static str> {
    let he160 = sae_bss([37, 3, 39, 47, 6], &[]);
    let me = local(0x04, true, RegFlags::empty());
    let plan = prepare(&he160, SAE_H2E, &me).map_err(|_| "160MHz refused")?;
    let ch = *plan.six_ghz().ok_or("no 6 GHz state")?.channel();
    check!(
        ch.width == SixGhzWidth::OneSixty && ch.center == 47 && ch.center_mhz == 6185,
        "160MHz channel"
    );
    // A station without HE160 narrows to the primary 80MHz.
    let plan = prepare(&he160, SAE_H2E, &local(0x04, false, RegFlags::empty()))
        .map_err(|_| "160MHz AP refused by an 80MHz station")?;
    let ch = *plan.six_ghz().ok_or("no 6 GHz state")?.channel();
    check!(
        ch.width == SixGhzWidth::Eighty && ch.center == 39,
        "160 -> 80"
    );
    // A 20MHz-only station.
    let plan = prepare(&he160, SAE_H2E, &local(0, false, RegFlags::empty()))
        .map_err(|_| "20MHz station refused")?;
    let ch = *plan.six_ghz().ok_or("no 6 GHz state")?.channel();
    check!(
        ch.width == SixGhzWidth::Twenty && ch.center == 37 && ch.center_mhz == 6135,
        "160 -> 20"
    );
    // 40MHz on primary 33 (centre 35).
    let he40 = sae_bss([33, 1, 35, 0, 6], &[]);
    let plan = prepare(&he40, SAE_H2E, &me).map_err(|_| "40MHz refused")?;
    let ch = *plan.six_ghz().ok_or("no 6 GHz state")?.channel();
    check!(
        ch.width == SixGhzWidth::Forty && ch.center == 35,
        "40MHz channel"
    );
    // The receive channel must be the announced primary.
    let mut bad = sae_bss([37, 2, 39, 0, 6], &[]);
    bad.channel = 33;
    check!(
        prepare(&bad, SAE_H2E, &me).is_err(),
        "primary mismatch admitted"
    );
    Ok(())
}
smoke!(smoke_six_ghz_plan_widths, widths);

fn local_eht(w320: bool) -> LocalEht {
    let eht = LocalEht::new([0; 2], [0; 9], [0x22; 3])
        .and_then(|e| e.with_160mhz([0x22; 3]))
        .unwrap();
    if w320 {
        eht.with_320mhz([0x22; 3]).unwrap()
    } else {
        eht
    }
}
fn eht_plan() -> Result<(), &'static str> {
    // HE 160MHz centre 47; EHT 320MHz (320-1) centre 31.
    let mut extra = Vec::new();
    eht(&mut extra, true, [4, 47, 31], None);
    let bss = sae_bss([37, 3, 39, 47, 6], &extra);
    let me = local(0x04, true, RegFlags::empty())
        .with_eht(local_eht(true))
        .map_err(|_| "local EHT320")?;
    let plan = prepare(&bss, SAE_H2E, &me).map_err(|_| "EHT320 BSS refused")?;
    let six = plan.six_ghz().ok_or("no 6 GHz state")?;
    let ch = six.channel();
    check!(
        ch.width == SixGhzWidth::ThreeTwenty && ch.center == 31 && ch.center_mhz == 6105,
        "320MHz channel"
    );
    let e = six.eht().ok_or("EHT not negotiated")?;
    check!(e.width320() && e.tx_max_nss()[0] == 2, "EHT 320 facts");
    check!(six.he().width() == Width::OneSixty, "HE width under EHT320");
    let order: Vec<_> = request_ids(&plan)
        .iter()
        .filter_map(|(_, ext, _)| *ext)
        .collect();
    check!(
        order
            == [
                he::EXT_HE_CAPABILITIES,
                EXT_HE_6GHZ_CAPABILITIES,
                EXT_NON_AP_STA_REG_CON,
                eht::EXT_EHT_CAPABILITIES
            ],
        "EHT request element order"
    );
    // Without local 320MHz: EHT at 160MHz.
    let me160 = local(0x04, true, RegFlags::empty())
        .with_eht(local_eht(false))
        .map_err(|_| "local EHT160")?;
    let plan = prepare(&bss, SAE_H2E, &me160).map_err(|_| "EHT160 station refused")?;
    let six = plan.six_ghz().ok_or("no 6 GHz state")?;
    check!(
        six.width() == SixGhzWidth::OneSixty
            && six.channel().center == 47
            && six.eht().is_some_and(|e| !e.width320()),
        "320 -> 160 without local 320MHz"
    );
    // Without EHT the plan never reaches 320MHz.
    let plan = prepare(&bss, SAE_H2E, &local(0x04, true, RegFlags::empty()))
        .map_err(|_| "HE station refused")?;
    check!(
        plan.six_ghz().map(SixGhzPlan::width) == Some(SixGhzWidth::OneSixty),
        "HE-only width"
    );
    // A punctured EHT channel falls back to HE.
    let mut punct = Vec::new();
    eht(&mut punct, true, [4, 47, 31], Some(0x0002));
    let plan = prepare(&sae_bss([37, 3, 39, 47, 6], &punct), SAE_H2E, &me)
        .map_err(|_| "punctured BSS refused")?;
    check!(
        plan.six_ghz()
            .is_some_and(|s| s.eht().is_none() && s.width() == SixGhzWidth::OneSixty),
        "punctured EHT fallback"
    );
    // EHT channel narrower than the HE channel: STRICT "HE/EHT incompatible".
    let mut narrow = Vec::new();
    eht(&mut narrow, true, [2, 39, 0], None);
    check!(
        prepare(&sae_bss([37, 3, 39, 47, 6], &narrow), SAE_H2E, &me).err()
            == Some(Error::InvalidBss),
        "incompatible HE/EHT channels admitted"
    );
    // A 320MHz centre not on the 31 + 32k raster.
    let mut bad = Vec::new();
    eht(&mut bad, true, [4, 47, 47], None);
    check!(
        prepare(&sae_bss([37, 3, 39, 47, 6], &bad), SAE_H2E, &me).is_err(),
        "bad 320MHz centre admitted"
    );
    Ok(())
}
smoke!(smoke_six_ghz_plan_eht320, eht_plan);

fn sme_ies_and_response() -> Result<(), &'static str> {
    let bss = sae_bss([37, 2, 39, 0, 6], &[]);
    let me = local(0x04, false, RegFlags::empty());
    let mut plan = prepare(&bss, SAE_H2E, &me).map_err(|_| "refused")?;
    let mut ht = vec![45, 26];
    ht.extend_from_slice(&[0; 26]);
    check!(
        plan.append_sme_ies(&ht) == Err(Error::UnsupportedRates),
        "HT Capabilities appended on 6 GHz"
    );
    let mut vht = vec![191, 12];
    vht.extend_from_slice(&[0; 12]);
    check!(
        plan.append_sme_ies(&vht) == Err(Error::UnsupportedRates),
        "VHT Capabilities appended on 6 GHz"
    );
    // Response element checks.
    let mut ok = Vec::new();
    element(&mut ok, 255, &he_cap());
    element(&mut ok, 255, &he_op([37, 2, 39, 0, 6]));
    check!(
        plan.six_ghz_response(&ok).is_ok(),
        "valid 6 GHz response refused"
    );
    let mut no_op = Vec::new();
    element(&mut no_op, 255, &he_cap());
    check!(
        plan.six_ghz_response(&no_op) == Err(Error::UnsupportedRates),
        "response without HE Operation admitted"
    );
    let mut with_ht = ok.clone();
    element(&mut with_ht, 61, &[0; 22]);
    check!(
        plan.six_ghz_response(&with_ht).is_err(),
        "HT Operation in a 6 GHz response"
    );
    Ok(())
}
smoke!(
    smoke_six_ghz_plan_sme_ies_and_response,
    sme_ies_and_response
);

fn local_phy_refuses_320() -> Result<(), &'static str> {
    use crate::association::phy::{LocalHt, LocalPhy};
    let phy = LocalPhy::ht20(LocalHt::siso20(false, false)).map_err(|_| "ht20")?;
    let he80 = local_he(0x04, false);
    let phy = phy.with_he(he80).map_err(|_| "with_he")?;
    let eht80 = LocalEht::new([0; 2], [0; 9], [0x22; 3]).map_err(|_| "eht")?;
    check!(phy.with_eht(eht80).is_ok(), "EHT80 refused by LocalPhy");
    check!(
        eht80.with_320mhz([0x22; 3]).is_err(),
        "320 without the 160 set"
    );
    check!(local_eht(true).width320(), "with_320mhz");
    Ok(())
}
smoke!(smoke_six_ghz_local_eht_320, local_phy_refuses_320);
