//! `JoinOptions::akms` / `JoinOptions::pmf` AKM-suite and PMF negotiation.
use super::*;
use crate::eapol::KeyMgmt;
use crate::station_security::Security;
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
const MFPC: u16 = rsn::RSN_CAP_MFP_CAPABLE;
const MFPR: u16 = rsn::RSN_CAP_MFP_REQUIRED;
macro_rules! smoke {
    ($name:ident, $body:ident) => {
        fn $name() -> TestResult {
            match $body() {
                Ok(()) => TestResult::Pass,
                Err(error) => TestResult::Fail(error),
            }
        }
        kernel_test_in!("wireless/association/akm", $name);
    };
}
fn ap_rsne(akms: &[u8], caps: u16) -> Vec<u8> {
    RsnIe {
        version: 1,
        group_cipher: Suite::standard(rsn::CIPHER_CCMP_128),
        pairwise_ciphers: vec![Suite::standard(rsn::CIPHER_CCMP_128)],
        akms: akms.iter().map(|a| Suite::standard(*a)).collect(),
        rsn_capabilities: caps,
        pmkids: Vec::new(),
        group_management_cipher: None,
    }
    .encode_body()
}
fn bss(rsne: &[u8], rsnxe: Option<u8>) -> Bss {
    let mut ies = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x82, 0x84, 0x8b];
    ies.extend_from_slice(&[48, rsne.len() as u8]);
    ies.extend_from_slice(rsne);
    if let Some(x) = rsnxe {
        ies.extend_from_slice(&[244, 1, x]);
    }
    Bss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 1,
        band: None,
        signal_dbm: None,
        capability: 0x11,
        beacon_interval: 100,
        information_elements: ies,
    }
}
fn plan(ap: &Bss, security: SecurityMode, options: JoinOptions) -> Result<JoinPlan, Error> {
    JoinPlan::prepare_with_options(ap, OWN, b"narf", security, None, options)
}
fn station_rsne(plan: &JoinPlan) -> Option<RsnIe> {
    RsnIe::decode_body(&plan.rsn_body()?)
}
const H2E: SecurityMode = SecurityMode::Wpa3Sae {
    pwe: SaePwe::HashToElement,
};

fn sae_akm_capability() -> Result<(), &'static str> {
    let ap = bss(&ap_rsne(&[8, 24], MFPC | MFPR), Some(rsn::RSNX_CAP_SAE_H2E));
    let default = plan(&ap, H2E, JoinOptions::default()).map_err(|_| "default SAE plan")?;
    if default.akm() != Some(KeyMgmt::SaeExtKey) {
        return Err("default options no longer prefer SAE-EXT-KEY under H2E");
    }
    let no24 = JoinOptions::default().with_akms(AkmSet::LEGACY.without(AkmSet::SAE_EXT_KEY));
    let fallback = plan(&ap, H2E, no24).map_err(|_| "AKM 8 fallback refused")?;
    if fallback.akm() != Some(KeyMgmt::Sae)
        || station_rsne(&fallback).map(|r| r.akms) != Some(vec![Suite::standard(rsn::AKM_SAE)])
    {
        return Err("driver without AKM 24 did not fall back to SAE AKM 8");
    }
    if !fallback.pmf() {
        return Err("SAE plan must report PMF");
    }
    // An AKM-24-only AP cannot fall back.
    let only24 = bss(&ap_rsne(&[24], MFPC | MFPR), Some(rsn::RSNX_CAP_SAE_H2E));
    if plan(&only24, H2E, no24).err() != Some(Error::UnsupportedSecurity) {
        return Err("AKM-24-only AP admitted without local AKM 24");
    }
    let only24_sae = JoinOptions::default().with_akms(AkmSet::SAE_EXT_KEY);
    if plan(&ap, H2E, only24_sae).map(|p| p.akm()) != Ok(Some(KeyMgmt::SaeExtKey)) {
        return Err("AKM-24-only station did not select AKM 24");
    }
    if plan(&ap, H2E, JoinOptions::default().with_akms(AkmSet::NONE)).err()
        != Some(Error::UnsupportedSecurity)
    {
        return Err("empty AKM set admitted SAE");
    }
    Ok(())
}
smoke!(
    smoke_join_sae_akm_capability_falls_back_to_akm8,
    sae_akm_capability
);

fn wpa2_legacy_unchanged() -> Result<(), &'static str> {
    // Default options keep the canonical AKM 2 / no-PMF body even when the
    // AP also offers PSK-SHA256 and MFPC.
    let ap = bss(&ap_rsne(&[2, 6], MFPC), None);
    let p = plan(&ap, SecurityMode::Wpa2Psk, JoinOptions::default()).map_err(|_| "legacy")?;
    if p.rsn_body() != Some(RsnIe::wpa2_psk_ccmp().encode_body())
        || p.akm() != Some(KeyMgmt::Psk)
        || p.pmf()
    {
        return Err("default WPA2 plan changed");
    }
    let mfpr = bss(&ap_rsne(&[2, 6], MFPC | MFPR), None);
    if plan(&mfpr, SecurityMode::Wpa2Psk, JoinOptions::default()).err()
        != Some(Error::UnsupportedSecurity)
    {
        return Err("default WPA2 plan admitted an MFPR AP");
    }
    Ok(())
}
smoke!(
    smoke_join_wpa2_default_profile_unchanged,
    wpa2_legacy_unchanged
);

fn wpa2_pmf() -> Result<(), &'static str> {
    let options = JoinOptions::default()
        .with_akms(AkmSet::ALL)
        .with_pmf(Pmf::Optional);
    // PMF-required AP offering PSK-SHA256 (AKM 6).
    let ap = bss(&ap_rsne(&[6], MFPC | MFPR), None);
    let p = plan(&ap, SecurityMode::Wpa2Psk, options).map_err(|_| "AKM 6 MFPR AP refused")?;
    let rsne = station_rsne(&p).ok_or("no RSNE")?;
    if rsne.akms != [Suite::standard(rsn::AKM_PSK_SHA256)]
        || rsne.rsn_capabilities != MFPC
        || p.akm() != Some(KeyMgmt::PskSha256)
        || !p.pmf()
    {
        return Err("WPA2 PSK-SHA256 PMF plan has the wrong RSNE");
    }
    let owner = Security::new(
        OWN,
        AP,
        &[7; 32],
        &p.rsn_body().unwrap(),
        &ap_rsne(&[6], MFPC | MFPR),
        None,
        0,
    )
    .map_err(|_| "Security refused the WPA2 PMF RSNE")?;
    if !owner.pmf() {
        return Err("Security did not negotiate WPA2 PMF");
    }
    // PSK preferred order: AKM 6 before 2; AKM 2 under optional PMF.
    let both = bss(&ap_rsne(&[2], MFPC), None);
    let p = plan(&both, SecurityMode::Wpa2Psk, options).map_err(|_| "AKM 2 MFPC refused")?;
    if p.akm() != Some(KeyMgmt::Psk) || !p.pmf() {
        return Err("WPA2 AKM 2 with optional PMF not negotiated");
    }
    let owner = Security::new(
        OWN,
        AP,
        &[7; 32],
        &p.rsn_body().unwrap(),
        &ap_rsne(&[2], MFPC),
        None,
        0,
    )
    .map_err(|_| "Security refused AKM 2 + MFPC")?;
    if !owner.pmf() {
        return Err("AKM 2 + MFPC owner without PMF");
    }
    // Optional PMF against a non-MFPC AP: MFPC advertised, PMF not in force.
    let legacy = bss(&ap_rsne(&[2], 0), None);
    let p = plan(&legacy, SecurityMode::Wpa2Psk, options).map_err(|_| "non-MFPC AP refused")?;
    if p.pmf() || station_rsne(&p).map(|r| r.rsn_capabilities) != Some(MFPC) {
        return Err("optional PMF against a non-MFPC AP");
    }
    let owner = Security::new(
        OWN,
        AP,
        &[7; 32],
        &p.rsn_body().unwrap(),
        &ap_rsne(&[2], 0),
        None,
        0,
    )
    .map_err(|_| "Security refused optional PMF to a legacy AP")?;
    if owner.pmf() {
        return Err("PMF in force without AP MFPC");
    }
    // Required PMF needs AP MFPC.
    let required = options.with_pmf(Pmf::Required);
    if plan(&legacy, SecurityMode::Wpa2Psk, required).err() != Some(Error::UnsupportedSecurity) {
        return Err("required PMF admitted a non-MFPC AP");
    }
    let p = plan(&ap, SecurityMode::Wpa2Psk, required).map_err(|_| "required PMF refused")?;
    if station_rsne(&p).map(|r| r.rsn_capabilities) != Some(MFPC | MFPR) {
        return Err("required PMF RSNE lacks MFPR");
    }
    // A WPA2 PMF RSNE is not an SAE owner.
    if Security::new_sae(
        OWN,
        AP,
        &[7; 32],
        &p.rsn_body().unwrap(),
        None,
        &ap_rsne(&[6], MFPC | MFPR),
        None,
        0,
    )
    .is_ok()
    {
        return Err("new_sae accepted a WPA2 PMF RSNE");
    }
    // AKM 6 without the local capability is not chosen.
    let no6 = options.with_akms(AkmSet::LEGACY);
    if plan(&ap, SecurityMode::Wpa2Psk, no6).err() != Some(Error::UnsupportedSecurity) {
        return Err("AKM 6 chosen without local PSK-SHA256");
    }
    // A non-default group management cipher cannot be protected.
    let mut gmac = RsnIe::decode_body(&ap_rsne(&[2], MFPC)).unwrap();
    gmac.group_management_cipher = Some(Suite::standard(rsn::CIPHER_BIP_GMAC_256));
    if plan(
        &bss(&gmac.encode_body(), None),
        SecurityMode::Wpa2Psk,
        options,
    )
    .is_ok()
    {
        return Err("BIP-GMAC-256 AP admitted for PMF");
    }
    Ok(())
}
smoke!(smoke_join_wpa2_psk_pmf_and_psk_sha256, wpa2_pmf);
