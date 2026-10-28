// SPDX-License-Identifier: GPL-2.0-or-later
//! Host-supplicant fallback over the common FullMAC station: Linux
//! brcmfmac `brcmf_cfg80211_connect` (FWSUP_NONE), `brcmf_set_key_mgmt`,
//! `brcmf_cfg80211_add_key`/`send_key_to_dongle` literals.
use super::{
    fullmac_fixture::*,
    ioctl::Direction,
    runtime::Error,
    station::{external, Station},
};
use alloc::{boxed::Box, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::{scan::BssSecurity, ExternalSecurity, SecurityConfig};

/// Supplicant RSNE: CCMP, one `akm`, no capabilities, one cached PMKID.
fn supplicant_rsne(akm: u8) -> Vec<u8> {
    let plain = rsne(akm, 0);
    let mut body = plain[2..].to_vec();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&[0x3c; 16]);
    let mut ie = vec![48, body.len() as u8];
    ie.extend_from_slice(&body);
    ie
}

fn join<const PCIE: bool>(station: &mut Station<Mock<PCIE>>, akm: u8) -> Result<(), Error> {
    cache(station, AP, 6, BssSecurity::Wpa2, &rsne(akm, 0));
    let req = request(
        AP,
        6,
        SecurityConfig::External(ExternalSecurity::default()),
        supplicant_rsne(akm),
    );
    ready(station.associate(req)).unwrap_or(Err(Error::Timeout))
}

fn vectors() -> Result<(), &'static str> {
    let key = [0xa5; 16];
    let pairwise = external::wsec_key(0, &key, &[], Some(AP)).map_err(|_| "pairwise")?;
    let mut expected = [0u8; 164];
    expected[4] = 16;
    expected[8..24].copy_from_slice(&key);
    expected[112] = 4; // CRYPTO_ALGO_AES_CCM
    expected[156..162].copy_from_slice(&AP);
    if pairwise[..] != expected[..] {
        return Err("pairwise wsec_key differs from brcmf_wsec_key_le");
    }
    let group = external::wsec_key(1, &key, &[1, 2, 3, 4, 5, 6], None).map_err(|_| "group")?;
    let mut expected = [0u8; 164];
    expected[0] = 1;
    expected[4] = 16;
    expected[8..24].copy_from_slice(&key);
    expected[112] = 4;
    expected[116] = 2; // BRCMF_PRIMARY_KEY
    expected[132] = 1; // iv_initialized
    expected[140..144].copy_from_slice(&[3, 4, 5, 6]);
    expected[144..146].copy_from_slice(&[1, 2]);
    if group[..] != expected[..] {
        return Err("group wsec_key differs from convert_key_from_CPU");
    }
    if external::wsec_key(4, &key, &[], None).is_ok()
        || external::wsec_key(0, &[0; 32], &[], None).is_ok()
        || external::wsec_key(0, &key, &[0; 8], None).is_ok()
    {
        return Err("invalid key index/length/RSC accepted");
    }
    let table = [(1u8, 0x40u32), (2, 0x80), (5, 0x1000), (6, 0x8000)];
    if table
        .iter()
        .any(|&(akm, auth)| external::wpa_auth(akm) != Some(auth))
        || external::wpa_auth(8).is_some()
    {
        return Err("host-supplicant wpa_auth differs from brcmf_set_key_mgmt");
    }
    Ok(())
}
fn smoke_fullmac_host_supplicant_key_and_akm_vectors() -> TestResult {
    vectors().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/external",
    smoke_fullmac_host_supplicant_key_and_akm_vectors
);

fn conversation<const PCIE: bool>(akm: u8) -> Result<(), &'static str> {
    let mut station = init_station::<PCIE>(Firmware::new())?;
    let start = station.runtime.fw.log.len();
    join(&mut station, akm).map_err(|_| "host-supplicant join failed")?;
    let fw = &station.runtime.fw;
    let since = |name: &[u8]| -> Vec<Vec<u8>> {
        fw.log[start..]
            .iter()
            .filter(|c| c.direction == Direction::Set && c.iovar() == Some(name))
            .map(|c| c.value().to_vec())
            .collect()
    };
    if since(b"wpaie") != [supplicant_rsne(akm)]
        || since(b"wpa_auth") != [external::wpa_auth(akm).unwrap().to_le_bytes().to_vec()]
        || since(b"sup_wpa") != [0u32.to_le_bytes().to_vec()]
        || fw.log[start..].iter().any(|c| c.command == 268)
    {
        return Err("host-supplicant connect differs from FWSUP_NONE brcmf_cfg80211_connect");
    }
    if station.external_port() != Some(false) || station.runtime.fw.link != Some(AP) {
        return Err("SET_SSID did not link up an unauthorized host-supplicant port");
    }
    // Keys: pairwise to the AP and a group key, then authorization.
    let ccmp = narf_wireless::CIPHER_SUITE_CCMP;
    let before = station.runtime.fw.log.len();
    if ready(station.install_key(0, true, Some(AP2), ccmp, &[1; 16], &[]))
        != Some(Err(Error::Malformed))
        || ready(station.install_key(0, true, Some(AP), 0x000f_ac02, &[1; 16], &[]))
            != Some(Err(Error::Malformed))
        || station.runtime.fw.log.len() != before
    {
        return Err("invalid key reached firmware");
    }
    ready(station.install_key(0, true, Some(AP), ccmp, &[1; 16], &[]))
        .ok_or("pended")?
        .map_err(|_| "pairwise key")?;
    ready(station.install_key(1, false, None, ccmp, &[2; 16], &[0; 6]))
        .ok_or("pended")?
        .map_err(|_| "group key")?;
    let keys = station.runtime.fw.iovars(Direction::Set, b"wsec_key");
    if keys.len() != 2
        || keys[0] != external::wsec_key(0, &[1; 16], &[], Some(AP)).unwrap()[..]
        || keys[1] != external::wsec_key(1, &[2; 16], &[0; 6], None).unwrap()[..]
    {
        return Err("installed wsec_key bodies differ");
    }
    if station.authorize_port(AP2, true).is_ok() {
        return Err("authorized a different peer");
    }
    station.authorize_port(AP, true).map_err(|_| "authorize")?;
    if station.external_port() != Some(true) {
        return Err("port not authorized");
    }
    ready(station.disconnect())
        .ok_or("pended")?
        .map_err(|_| "disconnect")?;
    if station.external_port().is_some() {
        return Err("host-supplicant state survived disconnect");
    }
    Ok(())
}

fn failures() -> Result<(), &'static str> {
    // SAE through the host-supplicant path needs external auth: refused.
    let mut station = init_station::<false>(Firmware::new())?;
    let before = station.runtime.fw.log.len();
    if join(&mut station, narf_wireless::rsn::AKM_SAE) != Err(Error::Unsupported)
        || station.runtime.fw.log.len() != before
    {
        return Err("unsupported host-supplicant AKM reached firmware");
    }
    // A refused key installation is terminal for the firmware lifetime.
    let mut fw = Firmware::new();
    fw.hook = Some(Box::new(|_, command| {
        (command.iovar() == Some(b"wsec_key")).then_some(Err(Error::Firmware((-23i32) as u32)))
    }));
    let mut station = init_station::<true>(fw)?;
    station.cache.clear();
    join(&mut station, narf_wireless::rsn::AKM_PSK).map_err(|_| "join")?;
    let ccmp = narf_wireless::CIPHER_SUITE_CCMP;
    if ready(station.install_key(0, true, Some(AP), ccmp, &[1; 16], &[])).is_none_or(|r| r.is_ok())
        || station.bssid.is_some()
        || station.runtime.fw.link.is_some()
        || !station.runtime.fw.failed
    {
        return Err("refused wsec_key did not close and poison the connection");
    }
    Ok(())
}
fn smoke_fullmac_host_supplicant_connect_keys_and_authorization() -> TestResult {
    for result in [
        conversation::<false>(narf_wireless::rsn::AKM_PSK),
        conversation::<true>(narf_wireless::rsn::AKM_DOT1X),
        conversation::<true>(narf_wireless::rsn::AKM_PSK_SHA256),
        failures(),
    ] {
        if let Err(error) = result {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/external",
    smoke_fullmac_host_supplicant_connect_keys_and_authorization
);
