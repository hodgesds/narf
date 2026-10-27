// SPDX-License-Identifier: GPL-2.0-or-later
//! WPA3-Personal SAE firmware offload over the common FullMAC station.
//! Literals follow Linux brcmfmac `cfg80211.c::brcmf_cfg80211_connect`,
//! `cyw/core.c::brcmf_cyw_set_sae_pwd`, `wcc/core.c::brcmf_wcc_set_sae_pwd`
//! and `fwil_types.h`.
use super::{
    fullmac::FirmwareVendor,
    fullmac_fixture::*,
    ioctl::Direction,
    runtime::Error,
    station::{sae, Station},
};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::{scan::BssSecurity, SecurityConfig};

const PASSWORD: &[u8] = b"correct horse battery staple";
const SAE: u8 = narf_wireless::rsn::AKM_SAE;
const MFPC: u16 = 0x80;
const MFPR: u16 = 0x40;

fn sae_firmware(vendor: FirmwareVendor) -> Firmware {
    let mut fw = Firmware::new();
    fw.vendor = vendor;
    fw.caps.extend_from_slice(b" sae sae_ext");
    fw
}

fn vectors() -> Result<(), &'static str> {
    if !sae::has_capability(b"ap sta sae mfp\0\0junk sae_ext", b"sae")
        || sae::has_capability(b"ap sta sae_ext mfp", b"sae")
        || sae::has_capability(b"ap sta\0sae ", b"sae")
    {
        return Err("cap token match differs from Linux \"sae \"");
    }
    let cyw = sae::cyw_password(b"abc").map_err(|_| "cyw password")?;
    let mut expected = vec![3, 0, b'a', b'b', b'c'];
    expected.resize(130, 0);
    if cyw[..] != expected[..] {
        return Err("sae_password is not brcmf_wsec_sae_pwd_le");
    }
    let wcc = sae::wcc_passphrase(b"abc").map_err(|_| "wcc password")?;
    let mut expected = vec![3, 0, 1, 0, b'a', b'b', b'c'];
    expected.resize(132, 0);
    if wcc[..] != expected[..] {
        return Err("WSEC_PMK passphrase is not brcmf_wsec_pmk_le");
    }
    if sae::cyw_password(&[0x61; 129]).is_ok()
        || sae::wcc_passphrase(&[]).is_ok()
        || sae::cyw_password(&[0x61; 128]).is_err()
    {
        return Err("SAE password bound differs from BRCMF_WSEC_MAX_SAE_PASSWORD_LEN");
    }
    Ok(())
}
fn smoke_fullmac_sae_capability_and_password_abi_vectors() -> TestResult {
    vectors().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sae",
    smoke_fullmac_sae_capability_and_password_abi_vectors
);

fn join<const PCIE: bool>(
    station: &mut Station<Mock<PCIE>>,
    ap_caps: u16,
    sme: Vec<u8>,
    password: &[u8],
) -> Result<(), Error> {
    cache(station, AP, 6, BssSecurity::Wpa3, &rsne(SAE, ap_caps));
    let request = request(
        AP,
        6,
        SecurityConfig::Wpa3 {
            password: password.to_vec(),
        },
        sme,
    );
    ready(station.associate(request)).unwrap_or(Err(Error::Timeout))
}

/// Exact offload order and vendor password ABI.
fn offload<const PCIE: bool>(vendor: FirmwareVendor, ap_caps: u16) -> Result<(), &'static str> {
    let mode = if ap_caps & MFPR != 0 { 2u32 } else { 1 };
    let request_caps = if mode == 2 { MFPC | MFPR } else { MFPC };
    let mut fw = sae_firmware(vendor);
    // Firmware-built association RSNE and the AP's response RSNE.
    fw.assoc_req_ies = rsne(SAE, request_caps);
    fw.assoc_resp_ies = rsne(SAE, ap_caps);
    let mut station = init_station::<PCIE>(fw)?;
    if !station.supports_sae_offload() {
        return Err("firmware sae/FWSUP/MFP did not advertise SAE offload");
    }
    let start = station.runtime.fw.log.len();
    join(&mut station, ap_caps, rsne(SAE, request_caps), PASSWORD)
        .map_err(|_| "SAE offload association failed")?;
    if station.bssid != Some(AP) || station.runtime.fw.link != Some(AP) {
        return Err("SAE offload did not open the authorized port");
    }
    let log = &station.runtime.fw.log[start..];
    let position =
        |pred: &dyn Fn(&super::fullmac_fixture::Command) -> bool| log.iter().position(|c| pred(c));
    let set = Direction::Set;
    let auth = position(&|c| c.direction == set && c.command == 22);
    let wpaie: Vec<usize> = log
        .iter()
        .enumerate()
        .filter(|(_, c)| c.direction == set && c.iovar() == Some(b"wpaie"))
        .map(|(i, _)| i)
        .collect();
    let wpa_auth = position(&|c| c.direction == set && c.iovar() == Some(b"wpa_auth"));
    let wsec = position(&|c| c.direction == set && c.command == 134);
    let mfp = position(&|c| c.direction == set && c.iovar() == Some(b"mfp"));
    let sup = position(&|c| c.direction == set && c.iovar() == Some(b"sup_wpa"));
    let cyw = position(&|c| c.direction == set && c.iovar() == Some(b"sae_password"));
    let wcc = position(&|c| c.direction == set && c.command == 268);
    let ssid = position(&|c| c.direction == set && c.command == 26);
    let (Some(auth), [first, clear], Some(wpa_auth), Some(wsec), Some(mfp), Some(sup), Some(ssid)) =
        (auth, wpaie.as_slice(), wpa_auth, wsec, mfp, sup, ssid)
    else {
        return Err("SAE offload command set incomplete");
    };
    let password = match vendor {
        FirmwareVendor::Cyw if wcc.is_none() => cyw.ok_or("CYW sae_password missing")?,
        FirmwareVendor::Wcc if cyw.is_none() => wcc.ok_or("WCC WSEC_PMK passphrase missing")?,
        _ => return Err("both vendor SAE password ABIs were written"),
    };
    if !(auth < *first
        && *first < wpa_auth
        && wpa_auth < wsec
        && wsec < mfp
        && mfp < sup
        && sup < *clear
        && *clear < password
        && password < ssid)
    {
        return Err("SAE offload order differs from brcmf_cfg80211_connect");
    }
    if log[auth].body != 3u32.to_le_bytes()
        || log[*first].value() != rsne(SAE, request_caps).as_slice()
        || !log[*clear].value().is_empty()
        || log[wpa_auth].value() != sae::WPA3_AUTH_SAE_PSK.to_le_bytes()
        || log[wsec].body != 4u32.to_le_bytes()
        || log[mfp].value() != mode.to_le_bytes()
        || log[sup].value() != 1u32.to_le_bytes()
    {
        return Err("SAE offload literals differ from Linux");
    }
    let expected: Vec<u8> = match vendor {
        FirmwareVendor::Cyw => sae::cyw_password(PASSWORD).unwrap()[..].to_vec(),
        FirmwareVendor::Wcc => sae::wcc_passphrase(PASSWORD).unwrap()[..].to_vec(),
    };
    if log[password].value() != expected.as_slice() {
        return Err("vendor SAE password body differs");
    }
    ready(station.disconnect())
        .ok_or("disconnect pended")?
        .map_err(|_| "disconnect failed")?;
    if station.runtime.fw.link.is_some() {
        return Err("disconnect left the SAE port open");
    }
    Ok(())
}
fn smoke_fullmac_sae_offload_cyw_and_wcc_password_abi() -> TestResult {
    for result in [
        offload::<false>(FirmwareVendor::Cyw, MFPC | MFPR),
        offload::<false>(FirmwareVendor::Wcc, MFPC | MFPR),
        offload::<true>(FirmwareVendor::Wcc, MFPC | MFPR),
        // WPA3 transition AP (MFPC): capable PMF with response RSNE proof.
        offload::<true>(FirmwareVendor::Wcc, MFPC),
    ] {
        if let Err(error) = result {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sae",
    smoke_fullmac_sae_offload_cyw_and_wcc_password_abi
);

fn refusals() -> Result<(), &'static str> {
    // Firmware without the exact `sae` token (only `sae_ext`) or without
    // FWSUP never offers or attempts SAE offload.
    for (caps, supplicant) in [(&b"sta mfp sae_ext"[..], true), (b"sta mfp sae", false)] {
        let mut fw = Firmware::new();
        fw.caps = caps.to_vec();
        fw.supplicant = supplicant;
        let mut station = init_station::<false>(fw)?;
        if station.supports_sae_offload() {
            return Err("SAE offload advertised without sae token and FWSUP");
        }
        let before = station.runtime.fw.log.len();
        if join(&mut station, MFPC | MFPR, Vec::new(), PASSWORD) != Err(Error::Unsupported)
            || station.runtime.fw.log.len() != before
        {
            return Err("SAE association reached firmware without offload support");
        }
    }
    // Malformed password, non-SAE AP and PMF-incapable AP fail before any
    // device write and keep the runtime usable.
    let mut station = init_station::<true>(sae_firmware(FirmwareVendor::Wcc))?;
    let before = station.runtime.fw.log.len();
    if join(&mut station, MFPC | MFPR, Vec::new(), &[0x61; 129]) != Err(Error::Malformed) {
        return Err("129-byte SAE password was accepted");
    }
    station.cache.clear();
    if join(&mut station, 0, Vec::new(), PASSWORD) != Err(Error::Unsupported) {
        return Err("SAE without PMF was accepted");
    }
    station.cache.clear();
    cache(&mut station, AP, 6, BssSecurity::Wpa2, &rsne(2, MFPC));
    let psk_ap = request(
        AP,
        6,
        SecurityConfig::Wpa3 {
            password: PASSWORD.to_vec(),
        },
        Vec::new(),
    );
    if ready(station.associate(psk_ap)) != Some(Err(Error::Unsupported)) {
        return Err("SAE to a PSK-only AP was accepted");
    }
    station.cache.clear();
    // An explicit request RSNE without MFPC cannot select SAE.
    if join(&mut station, MFPC | MFPR, rsne(SAE, 0), PASSWORD) != Err(Error::Unsupported) {
        return Err("SAE request RSNE without MFP was accepted");
    }
    if station.runtime.fw.log.len() != before || station.runtime.fw.failed {
        return Err("rejected SAE requests wrote to firmware");
    }
    // Firmware SAE failure (PSK_SUP not FWSUP_COMPLETED) is terminal and
    // the stale success that follows cannot authorize the port.
    let mut fw = sae_firmware(FirmwareVendor::Cyw);
    fw.join_events = false;
    fw.hook = Some(alloc::boxed::Box::new(|fw, command| {
        (command.direction == Direction::Set && command.command == 26).then(|| {
            fw.event(16, 0, 1, AP, &[]);
            fw.event(0, 0, 0, AP, &[]);
            fw.event(46, 5, 0, AP, &[]); // BRCMF_E_STATUS_FWSUP_FAIL_*.
            fw.event(46, 6, 0, AP, &[]);
            Ok(Vec::new())
        })
    }));
    let mut station = init_station::<false>(fw)?;
    station.cache.clear();
    if join(&mut station, MFPC | MFPR, Vec::new(), PASSWORD) != Err(Error::Firmware(5))
        || station.bssid.is_some()
        || station.runtime.fw.link.is_some()
        || !station.runtime.fw.failed
    {
        return Err("failed firmware SAE exchange did not close and poison the port");
    }
    Ok(())
}
fn smoke_fullmac_sae_offload_refusals_and_firmware_failure() -> TestResult {
    refusals().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sae",
    smoke_fullmac_sae_offload_refusals_and_firmware_failure
);
