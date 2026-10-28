// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware-internal roaming over the common FullMAC station: Linux
//! brcmfmac `brcmf_dongle_roam`, `brcmf_notify_roaming_status` and
//! `brcmf_bss_roaming_done` literals.
use super::{
    fullmac_fixture::*,
    ioctl::Direction,
    runtime::Error,
    station::{roam, Station},
};
use alloc::{boxed::Box, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::{scan::BssSecurity, SecurityConfig};

/// Firmware answering the roamed peer's current chanspec.
fn firmware(chanspec: u16) -> Firmware {
    let mut fw = Firmware::new();
    fw.hook = Some(Box::new(move |_, command| {
        (command.direction == Direction::Get && command.iovar() == Some(b"chanspec"))
            .then(|| Ok(u32::from(chanspec).to_le_bytes().to_vec()))
    }));
    fw
}

fn connected<const PCIE: bool>(chanspec: u16) -> Result<Station<Mock<PCIE>>, &'static str> {
    let mut station = init_station::<PCIE>(firmware(chanspec))?;
    ready(station.set_firmware_roaming(true))
        .ok_or("roaming setup pended")?
        .map_err(|_| "roaming setup failed")?;
    cache(&mut station, AP, 6, BssSecurity::Wpa2, &rsne(2, 0));
    let join = request(AP, 6, SecurityConfig::Wpa2 { psk: [0x11; 32] }, Vec::new());
    ready(station.associate(join))
        .ok_or("join pended")?
        .map_err(|_| "join failed")?;
    station.runtime.fw.link = Some(AP);
    Ok(station)
}

fn setup() -> Result<(), &'static str> {
    let mut station = init_station::<false>(Firmware::new())?;
    let start = station.runtime.fw.log.len();
    ready(station.set_firmware_roaming(true))
        .ok_or("pended")?
        .map_err(|_| "roaming setup failed")?;
    let fw = &station.runtime.fw;
    let mut trigger = (-75i32).to_le_bytes().to_vec();
    trigger.extend_from_slice(&3u32.to_le_bytes());
    let mut delta = 20u32.to_le_bytes().to_vec();
    delta.extend_from_slice(&3u32.to_le_bytes());
    let log = &fw.log[start..];
    let mask = roam::event_mask(true);
    if log.len() != 5
        || log[0].iovar() != Some(b"bcn_timeout")
        || log[0].value() != 2u32.to_le_bytes()
        || log[1].iovar() != Some(b"roam_off")
        || log[1].value() != 0u32.to_le_bytes()
        || (log[2].command, &log[2].body) != (55, &trigger)
        || (log[3].command, &log[3].body) != (57, &delta)
        || log[4].iovar() != Some(b"event_msgs")
        || log[4].value() != mask
        || mask[2] & (1 << 3) == 0
        || roam::event_mask(false)[2] & (1 << 3) != 0
    {
        return Err("roaming setup differs from brcmf_dongle_roam");
    }
    if !station.firmware_roaming() {
        return Err("roaming state not recorded");
    }
    // Disabling restores roam_off and the default beacon timeout.
    ready(station.set_firmware_roaming(false))
        .ok_or("pended")?
        .map_err(|_| "roaming disable failed")?;
    let log = &station.runtime.fw.log;
    let tail = &log[log.len() - 3..];
    if tail[0].value() != 4u32.to_le_bytes()
        || tail[1].value() != 1u32.to_le_bytes()
        || tail[2].value() != roam::event_mask(false)
    {
        return Err("roaming disable differs from roamoff");
    }
    // Connected stations cannot change roaming policy.
    let mut station = connected::<false>(0x100b)?;
    if ready(station.set_firmware_roaming(false)) != Some(Err(Error::Busy)) {
        return Err("roaming policy changed while connected");
    }
    Ok(())
}
fn smoke_fullmac_roam_engine_configuration() -> TestResult {
    setup().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/roam",
    smoke_fullmac_roam_engine_configuration
);

fn roam_to<const PCIE: bool>() -> Result<(), &'static str> {
    let mut station = connected::<PCIE>(0x100b)?;
    station.runtime.fw.bssid = AP2;
    station.runtime.fw.assoc_req_ies = rsne(2, 0);
    station.runtime.fw.assoc_resp_ies = vec![1, 1, 0x82];
    station.runtime.fw.event(19, 0, 0, AP2, &[]);
    station.poll().map_err(|_| "poll")?;
    if station.bssid.is_some()
        || station.runtime.fw.link.is_some()
        || station.roam_pending() != Some(AP2)
    {
        return Err("ROAM did not close the host port pending confirmation");
    }
    // Late old-peer link loss is ignored; keys are still pending.
    station.runtime.fw.event(16, 0, 0, AP, &[]);
    if ready(station.complete_roam()) != Some(Ok(None)) || station.roam_pending() != Some(AP2) {
        return Err("roam completed before FWSUP_COMPLETED or old link loss cancelled it");
    }
    station.runtime.fw.event(46, 6, 0, AP2, &[]);
    let before = station.runtime.fw.log.len();
    let roamed = ready(station.complete_roam())
        .ok_or("pended")?
        .map_err(|_| "roam confirmation failed")?
        .ok_or("roam not confirmed")?;
    if roamed
        != (roam::Roamed {
            bssid: AP2,
            frequency_mhz: 2462,
            request_ies: rsne(2, 0),
            response_ies: vec![1, 1, 0x82],
        })
        || station.bssid != Some(AP2)
        || station.runtime.fw.link != Some(AP2)
        || station.channel_width_mhz() != Some(20)
    {
        return Err("roamed peer not published with its native channel");
    }
    let log = &station.runtime.fw.log[before..];
    let qtx = log
        .iter()
        .position(|c| c.iovar() == Some(b"qtxpower"))
        .ok_or("qtxpower not re-applied for the roamed grant")?;
    let bssid = log
        .iter()
        .position(|c| c.command == 23)
        .ok_or("WLC_GET_BSSID missing")?;
    if bssid > qtx || log[qtx].value() != 68u32.to_le_bytes() {
        return Err("roam confirmation order or power differs");
    }
    // Disconnect after a roam waits for the new peer's link loss.
    ready(station.disconnect())
        .ok_or("pended")?
        .map_err(|_| "disconnect after roam")?;
    Ok(())
}

fn failures() -> Result<(), &'static str> {
    // Roaming disabled: a ROAM event changes nothing.
    let mut station = init_station::<false>(firmware(0x100b))?;
    cache(&mut station, AP, 6, BssSecurity::Open, &[]);
    ready(station.associate(request(AP, 6, SecurityConfig::Open, Vec::new())))
        .ok_or("pended")?
        .map_err(|_| "open join")?;
    station.runtime.fw.event(19, 0, 0, AP2, &[]);
    station.poll().map_err(|_| "poll")?;
    if station.bssid != Some(AP) || station.roam_pending().is_some() {
        return Err("ROAM handled with firmware roaming disabled");
    }
    // Channel outside policy, wrong current BSSID and a failed re-key are
    // terminal: the port stays closed and the runtime is poisoned.
    for fault in 0..3 {
        let chanspec = if fault == 0 { 0x100d } else { 0x100b };
        let mut station = connected::<true>(chanspec)?;
        station.runtime.fw.channels = vec![1, 6, 11, 13];
        station.runtime.fw.bssid = if fault == 1 { AP } else { AP2 };
        station.runtime.fw.event(19, 0, 0, AP2, &[]);
        station
            .runtime
            .fw
            .event(46, if fault == 2 { 5 } else { 6 }, 0, AP2, &[]);
        let result = ready(station.complete_roam()).ok_or("pended")?;
        let expected = [
            Err(Error::Unsupported),
            Err(Error::Malformed),
            Err(Error::Failed),
        ];
        if (fault < 2 && result != expected[fault])
            || (fault == 2 && result.is_ok())
            || station.bssid.is_some()
            || station.roam_pending().is_some()
            || station.runtime.fw.link.is_some()
            || !station.runtime.fw.failed
        {
            return Err("failed roam did not stay closed and poison the runtime");
        }
    }
    // Deauthentication by the new peer during a roam is a plain link loss.
    let mut station = connected::<false>(0x100b)?;
    station.runtime.fw.event(19, 0, 0, AP2, &[]);
    station.runtime.fw.event(6, 0, 0, AP2, &[]);
    station.poll().map_err(|_| "poll")?;
    if station.roam_pending().is_some() || station.bssid.is_some() || station.runtime.fw.failed {
        return Err("roam-time deauthentication not handled as link loss");
    }
    Ok(())
}
fn smoke_fullmac_roam_confirmation_publication_and_failures() -> TestResult {
    for result in [roam_to::<false>(), roam_to::<true>(), failures()] {
        if let Err(error) = result {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/roam",
    smoke_fullmac_roam_confirmation_publication_and_failures
);

const MDE: [u8; 5] = [54, 3, 0x12, 0x34, 0x01];

/// FT reassociation RSNE: `rsne(akm, MFPC|MFPR)` with one PMKR1Name.
fn ft_reassoc_rsne(akm: u8) -> Vec<u8> {
    let plain = rsne(akm, 0xc0);
    let mut body = plain[2..22].to_vec(); // through RSN capabilities
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&[0x77; 16]);
    body.extend_from_slice(&[0, 15, 172, 6]);
    let mut ie = vec![48, body.len() as u8];
    ie.extend_from_slice(&body);
    ie
}

fn fast_transition(sae: bool) -> Result<(), &'static str> {
    use narf_wireless::rsn::{AKM_FT_PSK, AKM_FT_SAE};
    let (akm, caps) = if sae {
        (AKM_FT_SAE, 0xc0)
    } else {
        (AKM_FT_PSK, 0)
    };
    let mut fw = firmware(0x100b);
    fw.caps.extend_from_slice(b" sae");
    fw.assoc_req_ies = rsne(akm, caps);
    fw.assoc_resp_ies = rsne(akm, caps);
    let mut station = init_station::<true>(fw)?;
    ready(station.set_firmware_roaming(true))
        .ok_or("pended")?
        .map_err(|_| "roaming")?;
    let mut ap = rsne(akm, caps);
    ap.extend_from_slice(&MDE);
    let security = || {
        if sae {
            SecurityConfig::Wpa3 {
                password: b"ft password".to_vec(),
            }
        } else {
            SecurityConfig::Wpa2 { psk: [0x22; 32] }
        }
    };
    let mut ie = rsne(akm, caps);
    ie.extend_from_slice(&MDE);
    // Without a Mobility Domain element the FT AKM is refused untouched.
    cache(&mut station, AP, 6, BssSecurity::Wpa2, &rsne(akm, caps));
    let before = station.runtime.fw.log.len();
    if ready(station.associate(request(AP, 6, security(), ie.clone())))
        != Some(Err(Error::Unsupported))
        || station.runtime.fw.log.len() != before
    {
        return Err("FT AKM admitted without a Mobility Domain element");
    }
    station.cache.clear();
    cache(&mut station, AP, 6, BssSecurity::Wpa2, &ap);
    ready(station.associate(request(AP, 6, security(), ie)))
        .ok_or("pended")?
        .map_err(|_| "FT initial mobility-domain association failed")?;
    let fw = &station.runtime.fw;
    let wpa_auth = fw.iovars(Direction::Set, b"wpa_auth");
    let wpaie = fw.iovars(Direction::Set, b"wpaie");
    let expected = if sae { 0x44000u32 } else { 0x4080 };
    if wpa_auth.last().map(Vec::as_slice) != Some(&expected.to_le_bytes()[..])
        || wpaie.first().map(Vec::as_slice) != Some(rsne(akm, caps).as_slice())
    {
        return Err("FT wpa_auth/wpaie differ from brcmf_set_key_mgmt");
    }
    // Over-the-air FT inside the firmware roam: the reassociation RSNE
    // carries PMKR1Name, which does not fail PMF re-verification.
    station.runtime.fw.link = Some(AP);
    station.runtime.fw.bssid = AP2;
    station.runtime.fw.assoc_req_ies = ft_reassoc_rsne(akm);
    station.runtime.fw.assoc_resp_ies = ft_reassoc_rsne(akm);
    station.runtime.fw.event(19, 0, 0, AP2, &[]);
    station.runtime.fw.event(46, 6, 0, AP2, &[]);
    let roamed = ready(station.complete_roam())
        .ok_or("pended")?
        .map_err(|_| "FT roam confirmation failed")?
        .ok_or("FT roam not confirmed")?;
    if roamed.bssid != AP2 || station.bssid != Some(AP2) {
        return Err("FT roam did not publish the target AP");
    }
    if sae && !station.management_protection() {
        return Err("FT-SAE roam lost verified PMF");
    }
    Ok(())
}
fn smoke_fullmac_fast_bss_transition_psk_and_sae() -> TestResult {
    for sae in [false, true] {
        if let Err(error) = fast_transition(sae) {
            return TestResult::Fail(error);
        }
    }
    let vectors = [
        (narf_wireless::rsn::AKM_PSK, 0x80),
        (narf_wireless::rsn::AKM_FT_PSK, 0x4080),
        (narf_wireless::rsn::AKM_SAE, 0x40000),
        (narf_wireless::rsn::AKM_FT_SAE, 0x44000),
    ];
    if vectors
        .iter()
        .any(|&(akm, auth)| super::station::ft::wpa_auth(akm) != auth)
    {
        return TestResult::Fail("wpa_auth table differs from brcmu_wifi.h");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ft",
    smoke_fullmac_fast_bss_transition_psk_and_sae
);
