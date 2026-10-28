//! `FakeAp` SAE / PMF profiles against the shared station stack
//! (`JoinPlan` + `SaeSession` + `station_security::Security`).
use crate::{ApPmf, ApSaePwe, FakeAp, NetworkPlan};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::association::{
    AkmSet, Bss, JoinOptions, JoinPlan, Pmf, SaePwe, SaeStep, SecurityMode,
};
use narf_wireless::eapol::KeyMgmt;
use narf_wireless::sae::SaeSession;
use narf_wireless::station_security::{MgmtRx, RawFrame, Rx, Security};

const PLAN: NetworkPlan = NetworkPlan {
    station: [2, 0x11, 0x22, 0x33, 0x44, 0x55],
    bssid: [2, 1, 2, 3, 4, 5],
    server_ip: [10, 77, 0, 1],
    lease_ip: [10, 77, 0, 42],
    netmask: [255, 255, 255, 0],
    lease_seconds: 3600,
};
const SSID: &[u8] = b"narf-pmf";
const PASSWORD: &[u8] = b"correct horse battery";
const PMK: [u8; 32] = [0x55; 32];

struct Raw(Vec<u8>);
impl RawFrame for Raw {
    fn bytes(&self) -> &[u8] {
        &self.0
    }
    fn unmodified(&self) -> bool {
        true
    }
}

macro_rules! case {
    ($kernel:ident, $body:block) => {
        fn $kernel() -> TestResult {
            let run = || -> Result<(), &'static str> { $body };
            match run() {
                Ok(()) => TestResult::Pass,
                Err(e) => TestResult::Fail(e),
            }
        }
        kernel_test_in!("verification/wifi-fixtures", $kernel);
    };
}

fn bss(ap: &FakeAp) -> Bss {
    let beacon = ap.beacon();
    Bss {
        bssid: PLAN.bssid,
        ssid: SSID.to_vec(),
        channel: 6,
        band: None,
        signal_dbm: None,
        capability: u16::from_le_bytes([beacon[34], beacon[35]]),
        beacon_interval: 100,
        information_elements: beacon[36..].to_vec(),
    }
}
/// The body of the element `id` in the beacon.
fn beacon_element(ap: &FakeAp, id: u8) -> Option<Vec<u8>> {
    let beacon = ap.beacon();
    let mut ies = &beacon[36..];
    while ies.len() >= 2 {
        let len = usize::from(ies[1]);
        if ies[0] == id {
            return ies.get(2..2 + len).map(<[u8]>::to_vec);
        }
        ies = ies.get(2 + len..)?;
    }
    None
}
/// Run association and the 4-way handshake; returns the station owner.
fn handshake(
    ap: &mut FakeAp,
    plan: &mut JoinPlan,
    assoc: Vec<u8>,
    owner: impl FnOnce(&JoinPlan) -> Result<Security, &'static str>,
) -> Result<Security, &'static str> {
    let replies = ap.receive(&assoc).map_err(|_| "AP refused association")?;
    let [response, m1] = replies.as_slice() else {
        return Err("AP did not send association response + M1");
    };
    plan.association_response(response)
        .map_err(|_| "station refused association response")?;
    let mut security = owner(plan)?;
    if security.receive(&Raw(m1.clone()), [0x73; 32]) != Ok(Rx::ReplyReady) {
        return Err("station refused M1");
    }
    let m2 = security.pending_frame().ok_or("no M2")?.to_vec();
    security
        .reply_delivered(m2.len())
        .map_err(|_| "M2 delivery")?;
    let replies = ap.receive(&m2).map_err(|_| "AP refused M2")?;
    let m3 = replies.first().ok_or("no M3")?;
    if security.receive(&Raw(m3.clone()), [0x73; 32]) != Ok(Rx::ReplyReady) {
        return Err("station refused M3");
    }
    let m4 = security.pending_frame().ok_or("no M4")?.to_vec();
    security
        .reply_delivered(m4.len())
        .map_err(|_| "M4 delivery")?;
    if ap.receive(&m4).map_err(|_| "AP refused M4")?.is_empty() && security.port_open() {
        Ok(security)
    } else {
        Err("handshake did not authorize")
    }
}
fn deauth_checks(ap: &mut FakeAp, security: &mut Security) -> Result<(), &'static str> {
    if !security.pmf() || !ap.pmf() || ap.igtk().is_none() {
        return Err("PMF not negotiated on both sides");
    }
    let protected = ap.bip_broadcast_deauth(3).map_err(|_| "BIP deauth")?;
    match security.receive_management(&Raw(protected.clone())) {
        Ok(MgmtRx::Frame(frame)) if frame.len() == 26 && frame[24..] == [3, 0] => {}
        _ => return Err("station rejected the BIP-protected broadcast deauth"),
    }
    if security.receive_management(&Raw(protected)) != Ok(MgmtRx::Ignored) {
        return Err("replayed BIP deauth accepted");
    }
    let mut plain = ap.bip_broadcast_deauth(3).map_err(|_| "BIP deauth")?;
    plain.truncate(26);
    if security.receive_management(&Raw(plain)) != Ok(MgmtRx::Ignored) {
        return Err("unprotected broadcast deauth accepted under PMF");
    }
    Ok(())
}

fn sae_join(pwe: ApSaePwe, ap_akms: &[u8], options: JoinOptions) -> Result<KeyMgmt, &'static str> {
    let mut ap = FakeAp::wpa3_sae(PLAN, SSID, 6, 3, PASSWORD, pwe, [0xaa; 32])
        .and_then(|ap| ap.with_akms(ap_akms))
        .map_err(|_| "AP configuration")?;
    let security = SecurityMode::Wpa3Sae { pwe: SaePwe::Both };
    let mut plan =
        JoinPlan::prepare_with_options(&bss(&ap), PLAN.station, SSID, security, None, options)
            .map_err(|_| "station refused the SAE AP")?;
    let join = plan.sae().ok_or("no SAE plan")?.clone();
    if join.h2e() != (pwe == ApSaePwe::HashToElement) {
        return Err("PWE method");
    }
    let mut session = if join.h2e() {
        SaeSession::new_h2e_bytes(SSID, PASSWORD, PLAN.station, PLAN.bssid)
    } else {
        SaeSession::new_hunt_and_peck(PASSWORD, PLAN.station, PLAN.bssid)
    }
    .with_test_seed([0x31; 64]);
    if let Some(selector) = join.akm_suite_selector() {
        session = session
            .with_akm_suite_selector(selector)
            .map_err(|_| "AKM selector")?;
    }
    session.build_commit();
    let mut out = plan
        .start_sae_authentication(&session)
        .map_err(|_| "SAE commit")?
        .to_vec();
    let assoc = loop {
        let replies = ap.receive(&out).map_err(|_| "AP refused SAE frame")?;
        let reply = replies.first().ok_or("AP sent no SAE reply")?;
        match plan
            .sae_authentication_response(reply, &mut session)
            .map_err(|_| "station refused AP SAE frame")?
        {
            SaeStep::Transmit(frame) => out = frame.to_vec(),
            SaeStep::Associate(frame) => break frame.to_vec(),
            SaeStep::Ignored => return Err("AP SAE frame ignored"),
        }
    };
    let pmk = *session.pmk().ok_or("no station PMK")?;
    let rsnxe = join.station_rsnxe();
    let ap_rsne = beacon_element(&ap, 48).ok_or("AP RSNE")?;
    let ap_rsnxe = beacon_element(&ap, 244);
    let mut security = handshake(&mut ap, &mut plan, assoc, |plan| {
        Security::new_sae(
            PLAN.station,
            PLAN.bssid,
            &pmk,
            &plan.rsn_body().ok_or("RSNE")?,
            rsnxe.as_deref(),
            &ap_rsne,
            ap_rsnxe.as_deref(),
            0,
        )
        .map_err(|_| "Security::new_sae")
    })?;
    if ap.akm() != Some(join.akm()) || ap.pairwise_tk().is_none() {
        return Err("AP negotiated another AKM");
    }
    deauth_checks(&mut ap, &mut security)?;
    Ok(join.akm())
}

case!(smoke_fake_ap_sae_h2e_pmf_igtk_and_bip_deauth, {
    if sae_join(ApSaePwe::HashToElement, &[8], JoinOptions::default())? != KeyMgmt::Sae {
        return Err("H2E AP did not negotiate AKM 8");
    }
    Ok(())
});
case!(smoke_fake_ap_sae_hunt_and_peck, {
    if sae_join(ApSaePwe::HuntAndPeck, &[8], JoinOptions::default())? != KeyMgmt::Sae {
        return Err("hunting-and-pecking AP did not negotiate AKM 8");
    }
    Ok(())
});
case!(smoke_fake_ap_sae_ext_key_and_akm8_fallback, {
    if sae_join(ApSaePwe::HashToElement, &[8, 24], JoinOptions::default())? != KeyMgmt::SaeExtKey {
        return Err("AKM 8+24 H2E AP did not negotiate AKM 24 by default");
    }
    let no24 = JoinOptions::default().with_akms(AkmSet::LEGACY.without(AkmSet::SAE_EXT_KEY));
    if sae_join(ApSaePwe::HashToElement, &[8, 24], no24)? != KeyMgmt::Sae {
        return Err("station without AKM 24 did not fall back to AKM 8");
    }
    Ok(())
});

case!(smoke_fake_ap_wpa2_pmf_psk_sha256, {
    let mut ap = FakeAp::wpa2(PLAN, SSID, 6, 3, PMK, [0xaa; 32])
        .and_then(|ap| ap.with_pmf(ApPmf::Required))
        .and_then(|ap| ap.with_akms(&[6]))
        .map_err(|_| "AP configuration")?;
    // A legacy station (no PMF) is refused by the MFPR AP's beacon.
    if JoinPlan::prepare(&bss(&ap), PLAN.station, SSID, SecurityMode::Wpa2Psk).is_ok() {
        return Err("no-PMF station admitted an MFPR AP");
    }
    let options = JoinOptions::default()
        .with_akms(AkmSet::ALL)
        .with_pmf(Pmf::Optional);
    let mut plan = JoinPlan::prepare_with_options(
        &bss(&ap),
        PLAN.station,
        SSID,
        SecurityMode::Wpa2Psk,
        None,
        options,
    )
    .map_err(|_| "PMF station refused the AP")?;
    let auth = plan.start_authentication().map_err(|_| "auth")?.to_vec();
    let replies = ap.receive(&auth).map_err(|_| "AP refused auth")?;
    let assoc = plan
        .authentication_response(replies.first().ok_or("no auth reply")?)
        .map_err(|_| "station refused auth reply")?
        .ok_or("auth reply ignored")?
        .to_vec();
    let ap_rsne = beacon_element(&ap, 48).ok_or("AP RSNE")?;
    let mut security = handshake(&mut ap, &mut plan, assoc, |plan| {
        Security::new(
            PLAN.station,
            PLAN.bssid,
            &PMK,
            &plan.rsn_body().ok_or("RSNE")?,
            &ap_rsne,
            None,
            0,
        )
        .map_err(|_| "Security::new")
    })?;
    if ap.akm() != Some(KeyMgmt::PskSha256) {
        return Err("AP did not negotiate PSK-SHA256");
    }
    deauth_checks(&mut ap, &mut security)
});

case!(smoke_fake_ap_legacy_wpa2_has_no_pmf, {
    let mut ap = FakeAp::wpa2(PLAN, SSID, 6, 3, PMK, [0xaa; 32]).map_err(|_| "AP")?;
    if ap.bip_broadcast_deauth(3).is_ok() || ap.igtk().is_some() || ap.pmf() {
        return Err("legacy WPA2 AP offers PMF");
    }
    if FakeAp::open(PLAN, SSID, 6, 3)
        .map_err(|_| "open AP")?
        .with_pmf(ApPmf::Optional)
        .is_ok()
    {
        return Err("open AP accepted PMF");
    }
    Ok(())
});
