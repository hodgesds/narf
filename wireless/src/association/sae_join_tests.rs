use super::*;
use crate::association::{Bss, Error, JoinPlan, Phase, SecurityMode};
use crate::rsn::{RsnIe, Suite};
use crate::sae::SaeSession;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
const SSID: &[u8] = b"narf";
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
        kernel_test_in!("wireless/association/sae", $name);
    };
}
fn element(bytes: &mut Vec<u8>, id: u8, body: &[u8]) {
    bytes.extend_from_slice(&[id, body.len() as u8]);
    bytes.extend_from_slice(body);
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
const MFP: u16 = rsn::RSN_CAP_MFP_CAPABLE | rsn::RSN_CAP_MFP_REQUIRED;
fn bss(rsne: Option<Vec<u8>>, rsnxe: Option<u8>, h2e_only: bool) -> Bss {
    let mut ies = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x82, 0x84, 0x8b];
    if h2e_only {
        element(&mut ies, 50, &[0x80 | 123]);
    }
    if let Some(rsne) = rsne {
        element(&mut ies, 48, &rsne);
    }
    if let Some(x) = rsnxe {
        element(&mut ies, 244, &[x]);
    }
    Bss {
        bssid: AP,
        ssid: SSID.to_vec(),
        channel: 1,
        signal_dbm: None,
        capability: 0x11,
        beacon_interval: 100,
        information_elements: ies,
    }
}
fn sae_ap() -> Bss {
    bss(Some(ap_rsne(&[8], MFP)), Some(0x20), false)
}
fn plan(ap: &Bss, pwe: SaePwe) -> Result<JoinPlan, Error> {
    JoinPlan::prepare(ap, OWN, SSID, SecurityMode::Wpa3Sae { pwe })
}
fn plan_err(ap: &Bss, pwe: SaePwe) -> Option<Error> {
    plan(ap, pwe).err()
}
/// AP -> station Authentication frame.
fn from_ap(seq: u16, status: u16, body: &[u8]) -> Vec<u8> {
    let mut f = vec![0xb0, 0, 0, 0];
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&3u16.to_le_bytes());
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(&status.to_le_bytes());
    f.extend_from_slice(body);
    f
}
fn sessions(h2e: bool, pw_ap: &[u8], akm24: bool) -> (SaeSession, SaeSession) {
    let mk = |own, peer, pw: &[u8], seed| {
        let s = if h2e {
            SaeSession::new_h2e_bytes(SSID, pw, own, peer)
        } else {
            SaeSession::new_hunt_and_peck(pw, own, peer)
        }
        .with_test_seed([seed; 64]);
        if akm24 {
            s.with_akm_suite_selector([0, 0x0f, 0xac, 24]).unwrap()
        } else {
            s
        }
    };
    (mk(OWN, AP, b"secret", 0x31), mk(AP, OWN, pw_ap, 0x42))
}
fn rsne_of(frame: &[u8]) -> Option<RsnIe> {
    let mut at = 28;
    while at + 2 <= frame.len() {
        let len = usize::from(frame[at + 1]);
        if frame[at] == 48 {
            return RsnIe::decode_body(&frame[at + 2..at + 2 + len]);
        }
        at += 2 + len;
    }
    None
}
fn assoc_response(capability: u16) -> Vec<u8> {
    let mut b = vec![0x10, 0, 0, 0];
    b.extend_from_slice(&OWN);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&capability.to_le_bytes());
    b.extend_from_slice(&[0, 0, 7, 0xc0]);
    b.extend_from_slice(&[1, 3, 0x82, 0x84, 0x8b]);
    b
}
/// Drive a complete exchange; returns the plan after Associate.
fn exchange(ap: &Bss, pwe: SaePwe, h2e: bool, akm24: bool) -> Result<JoinPlan, &'static str> {
    let mut plan = plan(ap, pwe).map_err(|_| "SAE AP refused")?;
    let (mut sta, mut peer) = sessions(h2e, b"secret", akm24);
    sta.build_commit();
    let commit = plan
        .start_sae_authentication(&sta)
        .map_err(|_| "commit refused")?
        .to_vec();
    let status = if h2e { 126 } else { 0 };
    check!(
        commit[24..30] == [3, 0, 1, 0, status as u8, 0] && commit[30..] == sta.commit_body(None),
        "commit frame layout"
    );
    check!(
        plan.sae_pending_frame() == Some(commit.as_slice()),
        "commit not pending"
    );
    let peer_commit = peer.build_commit();
    peer.on_commit(&commit[30..])
        .map_err(|_| "AP rejected commit")?;
    let confirm =
        match plan.sae_authentication_response(&from_ap(1, status, &peer_commit), &mut sta) {
            Ok(SaeStep::Transmit(f)) => f.to_vec(),
            _ => return Err("peer commit not answered with a confirm"),
        };
    check!(confirm[24..30] == [3, 0, 2, 0, 0, 0], "confirm header");
    // The AP sends its Confirm (entering Confirmed) before verifying ours.
    let peer_confirm = peer.build_confirm();
    peer.on_confirm(&confirm[30..])
        .map_err(|_| "AP rejected confirm")?;
    let assoc = match plan.sae_authentication_response(&from_ap(2, 0, &peer_confirm), &mut sta) {
        Ok(SaeStep::Associate(f)) => f.to_vec(),
        _ => return Err("peer confirm did not complete SAE"),
    };
    let rsne = rsne_of(&assoc).ok_or("assoc request lacks RSNE")?;
    check!(
        rsne.pmkids == vec![*sta.pmkid().unwrap()]
            && rsne.rsn_capabilities == MFP
            && rsne.akms == vec![Suite::standard(if akm24 { 24 } else { 8 })]
            && assoc[24] & 0x10 != 0
            && plan.phase() == Phase::AwaitAssociation
            && sta.pmk() == peer.pmk(),
        "association request RSNE/PMKID/privacy"
    );
    Ok(plan)
}

fn admission() -> Result<(), &'static str> {
    let p = plan(&sae_ap(), SaePwe::Both).map_err(|_| "SAE AP refused")?;
    let sae = p.sae().unwrap();
    check!(
        sae.h2e() && sae.akm() == KeyMgmt::Sae && sae.station_rsnxe() == Some(vec![0x20]),
        "Both did not pick H2E/AKM8"
    );
    let ext = bss(Some(ap_rsne(&[8, 24], MFP)), Some(0x20), false);
    check!(
        plan(&ext, SaePwe::Both).is_ok_and(|p| p.sae().unwrap().akm() == KeyMgmt::SaeExtKey),
        "AKM 24 not preferred under H2E"
    );
    check!(
        plan(&ext, SaePwe::HuntAndPeck).is_ok_and(|p| {
            let s = p.sae().unwrap();
            s.akm() == KeyMgmt::Sae && !s.h2e() && s.station_rsnxe().is_none()
        }),
        "hunting-and-pecking did not fall back to AKM 8"
    );
    let only24 = bss(Some(ap_rsne(&[24], MFP)), Some(0x20), false);
    check!(
        plan_err(&only24, SaePwe::HuntAndPeck) == Some(Error::UnsupportedSecurity),
        "AKM 24 admitted without H2E"
    );
    let no_mfp = bss(Some(ap_rsne(&[8], 0)), Some(0x20), false);
    check!(
        plan_err(&no_mfp, SaePwe::Both) == Some(Error::UnsupportedSecurity),
        "AP without MFPC admitted"
    );
    let no_h2e = bss(Some(ap_rsne(&[8], MFP)), None, false);
    check!(
        plan_err(&no_h2e, SaePwe::HashToElement) == Some(Error::UnsupportedSecurity)
            && plan(&no_h2e, SaePwe::Both).is_ok_and(|p| !p.sae().unwrap().h2e()),
        "H2E policy against a non-H2E AP"
    );
    let h2e_only = bss(Some(ap_rsne(&[8], MFP)), Some(0x20), true);
    check!(
        plan(&h2e_only, SaePwe::Both).is_ok()
            && plan_err(&h2e_only, SaePwe::HuntAndPeck) == Some(Error::UnsupportedRates),
        "SAE-H2E membership selector admission"
    );
    let inconsistent = bss(Some(ap_rsne(&[8], MFP)), None, true);
    check!(
        plan_err(&inconsistent, SaePwe::Both) == Some(Error::InvalidBss),
        "H2E selector without RSNXE H2E admitted"
    );
    check!(
        JoinPlan::prepare(&h2e_only, OWN, SSID, SecurityMode::Wpa2Psk).is_err()
            && JoinPlan::prepare(&sae_ap(), OWN, SSID, SecurityMode::Wpa2Psk).is_err()
            && JoinPlan::prepare(&sae_ap(), OWN, SSID, SecurityMode::Open).is_err(),
        "non-SAE modes admitted an SAE-only AP"
    );
    let open = bss(None, None, false);
    let mut open = open;
    open.capability = 1;
    check!(
        plan_err(&open, SaePwe::Both) == Some(Error::UnsupportedSecurity),
        "SAE admitted an open AP"
    );
    let mut p = plan(&sae_ap(), SaePwe::Both).unwrap();
    check!(
        p.start_authentication() == Err(Error::UnsupportedSecurity),
        "open authentication on an SAE plan"
    );
    Ok(())
}
smoke!(
    smoke_sae_join_admission_akm_pwe_pmf_and_h2e_selector,
    admission
);

fn full_exchange() -> Result<(), &'static str> {
    let mut plan = exchange(&sae_ap(), SaePwe::Both, true, false)?;
    check!(
        plan.association_response(&assoc_response(0x11)) == Ok(Some(7)),
        "SAE association response refused"
    );
    let body = plan.rsn_body().unwrap();
    check!(
        RsnIe::decode_body(&body).is_some_and(|r| r.pmkids.len() == 1),
        "rsn_body lacks the PMKID for the supplicant"
    );
    let no_h2e = bss(Some(ap_rsne(&[8], MFP)), None, false);
    exchange(&no_h2e, SaePwe::Both, false, false)?;
    let ext = bss(Some(ap_rsne(&[24], MFP)), Some(0x20), false);
    exchange(&ext, SaePwe::HashToElement, true, true)?;
    // An unprotected association response is refused.
    let mut plan = exchange(&sae_ap(), SaePwe::Both, true, false)?;
    check!(
        plan.association_response(&assoc_response(0x01)).is_err(),
        "association without privacy admitted"
    );
    Ok(())
}
smoke!(
    smoke_sae_join_full_h2e_hnp_and_akm24_exchange,
    full_exchange
);

fn anti_clogging() -> Result<(), &'static str> {
    let mut plan = plan(&sae_ap(), SaePwe::Both).unwrap();
    let (mut sta, _) = sessions(true, b"secret", false);
    sta.build_commit();
    plan.start_sae_authentication(&sta).unwrap();
    let request = |tok: &[u8]| {
        let mut b = vec![19, 0, 0xff, 1 + tok.len() as u8, 93];
        b.extend_from_slice(tok);
        from_ap(1, 76, &b)
    };
    for round in 0..MAX_ANTI_CLOGGING {
        match plan.sae_authentication_response(&request(&[0xab, round]), &mut sta) {
            Ok(SaeStep::Transmit(f)) => {
                check!(
                    f[30..] == sta.commit_body(Some(&[0xab, round]))[..]
                        && f.ends_with(&[0xff, 3, 93, 0xab, round]),
                    "token container not echoed"
                );
            }
            _ => return Err("anti-clogging request not answered"),
        }
    }
    check!(
        plan.sae_authentication_response(&request(&[1]), &mut sta) == Err(Error::Rejected(76))
            && plan.phase() == Phase::Failed
            && plan.sae_pending_frame().is_none(),
        "unbounded anti-clogging rounds"
    );
    let mut plan = self::plan(&sae_ap(), SaePwe::Both).unwrap();
    let (mut sta, _) = sessions(true, b"secret", false);
    sta.build_commit();
    plan.start_sae_authentication(&sta).unwrap();
    check!(
        plan.sae_authentication_response(&from_ap(1, 76, &[20, 0, 0xff, 2, 93, 1]), &mut sta)
            == Err(Error::Protocol),
        "anti-clogging for another group accepted"
    );
    Ok(())
}
smoke!(smoke_sae_join_anti_clogging_bounded, anti_clogging);

fn failures() -> Result<(), &'static str> {
    let ready = |h2e_plan: bool| {
        let ap = if h2e_plan {
            sae_ap()
        } else {
            bss(Some(ap_rsne(&[8], MFP)), None, false)
        };
        let mut plan = plan(&ap, SaePwe::Both).unwrap();
        let (mut sta, mut peer) = sessions(h2e_plan, b"secret", false);
        sta.build_commit();
        let commit = plan.start_sae_authentication(&sta).unwrap().to_vec();
        let pc = peer.build_commit();
        peer.on_commit(&commit[30..]).unwrap();
        (plan, sta, peer, pc, commit)
    };
    // Rejection status and PWE status mismatch.
    let (mut plan, mut sta, _, pc, _) = ready(true);
    check!(
        plan.sae_authentication_response(&from_ap(1, 1, &pc), &mut sta) == Err(Error::Rejected(1)),
        "commit rejection not terminal"
    );
    let (mut plan, mut sta, _, pc, _) = ready(true);
    check!(
        plan.sae_authentication_response(&from_ap(1, 0, &pc), &mut sta) == Err(Error::Protocol),
        "H2E plan accepted a status-0 commit"
    );
    // Confirm before commit.
    let (mut plan, mut sta, _, _, _) = ready(true);
    check!(
        plan.sae_authentication_response(&from_ap(2, 0, &[0; 34]), &mut sta)
            == Err(Error::Protocol),
        "confirm before commit accepted"
    );
    // Reflection: our own commit back is silently discarded.
    let (mut plan, mut sta, _, _, commit) = ready(true);
    check!(
        plan.sae_authentication_response(&from_ap(1, 126, &commit[30..]), &mut sta)
            == Ok(SaeStep::Ignored)
            && plan.phase() == Phase::AwaitAuthentication,
        "reflected commit not discarded"
    );
    // Other peers are ignored.
    let (mut plan, mut sta, _, pc, _) = ready(true);
    let mut foreign = from_ap(1, 126, &pc);
    foreign[10] ^= 0x80;
    check!(
        plan.sae_authentication_response(&foreign, &mut sta) == Ok(SaeStep::Ignored),
        "foreign frame processed"
    );
    // Wrong password: the Confirm fails and nothing is associated.
    let mut plan = self::plan(&sae_ap(), SaePwe::Both).unwrap();
    let (mut sta, mut peer) = sessions(true, b"wrong", false);
    sta.build_commit();
    let commit = plan.start_sae_authentication(&sta).unwrap().to_vec();
    let pc = peer.build_commit();
    peer.on_commit(&commit[30..]).unwrap();
    plan.sae_authentication_response(&from_ap(1, 126, &pc), &mut sta)
        .map_err(|_| "commit")?;
    let bad = peer.build_confirm();
    check!(
        plan.sae_authentication_response(&from_ap(2, 0, &bad), &mut sta) == Err(Error::Protocol)
            && plan.phase() == Phase::Failed
            && plan.sae().unwrap().pmkid().is_none()
            && rsne_of(
                &plan
                    .rsn_body()
                    .map(|b| {
                        let mut f = vec![0; 28];
                        f.extend_from_slice(&[48, b.len() as u8]);
                        f.extend_from_slice(&b);
                        f
                    })
                    .unwrap()
            )
            .is_some_and(|r| r.pmkids.is_empty()),
        "bad confirm admitted"
    );
    // Session binding: a hunting-and-pecking session for an H2E plan, an
    // uncommitted session, swapped addresses and an AKM 24 mismatch.
    let mut plan = self::plan(&sae_ap(), SaePwe::Both).unwrap();
    let (mut hnp, _) = sessions(false, b"secret", false);
    hnp.build_commit();
    let fresh = SaeSession::new_h2e_bytes(SSID, b"secret", OWN, AP);
    let mut swapped = SaeSession::new_h2e_bytes(SSID, b"secret", AP, OWN).with_test_seed([9; 64]);
    swapped.build_commit();
    let (mut bound24, _) = sessions(true, b"secret", true);
    bound24.build_commit();
    check!(
        plan.start_sae_authentication(&hnp) == Err(Error::UnsupportedSecurity)
            && plan.start_sae_authentication(&fresh) == Err(Error::UnsupportedSecurity)
            && plan.start_sae_authentication(&swapped) == Err(Error::UnsupportedSecurity)
            && plan.start_sae_authentication(&bound24) == Err(Error::UnsupportedSecurity)
            && plan.phase() == Phase::Prepared,
        "mismatched session bound"
    );
    // Cancel clears the retransmission frame.
    let (mut plan, _, _, _, _) = ready(true);
    plan.cancel();
    check!(
        plan.sae_pending_frame().is_none() && plan.phase() == Phase::Failed,
        "cancel kept an SAE frame"
    );
    Ok(())
}
smoke!(
    smoke_sae_join_rejections_reflection_binding_and_cancel,
    failures
);
