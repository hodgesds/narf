// SPDX-License-Identifier: GPL-2.0-or-later
//! WPA3-Personal (SAE) admission and Authentication-frame exchange for the
//! shared `JoinPlan`.
//!
//! Security negotiation mirrors wpa_supplicant `wpa_supplicant_set_suites`
//! / `wpa_gen_wpa_ie_rsn` / `wpa_gen_rsnxe` with `ieee80211w=2` (PMF
//! required) and `sae_pwe` 0/1/2, and mac80211's SAE_H2E membership
//! selector handling (mlme.c `ieee80211_determine_chan_mode`, selectors
//! supplied by the SME). The Authentication exchange mirrors wpa_supplicant
//! `sme_sae_auth` over mac80211 `ieee80211_rx_mgmt_auth` (algorithm 3):
//! Commit (status 0 or 126 SAE_HASH_TO_ELEMENT), anti-clogging retries
//! (status 76), reflection discard, Confirm, then PMKID in the association
//! request RSNE (IEEE802.11-2020 12.4, 9.4.2.24, 9.4.2.241).
//!
//! The PMK, KCK and password stay inside the caller's `SaeSession`; this
//! plan only binds frames to the retained addresses and transaction state.
use super::{management, Error, JoinPlan, Phase};
use crate::eapol::KeyMgmt;
use crate::rsn::{self, RsnIe, Suite};
use crate::sae::{SaeError, SaeSession, SaeState};
use alloc::{vec, vec::Vec};

/// `WLAN_AUTH_SAE`.
const AUTH_SAE: u16 = 3;
/// `WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ`.
const STATUS_ANTI_CLOGGING: u16 = 76;
/// `WLAN_STATUS_SAE_HASH_TO_ELEMENT`.
const STATUS_H2E: u16 = 126;
/// `WLAN_EID_EXT_ANTI_CLOGGING_TOKEN`.
const EXT_TOKEN: u8 = 93;
/// Anti-clogging rounds before giving up (wpa_supplicant resends the Commit
/// for every token request; NARF bounds it like the ath11k driver path).
pub const MAX_ANTI_CLOGGING: u8 = 3;

/// wpa_supplicant `sae_pwe`: which SAE password-element derivations the
/// station may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaePwe {
    /// `sae_pwe=0`: hunting-and-pecking only (IEEE802.11-2020 12.4.4.2.2).
    HuntAndPeck,
    /// `sae_pwe=1`: hash-to-element only (12.4.4.2.3).
    HashToElement,
    /// `sae_pwe=2`: H2E when the AP's RSNXE advertises it, else
    /// hunting-and-pecking.
    Both,
}

/// One step of the SAE Authentication exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaeStep<'a> {
    /// Not addressed to this transaction, a reflected Commit, or a
    /// retransmitted peer Commit after ours was answered. Nothing changes.
    Ignored,
    /// Transmit this Authentication frame (a Commit with an anti-clogging
    /// token, or our Confirm).
    Transmit(&'a [u8]),
    /// SAE accepted: transmit this association request (its RSNE carries
    /// the SAE PMKID).
    Associate(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Auth {
    Idle,
    AwaitCommit,
    AwaitConfirm,
    Done,
    Failed,
}

/// The negotiated SAE profile and Authentication transaction state.
#[derive(Clone, Debug)]
pub struct SaeJoin {
    akm: KeyMgmt,
    h2e: bool,
    advertise_h2e: bool,
    auth: Auth,
    tokens: u8,
    pmkid: Option<[u8; 16]>,
    frame: Vec<u8>,
}

impl SaeJoin {
    /// Admit an AP for SAE. `h2e_required` is the SAE-H2E BSS membership
    /// selector (123) in the AP's basic rate set.
    pub(super) fn negotiate(
        pwe: SaePwe,
        capability: u16,
        ap: &RsnIe,
        rsnxe: Option<&[u8]>,
        h2e_required: bool,
        akms: super::AkmSet,
    ) -> Result<Self, Error> {
        if let Some(b) = rsnxe {
            // Extended RSN Capabilities: bits0..3 are the field length - 1.
            if b.is_empty() || usize::from(b[0] & 15) + 1 != b.len() {
                return Err(Error::InvalidBss);
            }
        }
        let ap_h2e = rsnxe.is_some_and(|b| b[0] & rsn::RSNX_CAP_SAE_H2E != 0);
        if h2e_required && !ap_h2e {
            // An H2E-only BSS must advertise H2E in its RSNXE.
            return Err(Error::InvalidBss);
        }
        let ccmp = Suite::standard(rsn::CIPHER_CCMP_128);
        if capability & 0x10 == 0
            || ap.group_cipher != ccmp
            || !ap.pairwise_ciphers.contains(&ccmp)
            || ap.rsn_capabilities & rsn::RSN_CAP_NO_PAIRWISE != 0
            // ieee80211w=2: "PMF required but AP not MFP capable".
            || ap.rsn_capabilities & rsn::RSN_CAP_MFP_CAPABLE == 0
            || ap
                .group_management_cipher
                .is_some_and(|c| c != Suite::standard(rsn::CIPHER_BIP_CMAC_128))
        {
            return Err(Error::UnsupportedSecurity);
        }
        let h2e = match pwe {
            SaePwe::HuntAndPeck => false,
            SaePwe::HashToElement if !ap_h2e => return Err(Error::UnsupportedSecurity),
            SaePwe::HashToElement | SaePwe::Both => ap_h2e,
        };
        if h2e_required && !h2e {
            // mac80211: required BSS membership selector not supported.
            return Err(Error::UnsupportedRates);
        }
        // wpa_pick_key_mgmt prefers SAE-EXT-KEY; hostap completes it only
        // under H2E (the AKM Suite Selector element is parsed only then).
        // Each AKM must also be in the owner's `JoinOptions::akms`
        // (cfg80211 `wiphy->akm_suites`), so a driver without AKM 24's
        // HMAC-SHA-256 MIC falls back to AKM 8.
        let akm = if h2e
            && akms.contains_suite(rsn::AKM_SAE_EXT_KEY)
            && ap.akms.contains(&Suite::standard(rsn::AKM_SAE_EXT_KEY))
        {
            KeyMgmt::SaeExtKey
        } else if akms.contains_suite(rsn::AKM_SAE)
            && ap.akms.contains(&Suite::standard(rsn::AKM_SAE))
        {
            KeyMgmt::Sae
        } else {
            return Err(Error::UnsupportedSecurity);
        };
        Ok(Self {
            akm,
            h2e,
            advertise_h2e: pwe != SaePwe::HuntAndPeck,
            auth: Auth::Idle,
            tokens: 0,
            pmkid: None,
            frame: Vec::new(),
        })
    }
    /// The negotiated SAE AKM (8, or 24 under H2E).
    pub fn akm(&self) -> KeyMgmt {
        self.akm
    }
    /// Whether the caller's session must use hash-to-element.
    pub fn h2e(&self) -> bool {
        self.h2e
    }
    /// The AKM Suite Selector element an AKM 24 session must carry.
    pub fn akm_suite_selector(&self) -> Option<[u8; 4]> {
        (self.akm == KeyMgmt::SaeExtKey).then_some([0x00, 0x0F, 0xAC, rsn::AKM_SAE_EXT_KEY])
    }
    /// The SAE PMKID once Confirm verified.
    pub fn pmkid(&self) -> Option<[u8; 16]> {
        self.pmkid
    }
    /// The station RSNE body: CCMP-128, the negotiated AKM, MFPC|MFPR,
    /// optional PMKID, default BIP-CMAC-128 group management cipher
    /// (omitted, as `wpa_gen_wpa_ie_rsn` omits the default).
    pub fn station_rsne(&self, pmkid: Option<[u8; 16]>) -> Vec<u8> {
        RsnIe {
            version: 1,
            group_cipher: Suite::standard(rsn::CIPHER_CCMP_128),
            pairwise_ciphers: vec![Suite::standard(rsn::CIPHER_CCMP_128)],
            akms: vec![Suite::standard(self.akm.suite_type())],
            rsn_capabilities: rsn::RSN_CAP_MFP_REQUIRED | rsn::RSN_CAP_MFP_CAPABLE,
            pmkids: pmkid.into_iter().collect(),
            group_management_cipher: None,
        }
        .encode_body()
    }
    /// The station RSNXE body (`wpa_gen_rsnxe`: SAE H2E for sae_pwe 1/2).
    pub fn station_rsnxe(&self) -> Option<Vec<u8>> {
        self.advertise_h2e.then(|| vec![rsn::RSNX_CAP_SAE_H2E])
    }
    pub(super) fn cancel(&mut self) {
        self.auth = Auth::Failed;
        self.frame.clear();
    }
}

fn auth_frame(own: [u8; 6], peer: [u8; 6], seq: u16, status: u16, body: &[u8]) -> Vec<u8> {
    let mut frame = management(0xb0, own, peer);
    frame.extend_from_slice(&AUTH_SAE.to_le_bytes());
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

/// wpa_supplicant `sme_sae_auth` token extraction: after the group, an
/// Anti-Clogging Token Container for H2E, the remaining octets otherwise.
fn anti_clogging_token(data: &[u8], h2e: bool) -> Option<Vec<u8>> {
    let t = data.get(2..)?;
    if !h2e {
        return (!t.is_empty()).then(|| t.to_vec());
    }
    if t.len() < 3
        || t[0] != 0xff
        || t[1] < 2
        || usize::from(t[1]) + 2 != t.len()
        || t[2] != EXT_TOKEN
    {
        return None;
    }
    Some(t[3..].to_vec())
}

/// Replace the first element `id` after the fixed association-request
/// fields (Capability, Listen Interval) with `body`.
fn replace_element(frame: &mut Vec<u8>, id: u8, body: &[u8]) -> Result<(), Error> {
    let mut at = 28;
    while at + 2 <= frame.len() {
        let len = usize::from(frame[at + 1]);
        if at + 2 + len > frame.len() {
            break;
        }
        if frame[at] == id {
            let mut out = frame[..at].to_vec();
            out.extend_from_slice(&[id, body.len() as u8]);
            out.extend_from_slice(body);
            out.extend_from_slice(&frame[at + 2 + len..]);
            *frame = out;
            return Ok(());
        }
        at += 2 + len;
    }
    Err(Error::Protocol)
}

impl JoinPlan {
    /// The negotiated SAE profile of a `SecurityMode::Wpa3Sae` plan.
    pub fn sae(&self) -> Option<&SaeJoin> {
        self.sae.as_ref()
    }

    /// Bind the caller's committed session and return the first SAE Commit
    /// frame. The session must already hold a Commit built from the
    /// driver's entropy (`SaeSession::try_build_commit_with_entropy`),
    /// match the plan's MAC pair, PWE method and AKM Suite Selector, and
    /// not be an SAE-PK session (whose KeyAuth verification needs the
    /// caller's password and is therefore refused here).
    pub fn start_sae_authentication(&mut self, session: &SaeSession) -> Result<&[u8], Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::Busy);
        }
        let (own, peer) = (self.own, self.peer);
        let sae = self.sae.as_mut().ok_or(Error::UnsupportedSecurity)?;
        if sae.auth != Auth::Idle {
            return Err(Error::Busy);
        }
        if session.state() != SaeState::Committed
            || session.addresses() != (own, peer)
            || session.is_h2e() != sae.h2e
            || session.is_sae_pk()
            || session.akm_suite_selector() != sae.akm_suite_selector()
        {
            return Err(Error::UnsupportedSecurity);
        }
        let status = if sae.h2e { STATUS_H2E } else { 0 };
        sae.frame = auth_frame(own, peer, 1, status, &session.commit_body(None));
        sae.auth = Auth::AwaitCommit;
        self.phase = Phase::AwaitAuthentication;
        Ok(&self.sae.as_ref().ok_or(Error::Protocol)?.frame)
    }

    /// The last SAE frame this plan produced, for the owner's
    /// retransmission timer (IEEE802.11-2020 12.4.8.6 retransmits).
    pub fn sae_pending_frame(&self) -> Option<&[u8]> {
        let sae = self.sae.as_ref()?;
        matches!(sae.auth, Auth::AwaitCommit | Auth::AwaitConfirm).then_some(sae.frame.as_slice())
    }

    /// Process one received management frame during SAE authentication.
    /// Frames for other peers/subtypes are ignored; any protocol error or
    /// rejection is terminal and leaves the plan Failed.
    pub fn sae_authentication_response(
        &mut self,
        bytes: &[u8],
        session: &mut SaeSession,
    ) -> Result<SaeStep<'_>, Error> {
        if self.phase != Phase::AwaitAuthentication
            || self
                .sae
                .as_ref()
                .is_none_or(|s| !matches!(s.auth, Auth::AwaitCommit | Auth::AwaitConfirm))
        {
            return Err(Error::Busy);
        }
        if !self.response(bytes, 0xb0) {
            return Ok(SaeStep::Ignored);
        }
        match self.sae_step(bytes, session) {
            Ok(Some(true)) => Ok(SaeStep::Associate(&self.assoc)),
            Ok(Some(false)) => Ok(SaeStep::Transmit(
                &self.sae.as_ref().ok_or(Error::Protocol)?.frame,
            )),
            Ok(None) => Ok(SaeStep::Ignored),
            Err(error) => {
                self.phase = Phase::Failed;
                if let Some(sae) = self.sae.as_mut() {
                    sae.cancel();
                }
                Err(error)
            }
        }
    }

    /// `Some(true)` = associate, `Some(false)` = transmit `sae.frame`.
    fn sae_step(&mut self, bytes: &[u8], session: &mut SaeSession) -> Result<Option<bool>, Error> {
        let (own, peer) = (self.own, self.peer);
        if session.addresses() != (own, peer) || !(30..=4096).contains(&bytes.len()) {
            return Err(Error::Protocol);
        }
        let field = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let (alg, seq, status) = (field(24), field(26), field(28));
        let body = &bytes[30..];
        if alg != AUTH_SAE {
            return Err(Error::Protocol);
        }
        let sae = self.sae.as_mut().ok_or(Error::Protocol)?;
        match (sae.auth, seq) {
            (Auth::AwaitCommit, 1) if status == STATUS_ANTI_CLOGGING => {
                sae.tokens += 1;
                if sae.tokens > MAX_ANTI_CLOGGING {
                    return Err(Error::Rejected(status));
                }
                // sae_group_allowed on the requested group (19 only).
                if body.len() < 2 || u16::from_le_bytes([body[0], body[1]]) != 19 {
                    return Err(Error::Protocol);
                }
                let token = anti_clogging_token(body, sae.h2e).ok_or(Error::Protocol)?;
                let commit = session.commit_body(Some(&token));
                if commit.is_empty() {
                    return Err(Error::Protocol);
                }
                let status = if sae.h2e { STATUS_H2E } else { 0 };
                sae.frame = auth_frame(own, peer, 1, status, &commit);
                Ok(Some(false))
            }
            (Auth::AwaitCommit, 1) => {
                if status != 0 && status != STATUS_H2E {
                    return Err(Error::Rejected(status));
                }
                // "Unexpected use of status code" for the PWE method.
                if (status == STATUS_H2E) != sae.h2e {
                    return Err(Error::Protocol);
                }
                match session.on_commit(body) {
                    Ok(()) => {}
                    // SAE_SILENTLY_DISCARD: wait for a retransmission.
                    Err(SaeError::Reflection) => return Ok(None),
                    Err(_) => return Err(Error::Protocol),
                }
                let confirm = session.build_confirm();
                if confirm.is_empty() {
                    return Err(Error::Protocol);
                }
                sae.frame = auth_frame(own, peer, 2, 0, &confirm);
                sae.auth = Auth::AwaitConfirm;
                Ok(Some(false))
            }
            // A Confirm before the peer's Commit (sme_sae_auth: not in
            // SAE_CONFIRMED) fails the attempt.
            (Auth::AwaitCommit, _) => Err(Error::Protocol),
            // A retransmitted peer Commit: our Confirm is already pending
            // and is resent by the owner's retransmission timer.
            (Auth::AwaitConfirm, 1) if status == 0 || status == STATUS_H2E => Ok(None),
            (Auth::AwaitConfirm, 2) => {
                if status != 0 {
                    return Err(Error::Rejected(status));
                }
                if session.on_confirm(body).is_err() || session.state() != SaeState::Accepted {
                    return Err(Error::Protocol);
                }
                let pmkid = *session.pmkid().ok_or(Error::Protocol)?;
                let rsne = sae.station_rsne(Some(pmkid));
                sae.pmkid = Some(pmkid);
                sae.auth = Auth::Done;
                sae.frame.clear();
                replace_element(&mut self.assoc, 48, &rsne)?;
                self.phase = Phase::AwaitAssociation;
                Ok(Some(true))
            }
            (Auth::AwaitConfirm, _) => Err(Error::Protocol),
            _ => Err(Error::Busy),
        }
    }

    /// An association-response RSNE (rare outside FT/FILS) must repeat
    /// the station's own RSNE.
    pub(super) fn response_rsne_matches(&self, body: &[u8]) -> bool {
        let Some(got) = RsnIe::decode_body(body) else {
            return false;
        };
        if let Some(sae) = self.sae.as_ref() {
            return [sae.station_rsne(sae.pmkid), sae.station_rsne(None)]
                .iter()
                .any(|own| RsnIe::decode_body(own).as_ref() == Some(&got));
        }
        self.security.is_wpa2() && got == self.wpa2.rsne(false)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "sae_join_tests.rs"]
mod tests;
