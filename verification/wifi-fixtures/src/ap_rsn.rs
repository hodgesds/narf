//! SAE (WPA3-Personal) and PMF profiles for `FakeAp`.
//!
//! The AP side of SAE reuses the shared `narf_wireless::sae::SaeSession`
//! (it is symmetric: the AP is just the other peer). The 4-way handshake for
//! a profiled AP uses the shared AKM-aware primitives (`wpa_pmk_to_ptk`,
//! `wpa_eapol_key_mic`) like hostapd's `wpa_auth` does, delivers the IGTK in
//! message 3 when both sides set MFPC, and can emit a BIP-CMAC-128 protected
//! broadcast Deauthentication (IEEE802.11-2020 12.5.4, 9.4.2.54 MMIE).
use alloc::{vec, vec::Vec};
use narf_wireless::eapol::KeyMgmt;
use narf_wireless::rsn::{self, RsnIe, Suite};
use narf_wireless::sae::{SaeSession, SaeState};

/// wpa_supplicant/hostapd `ieee80211w` for the fake AP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApPmf {
    /// MFPC: PMF when the station also sets MFPC.
    Optional,
    /// MFPC|MFPR: stations without MFPC are refused.
    Required,
}

/// The SAE password-element derivation the fake AP runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApSaePwe {
    /// Hunting-and-pecking (Commit status 0).
    HuntAndPeck,
    /// Hash-to-element (Commit status 126, RSNXE SAE H2E).
    HashToElement,
}

pub(crate) const STATUS_H2E: u16 = 126;

/// The RSN profile of a WPA3/PMF fake AP.
pub(crate) struct RsnProfile {
    /// AKM suite types offered in the RSNE, in order.
    pub akms: Vec<u8>,
    /// RSN Capabilities MFPC/MFPR bits.
    pub caps: u16,
    /// RSNXE body, when advertised.
    pub rsnxe: Option<u8>,
    /// SAE state, for an SAE AP.
    pub sae: Option<SaeAp>,
    /// IGTK material, key ID and the last transmitted IPN.
    pub igtk: [u8; 16],
    pub igtk_id: u16,
    pub ipn: u64,
    /// Negotiated in association: the station's AKM, PMF, and its
    /// RSNE (+ RSNXE) elements as message 2 must repeat them.
    pub km: Option<KeyMgmt>,
    pub pmf: bool,
    pub assoc_ies: Vec<u8>,
}

pub(crate) struct SaeAp {
    pub session: SaeSession,
    pub pwe: ApSaePwe,
    pub accepted: bool,
    /// Inputs to rebuild the session bound to an AKM Suite Selector when a
    /// station's H2E Commit selects SAE-EXT-KEY (`sae_write_commit`).
    pub ssid: Vec<u8>,
    pub password: Vec<u8>,
    pub addresses: ([u8; 6], [u8; 6]),
}

impl RsnProfile {
    pub fn rsne_body(&self) -> Vec<u8> {
        RsnIe {
            version: 1,
            group_cipher: Suite::standard(rsn::CIPHER_CCMP_128),
            pairwise_ciphers: vec![Suite::standard(rsn::CIPHER_CCMP_128)],
            akms: self.akms.iter().map(|a| Suite::standard(*a)).collect(),
            rsn_capabilities: self.caps,
            pmkids: Vec::new(),
            group_management_cipher: None,
        }
        .encode_body()
    }
    /// RSNE and RSNXE elements as the Beacon and message 3 carry them.
    pub fn elements(&self) -> Vec<u8> {
        let body = self.rsne_body();
        let mut out = vec![48, body.len() as u8];
        out.extend_from_slice(&body);
        if let Some(x) = self.rsnxe {
            out.extend_from_slice(&[244, 1, x]);
        }
        out
    }
    /// Key Descriptor Version of the negotiated AKM.
    pub fn key_version(&self) -> u16 {
        match self.km {
            Some(KeyMgmt::Psk) => narf_wireless::eapol::KI_VERSION_HMAC_SHA1_AES,
            Some(KeyMgmt::PskSha256) => narf_wireless::eapol::KI_VERSION_AES_128_CMAC,
            _ => narf_wireless::eapol::KI_VERSION_AKM_DEFINED,
        }
    }
    /// hostapd `wpa_validate_wpa_ie` for the association request: CCMP,
    /// one offered AKM (SAE AKMs only on an SAE AP, AKM 24 only under H2E),
    /// MFPR on either side requires MFPC on the other, and an SAE PMKID (if
    /// any) must be the accepted one. Records the negotiated profile.
    pub fn admit(&mut self, rsne: &[u8], rsnxe: Option<&[u8]>) -> bool {
        let Some(sta) = RsnIe::decode_body(&rsne[2..]) else {
            return false;
        };
        let ccmp = Suite::standard(rsn::CIPHER_CCMP_128);
        let [akm] = sta.akms.as_slice() else {
            return false;
        };
        let km = KeyMgmt::from_suite_type(akm.suite_type);
        let sta_mfpc = sta.rsn_capabilities & rsn::RSN_CAP_MFP_CAPABLE != 0;
        let sta_mfpr = sta.rsn_capabilities & rsn::RSN_CAP_MFP_REQUIRED != 0;
        let ap_mfpc = self.caps & rsn::RSN_CAP_MFP_CAPABLE != 0;
        let ap_mfpr = self.caps & rsn::RSN_CAP_MFP_REQUIRED != 0;
        let sae_akm = km.is_some_and(KeyMgmt::sae);
        let h2e = self
            .sae
            .as_ref()
            .is_some_and(|s| s.pwe == ApSaePwe::HashToElement);
        let pmkid_ok = match (sta.pmkids.as_slice(), self.sae.as_ref()) {
            ([], _) => true,
            ([pmkid], Some(sae)) => sae.session.pmkid() == Some(pmkid),
            _ => false,
        };
        if akm.oui != rsn::RSN_OUI
            || km.is_none()
            || !self.akms.contains(&akm.suite_type)
            || sae_akm != self.sae.is_some()
            || (km == Some(KeyMgmt::SaeExtKey) && !h2e)
            || self.sae.as_ref().is_some_and(|s| !s.accepted)
            || sta.group_cipher != ccmp
            || sta.pairwise_ciphers != [ccmp]
            || (ap_mfpr && !sta_mfpc)
            || (sta_mfpr && !ap_mfpc)
            || (sae_akm && !(sta_mfpc && ap_mfpc))
            || sta
                .group_management_cipher
                .is_some_and(|c| c != Suite::standard(rsn::CIPHER_BIP_CMAC_128))
            || !pmkid_ok
        {
            return false;
        }
        self.km = km;
        self.pmf = sta_mfpc && ap_mfpc;
        self.assoc_ies = rsne.to_vec();
        if let Some(x) = rsnxe {
            self.assoc_ies.extend_from_slice(x);
        }
        true
    }
    /// The PMK: SAE's, else the configured PSK PMK.
    pub fn sae_pmk(&self) -> Option<[u8; 32]> {
        self.sae.as_ref().and_then(|s| s.session.pmk().copied())
    }
    /// IGTK KDE (00-0F-AC:9): Key ID, IPN (6 octets), IGTK.
    pub fn igtk_kde(&self) -> Vec<u8> {
        let mut out = vec![221, 28, 0, 0x0f, 0xac, 9];
        out.extend_from_slice(&self.igtk_id.to_le_bytes());
        out.extend_from_slice(&self.ipn.to_le_bytes()[..6]);
        out.extend_from_slice(&self.igtk);
        out
    }
}

/// The AKM Suite Selector element of a group-19 SAE Commit body, if any.
fn akm_suite_selector(body: &[u8]) -> Option<[u8; 4]> {
    let mut rest = body.get(2 + 32 + 64..)?;
    while rest.len() >= 2 {
        let len = usize::from(rest[1]);
        let element = rest.get(2..2 + len)?;
        if rest[0] == 255
            && element.first() == Some(&narf_wireless::sae::session::EID_EXT_AKM_SUITE_SELECTOR)
        {
            return element.get(1..5)?.try_into().ok();
        }
        rest = &rest[2 + len..];
    }
    None
}

impl SaeAp {
    /// Station Commit (`seq` 1) or Confirm (`seq` 2) body after the status
    /// field. Returns the AP's reply body (Commit or Confirm) and status.
    pub fn step(&mut self, seq: u16, status: u16, body: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
        let want = match self.pwe {
            ApSaePwe::HuntAndPeck => 0,
            ApSaePwe::HashToElement => STATUS_H2E,
        };
        match seq {
            1 if status == want && self.session.state() == SaeState::Nothing => {
                // An H2E Commit for AKM 24 carries the AKM Suite Selector
                // element after group, scalar and element; ours must match.
                if let Some(selector) = akm_suite_selector(body) {
                    let (own, peer) = self.addresses;
                    self.session = SaeSession::new_h2e_bytes(&self.ssid, &self.password, own, peer)
                        .with_akm_suite_selector(selector)
                        .ok()?;
                }
                let commit = self.session.try_build_commit().ok()?;
                self.session.on_commit(body).ok()?;
                Some((1, want, commit))
            }
            2 if status == 0 && self.session.state() == SaeState::Committed => {
                let confirm = self.session.build_confirm();
                self.session.on_confirm(body).ok()?;
                self.accepted = true;
                Some((2, 0, confirm))
            }
            _ => None,
        }
    }
}
