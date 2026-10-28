// SPDX-License-Identifier: GPL-2.0-or-later
//! Native WPA2 PMF-policy admission. Configuration is not negotiated proof.
//! BRCMF_MFP modes and association
//! receipts follow Linux brcmfmac/{feature,cfg80211}.c, fwil_types.h.
use super::{policy::TxGrant, Error, Fullmac, Station, MAX_REPLY};
use narf_wireless::rsn::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Profile {
    mode: u32,
    ap_mfp: u16,
    /// Negotiated AKM suite type: `AKM_PSK` or (SAE offload) `AKM_SAE`.
    akm: u8,
}

/// Shared decoding intentionally accepts optional RSN fields. This native
/// security boundary additionally requires exact consumption, before a missing
/// group-management suite can acquire its IEEE default meaning.
fn exact_body(body: &[u8]) -> Result<RsnIe, Error> {
    let mut at = 6usize; // version and group cipher, checked by the decoder.
    for _ in 0..2 {
        let end = at.checked_add(2).ok_or(Error::Malformed)?;
        let count = u16::from_le_bytes(
            body.get(at..end)
                .ok_or(Error::Malformed)?
                .try_into()
                .unwrap(),
        ) as usize;
        at = end
            .checked_add(count.checked_mul(4).ok_or(Error::Malformed)?)
            .ok_or(Error::Malformed)?;
        if at > body.len() {
            return Err(Error::Malformed);
        }
    }
    if at < body.len() {
        // Capabilities may be absent for a valid legacy18-byte body, but
        // never partial. The same applies to the subsequent PMKID count.
        at = at
            .checked_add(2)
            .filter(|end| *end <= body.len())
            .ok_or(Error::Malformed)?;
        if at < body.len() {
            let end = at.checked_add(2).ok_or(Error::Malformed)?;
            let count = u16::from_le_bytes(
                body.get(at..end)
                    .ok_or(Error::Malformed)?
                    .try_into()
                    .unwrap(),
            ) as usize;
            at = end
                .checked_add(count.checked_mul(16).ok_or(Error::Malformed)?)
                .ok_or(Error::Malformed)?;
            if at > body.len() || !matches!(body.len() - at, 0 | 4) {
                return Err(Error::Malformed);
            }
        }
    }
    RsnIe::decode_body(body).ok_or(Error::Malformed)
}

fn rsn(mut ies: &[u8]) -> Result<Option<RsnIe>, Error> {
    // Apply the existing association IE bound before traversing a public
    // SME request or allocating its decoded suite/PMKID lists.
    if ies.len() > 2048 {
        return Err(Error::Malformed);
    }
    let mut result = None;
    while !ies.is_empty() {
        let header = ies.get(..2).ok_or(Error::Malformed)?;
        let end = 2 + usize::from(header[1]);
        let body = ies.get(2..end).ok_or(Error::Malformed)?;
        if header[0] == 48 {
            if result.is_some() {
                return Err(Error::Malformed);
            }
            result = Some(exact_body(body)?);
        }
        ies = &ies[end..];
    }
    Ok(result)
}

impl Profile {
    pub(super) fn negotiate(
        ap: &[u8],
        sme: &[u8],
        secure: bool,
        supported: bool,
    ) -> Result<Self, Error> {
        Self::negotiate_akm(ap, sme, secure.then_some(AKM_PSK), supported)
    }
    /// `akm` is `None` for Open. WPA3-Personal (`AKM_SAE`) mandates PMF
    /// (WPA3 spec §2.2; IEEE 802.11-2020 12.4.2): an SAE profile is never
    /// negotiated with MFP disabled, and an empty request RSNE selects
    /// capable(1) or, for an MFPR AP, required(2), as Linux derives `mfp`
    /// from the supplicant's RSNE in `brcmf_cfg80211_connect`.
    pub(super) fn negotiate_akm(
        ap: &[u8],
        sme: &[u8],
        akm: Option<u8>,
        supported: bool,
    ) -> Result<Self, Error> {
        let ap = rsn(ap)?;
        let sme = rsn(sme)?;
        let Some(akm) = akm else {
            return if ap.is_none() && sme.is_none() {
                Ok(Self {
                    mode: 0,
                    ap_mfp: 0,
                    akm: 0,
                })
            } else {
                Err(Error::Unsupported)
            };
        };
        let sae = super::ft::is_sae(akm);
        let ap = ap.ok_or(Error::Unsupported)?;
        for ie in core::iter::once(&ap).chain(sme.iter()) {
            let bits = ie.rsn_capabilities;
            if bits & RSN_CAP_MFP_REQUIRED != 0 && bits & RSN_CAP_MFP_CAPABLE == 0 {
                return Err(Error::Unsupported);
            }
        }
        let flags = RSN_CAP_MFP_REQUIRED | RSN_CAP_MFP_CAPABLE;
        let ap_mfp = ap.rsn_capabilities & flags;
        // The caller's original RSNE encodes its explicit policy. An empty
        // typed request preserves automatic required-PMF admission; it never
        // silently enables optional PMF on an ordinary optional-capable AP.
        let mode = match sme.as_ref().map(|ie| ie.rsn_capabilities & flags) {
            Some(bits) if bits & RSN_CAP_MFP_REQUIRED != 0 => 2,
            Some(RSN_CAP_MFP_CAPABLE) => 1,
            None if ap_mfp & RSN_CAP_MFP_REQUIRED != 0 => 2,
            None if sae => 1,
            _ => 0,
        };
        if sae && (mode == 0 || ap_mfp & RSN_CAP_MFP_CAPABLE == 0) {
            return Err(Error::Unsupported);
        }
        if sme
            .as_ref()
            .is_some_and(|ie| mode != 0 && ie.rsn_capabilities & !flags != 0)
            || ap_mfp & RSN_CAP_MFP_REQUIRED != 0 && mode == 0
            || mode != 0 && !supported
            || mode == 2 && ap_mfp & RSN_CAP_MFP_CAPABLE == 0
            || mode != 0
                && core::iter::once(&ap).chain(sme.iter()).any(|ie| {
                    ie.group_management_cipher
                        .is_some_and(|cipher| cipher != Suite::standard(CIPHER_BIP_CMAC_128))
                })
        {
            return Err(Error::Unsupported);
        }
        Ok(Self { mode, ap_mfp, akm })
    }
    pub(super) fn akm(self) -> u8 {
        self.akm
    }
    pub(super) fn required(self) -> bool {
        self.mode == 2
    }
    pub(super) fn verify(self) -> bool {
        self.mode != 0
    }
    fn protected(self) -> bool {
        self.mode != 0 && self.ap_mfp & RSN_CAP_MFP_CAPABLE != 0
    }
    pub(super) fn mode(self) -> u32 {
        self.mode
    }
    pub(super) fn rsn(self) -> RsnIe {
        let mut ie = RsnIe::wpa2_psk_ccmp();
        if self.akm != 0 {
            ie.akms = alloc::vec![Suite::standard(self.akm)];
        }
        if self.mode != 0 {
            ie.rsn_capabilities = RSN_CAP_MFP_CAPABLE
                | if self.required() {
                    RSN_CAP_MFP_REQUIRED
                } else {
                    0
                };
            ie.group_management_cipher = Some(Suite::standard(CIPHER_BIP_CMAC_128));
        }
        ie
    }
}

impl<R: Fullmac> Station<R> {
    pub(super) async fn verify_management_protection(
        &mut self,
        grant: TxGrant,
        peer: [u8; 6],
        profile: Profile,
    ) -> Result<bool, Error> {
        // FWSUP_COMPLETED already confirmed the firmware-owned handshake.
        // IGTK/BIP keys remain inside that offload, never fabricated or read
        // back into host memory. Verify actual firmware configuration and
        // the RSNE it transmitted, rather than the caller's desired flags.
        if self.tx_query(grant, "mfp", 4).await?.as_slice() != profile.mode().to_le_bytes() {
            return Err(Error::Unsupported);
        }
        let bssid = self.tx_get(grant, 23, &[], 6).await?;
        if bssid.as_slice() != peer {
            return Err(Error::Malformed);
        }
        let info = self.tx_query(grant, "assoc_info", 8).await?;
        if info.len() != 8 {
            return Err(Error::Malformed);
        }
        let length = u32::from_le_bytes(info[..4].try_into().unwrap()) as usize;
        let response = u32::from_le_bytes(info[4..].try_into().unwrap()) as usize;
        if !(2..=MAX_REPLY).contains(&length) || response > MAX_REPLY {
            return Err(Error::Malformed);
        }
        let ies = self.tx_query(grant, "assoc_req_ies", length).await?;
        let mut request = rsn(&ies)?.ok_or(Error::Unsupported)?;
        // IEEE default group-management suite is BIP-CMAC128 when omitted.
        // Normalize only that semantic default, never a different promise.
        if request.group_management_cipher.is_none() {
            request.group_management_cipher = Some(Suite::standard(CIPHER_BIP_CMAC_128));
        }
        // An FT (re)association RSNE carries PMKR0Name/PMKR1Name in its
        // PMKID list (IEEE 802.11-2020 13.8.2-13.8.4); it is not cached
        // PMKSA state and is excluded from the profile comparison.
        if super::ft::is_ft(profile.akm) {
            request.pmkids.clear();
        }
        if ies.len() != length || request != profile.rsn() {
            return Err(Error::Unsupported);
        }
        // A response RSNE, when present, must agree with the AP's advertised
        // capabilities. Its absence is normal: IEEE 802.11-2020 9.3.3.6/
        // 9.3.3.7 carry an RSNE in a (Re)Association Response only for FT
        // (and OCI/OWE cases outside this profile), and 12.6.3 negotiates
        // MFP when both the AP's advertised RSNE and the STA's request RSNE
        // set MFPC. Both are verified above (profile.ap_mfp from the
        // selected BSS, the transmitted assoc_req_ies RSNE, and the firmware
        // `mfp` readback); Linux v7.2 `cfg80211.c::brcmf_configure_wpaie`
        // likewise sets bsscfg `mfp` from the connect RSNE and trusts
        // firmware without any negotiated-state readback.
        let actual = if response == 0 {
            None
        } else {
            let ies = self.tx_query(grant, "assoc_resp_ies", response).await?;
            if ies.len() != response {
                return Err(Error::Malformed);
            }
            rsn(&ies)?
        };
        if let Some(actual) = actual {
            let ccmp = Suite::standard(CIPHER_CCMP_128);
            if actual.group_cipher != ccmp
                || !actual.pairwise_ciphers.contains(&ccmp)
                || !actual.akms.contains(&Suite::standard(profile.akm))
                || !actual.pmkids.is_empty() && !super::ft::is_ft(profile.akm)
                || actual.rsn_capabilities & (RSN_CAP_MFP_REQUIRED | RSN_CAP_MFP_CAPABLE)
                    != profile.ap_mfp
                || actual
                    .group_management_cipher
                    .is_some_and(|cipher| cipher != Suite::standard(CIPHER_BIP_CMAC_128))
            {
                return Err(Error::Unsupported);
            }
        }
        Ok(profile.protected())
    }
}
