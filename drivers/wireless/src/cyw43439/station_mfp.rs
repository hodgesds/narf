// SPDX-License-Identifier: GPL-2.0-or-later
//! Required-PMF WPA2 offload admission. Native BRCMF_MFP modes and association
//! receipts follow Linux brcmfmac/{feature,cfg80211}.c, fwil_types.h.
use super::{policy::TxGrant, Error, Fullmac, Station, MAX_REPLY};
use narf_wireless::rsn::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Profile(bool);

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
            result = Some(RsnIe::decode_body(body).ok_or(Error::Malformed)?);
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
        let ap = rsn(ap)?;
        let sme = rsn(sme)?;
        if !secure {
            return if ap.is_none() && sme.is_none() {
                Ok(Self(false))
            } else {
                Err(Error::Unsupported)
            };
        }
        let ap = ap.ok_or(Error::Unsupported)?;
        for ie in core::iter::once(&ap).chain(sme.iter()) {
            let bits = ie.rsn_capabilities;
            if bits & RSN_CAP_MFP_REQUIRED != 0 && bits & RSN_CAP_MFP_CAPABLE == 0 {
                return Err(Error::Unsupported);
            }
        }
        let required = ap.rsn_capabilities & RSN_CAP_MFP_REQUIRED != 0
            || sme
                .as_ref()
                .is_some_and(|ie| ie.rsn_capabilities & RSN_CAP_MFP_REQUIRED != 0);
        if required
            && (!supported
                || ap.rsn_capabilities & RSN_CAP_MFP_CAPABLE == 0
                || sme
                    .as_ref()
                    // The canonical firmware request must not silently
                    // discard a caller's additional security promises (OCV,
                    // preauthentication, replay-counter modes, etc.).
                    .is_some_and(|ie| {
                        ie.rsn_capabilities != RSN_CAP_MFP_REQUIRED | RSN_CAP_MFP_CAPABLE
                    })
                || core::iter::once(&ap).chain(sme.iter()).any(|ie| {
                    ie.group_management_cipher
                        .is_some_and(|cipher| cipher != Suite::standard(CIPHER_BIP_CMAC_128))
                }))
        {
            return Err(Error::Unsupported);
        }
        Ok(Self(required))
    }
    pub(super) fn required(self) -> bool {
        self.0
    }
    pub(super) fn mode(self) -> u32 {
        if self.0 {
            2
        } else {
            0
        }
    }
    pub(super) fn rsn(self) -> RsnIe {
        let mut ie = RsnIe::wpa2_psk_ccmp();
        if self.0 {
            ie.rsn_capabilities = RSN_CAP_MFP_REQUIRED | RSN_CAP_MFP_CAPABLE;
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
    ) -> Result<(), Error> {
        // FWSUP_COMPLETED already confirmed the firmware-owned handshake.
        // IGTK/BIP keys remain inside that offload, never fabricated or read
        // back into host memory. Verify actual firmware configuration and
        // the RSNE it transmitted, rather than the caller's desired flags.
        if self.tx_query(grant, "mfp", 4).await?.as_slice() != [2, 0, 0, 0] {
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
        if ies.len() != length || rsn(&ies)? != Some(profile.rsn()) {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}
