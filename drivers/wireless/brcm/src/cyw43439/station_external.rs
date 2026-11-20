// SPDX-License-Identifier: GPL-2.0-or-later
//! Host-supplicant fallback (userspace 4-way / 802.1X) for the FullMAC station.
//!
//! Linux brcmfmac without a firmware-supplicant profile
//! (`BRCMF_PROFILE_FWSUP_NONE`, `brcmf_cfg80211_connect`) writes the
//! supplicant's RSNE to `wpaie`, maps its first AKM to `wpa_auth`
//! (`brcmf_set_key_mgmt`: PSK 0x80, 802.1X `WPA2_AUTH_UNSPECIFIED` 0x40,
//! PSK-SHA256 0x8000, 802.1X-SHA256 `WPA2_AUTH_1X_SHA256` 0x1000), sets
//! `sup_wpa 0` and joins; `SET_SSID` success alone is link-up
//! (`brcmf_is_linkup`). EAPOL then travels as ordinary data and the
//! supplicant installs keys with `brcmf_cfg80211_add_key` →
//! `send_key_to_dongle`, the `wsec_key` iovar carrying
//! `struct brcmf_wsec_key_le`. Key indices are limited to
//! `BRCMF_MAX_DEFAULT_KEYS`=4 and this profile carries CCMP only
//! (`CRYPTO_ALGO_AES_CCM`). NARF keeps the host port closed (only EAPOL
//! passes, to the control port) until `set_port_authorized`.
use super::{Error, Fullmac, Station};
use narf_wireless::rsn::{AKM_DOT1X, AKM_DOT1X_SHA256, AKM_PSK, AKM_PSK_SHA256};
use zeroize::Zeroizing;

/// `brcmu_wifi.h` key-management values.
pub const WPA2_AUTH_UNSPECIFIED: u32 = 0x0040;
pub const WPA2_AUTH_1X_SHA256: u32 = 0x1000;
pub const WPA2_AUTH_PSK_SHA256: u32 = 0x8000;
/// `fwil_types.h` `BRCMF_MAX_DEFAULT_KEYS`, `BRCMF_PRIMARY_KEY`;
/// `brcmu_wifi.h` `CRYPTO_ALGO_AES_CCM`.
pub const MAX_DEFAULT_KEYS: u8 = 4;
pub const PRIMARY_KEY: u32 = 1 << 1;
pub const ALGO_AES_CCM: u32 = 4;
/// `sizeof(struct brcmf_wsec_key_le)`.
pub const WSEC_KEY_LEN: usize = 164;

/// `brcmf_set_key_mgmt` for the host-supplicant AKMs.
pub fn wpa_auth(akm: u8) -> Option<u32> {
    Some(match akm {
        AKM_PSK => super::ft::WPA2_AUTH_PSK,
        AKM_DOT1X => WPA2_AUTH_UNSPECIFIED,
        AKM_PSK_SHA256 => WPA2_AUTH_PSK_SHA256,
        AKM_DOT1X_SHA256 => WPA2_AUTH_1X_SHA256,
        _ => return None,
    })
}

/// The supplicant's single RSNE AKM (the first, as Linux uses
/// `akm_suites[0]`), admitted only for the host-supplicant set above.
pub fn akm(request_ies: &[u8]) -> Result<u8, Error> {
    let mut ies = request_ies;
    while ies.len() >= 2 {
        let end = 2 + usize::from(ies[1]);
        let body = ies.get(2..end).ok_or(Error::Malformed)?;
        if ies[0] == 48 {
            let rsn = narf_wireless::rsn::RsnIe::decode_body(body).ok_or(Error::Malformed)?;
            let suite = rsn.akms.first().ok_or(Error::Malformed)?;
            if suite.oui != [0x00, 0x0f, 0xac] || wpa_auth(suite.suite_type).is_none() {
                return Err(Error::Unsupported);
            }
            return Ok(suite.suite_type);
        }
        ies = &ies[end..];
    }
    Err(Error::Unsupported)
}

/// The exact supplicant RSNE element (header included) for `wpaie`.
pub fn rsne(request_ies: &[u8]) -> Option<&[u8]> {
    let mut ies = request_ies;
    while ies.len() >= 2 {
        let end = 2 + usize::from(ies[1]);
        if ies[0] == 48 {
            return ies.get(..end);
        }
        ies = ies.get(end..)?;
    }
    None
}

/// `convert_key_from_CPU` → `struct brcmf_wsec_key_le`. A pairwise key
/// carries the peer address (`ext_key`); a group key is `BRCMF_PRIMARY_KEY`.
pub fn wsec_key(
    index: u8,
    key: &[u8],
    seq: &[u8],
    peer: Option<[u8; 6]>,
) -> Result<Zeroizing<[u8; WSEC_KEY_LEN]>, Error> {
    if index >= MAX_DEFAULT_KEYS || key.len() != 16 || !(seq.is_empty() || seq.len() == 6) {
        return Err(Error::Malformed);
    }
    let mut out = Zeroizing::new([0; WSEC_KEY_LEN]);
    out[..4].copy_from_slice(&u32::from(index).to_le_bytes());
    out[4..8].copy_from_slice(&(key.len() as u32).to_le_bytes());
    out[8..8 + key.len()].copy_from_slice(key);
    out[112..116].copy_from_slice(&ALGO_AES_CCM.to_le_bytes());
    let flags = if peer.is_some() { 0 } else { PRIMARY_KEY };
    out[116..120].copy_from_slice(&flags.to_le_bytes());
    if seq.len() == 6 {
        let hi = u32::from_le_bytes([seq[2], seq[3], seq[4], seq[5]]);
        let lo = u16::from_le_bytes([seq[0], seq[1]]);
        out[132..136].copy_from_slice(&1u32.to_le_bytes());
        out[140..144].copy_from_slice(&hi.to_le_bytes());
        out[144..146].copy_from_slice(&lo.to_le_bytes());
    }
    if let Some(peer) = peer {
        out[156..162].copy_from_slice(&peer);
    }
    Ok(out)
}

impl<R: Fullmac> Station<R> {
    /// Host-supplicant connection: `Some(authorized)`.
    pub fn external_port(&self) -> Option<bool> {
        self.bssid.and(self.external)
    }

    /// `brcmf_cfg80211_add_key` for the host-supplicant connection.
    pub async fn install_key(
        &mut self,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
        cipher: u32,
        key: &[u8],
        seq: &[u8],
    ) -> Result<(), Error> {
        let Some(current) = self.bssid.filter(|_| self.external.is_some()) else {
            return Err(Error::Failed);
        };
        if cipher != narf_wireless::CIPHER_SUITE_CCMP
            || pairwise && peer != Some(current)
            || !pairwise && peer.is_some_and(|p| p[0] & 1 == 0)
        {
            return Err(Error::Malformed);
        }
        let body = wsec_key(index, key, seq, pairwise.then_some(current))?;
        let grants: alloc::vec::Vec<_> = self.connection.into_iter().collect();
        self.operation = true;
        let result = self.checked_var(&grants, &[], "wsec_key", &body[..]).await;
        self.operation = false;
        if result.is_err() {
            // An ambiguous key installation leaves firmware crypto unknown.
            self.external = None;
            self.bssid = None;
            self.connection = None;
            self.runtime.fail();
            self.runtime.set_link(None);
        }
        result
    }

    /// `brcmf_cfg80211_del_key`: `wsec_key` with `CRYPTO_ALGO_OFF`.
    pub async fn delete_key(&mut self, index: u8) -> Result<(), Error> {
        if self.bssid.is_none() || self.external.is_none() || index >= MAX_DEFAULT_KEYS {
            return Err(Error::Failed);
        }
        let mut body = [0u8; WSEC_KEY_LEN];
        body[..4].copy_from_slice(&u32::from(index).to_le_bytes());
        body[116..120].copy_from_slice(&PRIMARY_KEY.to_le_bytes());
        let grants: alloc::vec::Vec<_> = self.connection.into_iter().collect();
        self.operation = true;
        let result = self.checked_var(&grants, &[], "wsec_key", &body).await;
        self.operation = false;
        if result.is_err() {
            self.external = None;
            self.bssid = None;
            self.connection = None;
            self.runtime.fail();
            self.runtime.set_link(None);
        }
        result
    }

    /// `set_port_authorized` from the supplicant (SET_STATION AUTHORIZED).
    pub fn authorize_port(&mut self, peer: [u8; 6], authorized: bool) -> Result<(), Error> {
        if self.bssid != Some(peer) || self.external.is_none() {
            return Err(Error::Failed);
        }
        self.external = Some(authorized);
        Ok(())
    }
}
