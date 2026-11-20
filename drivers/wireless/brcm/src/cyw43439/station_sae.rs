// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware WPA3-Personal SAE offload encodings.
//!
//! Linux brcmfmac `feature.c` sets `BRCMF_FEAT_SAE` from the exact `cap`
//! token `"sae "`; `cfg80211.c::brcmf_cfg80211_connect` then, with
//! `BRCMF_FEAT_FWSUP`, selects `BRCMF_PROFILE_FWSUP_SAE`, writes
//! `wpa_auth = WPA3_AUTH_SAE_PSK`, auth type 3, enables `sup_wpa`, clears the
//! user-space `wpaie` and calls the firmware-vendor `set_sae_password` op:
//! `cyw/core.c` uses the `sae_password` iovar (`brcmf_wsec_sae_pwd_le`),
//! `wcc/core.c` uses `BRCMF_C_SET_WSEC_PMK` with `BRCMF_WSEC_PASSPHRASE`
//! (`brcmf_wsec_pmk_le`). SAE commit/confirm and the 4-way handshake run in
//! firmware; `BRCMF_E_PSK_SUP`/`FWSUP_COMPLETED` plus `SET_SSID` success
//! confirm it exactly as for PSK offload (`brcmf_is_linkup`).
use super::Error;
use zeroize::Zeroizing;

/// `brcmu_wifi.h` `WPA3_AUTH_SAE_PSK`.
pub const WPA3_AUTH_SAE_PSK: u32 = 0x4_0000;
/// `fwil_types.h` `BRCMF_WSEC_MAX_SAE_PASSWORD_LEN`.
pub const PASSWORD_MAX: usize = 128;
/// `fwil_types.h` `BRCMF_WSEC_PASSPHRASE`.
pub const WSEC_PASSPHRASE: u16 = 1;
/// Linux `feature.c` reads `cap` into a 512-byte buffer
/// (`MAX_CAPS_BUFFER_SIZE`).
pub const CAP_LEN: usize = 512;
/// `sizeof(struct brcmf_wsec_sae_pwd_le)`.
pub const CYW_PASSWORD_LEN: usize = 2 + PASSWORD_MAX;
/// `sizeof(struct brcmf_wsec_pmk_le)`.
pub const WCC_PMK_LEN: usize = 4 + PASSWORD_MAX;

/// Whitespace/NUL-delimited firmware capability token match. Linux's
/// trailing-space match `"sae "` therefore never accepts `"sae_ext"`.
pub fn has_capability(caps: &[u8], token: &[u8]) -> bool {
    let end = caps.iter().position(|&b| b == 0).unwrap_or(caps.len());
    caps[..end]
        .split(|b| b.is_ascii_whitespace())
        .any(|word| word == token)
}

fn checked(password: &[u8]) -> Result<(), Error> {
    if password.is_empty() || password.len() > PASSWORD_MAX {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}

/// CYW `sae_password` iovar body: `{ le16 key_len; u8 key[128]; }`.
pub fn cyw_password(password: &[u8]) -> Result<Zeroizing<[u8; CYW_PASSWORD_LEN]>, Error> {
    checked(password)?;
    let mut body = Zeroizing::new([0; CYW_PASSWORD_LEN]);
    body[..2].copy_from_slice(&(password.len() as u16).to_le_bytes());
    body[2..2 + password.len()].copy_from_slice(password);
    Ok(body)
}

/// WCC `BRCMF_C_SET_WSEC_PMK` body: `{ le16 key_len; le16 flags; u8 key[128]; }`
/// with `flags = BRCMF_WSEC_PASSPHRASE`.
pub fn wcc_passphrase(password: &[u8]) -> Result<Zeroizing<[u8; WCC_PMK_LEN]>, Error> {
    checked(password)?;
    let mut body = Zeroizing::new([0; WCC_PMK_LEN]);
    body[..2].copy_from_slice(&(password.len() as u16).to_le_bytes());
    body[2..4].copy_from_slice(&WSEC_PASSPHRASE.to_le_bytes());
    body[4..4 + password.len()].copy_from_slice(password);
    Ok(body)
}
