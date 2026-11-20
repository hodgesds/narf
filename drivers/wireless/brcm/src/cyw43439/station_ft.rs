// SPDX-License-Identifier: GPL-2.0-or-later
//! Fast BSS Transition (802.11r) with the firmware supplicant.
//!
//! Linux brcmfmac `cfg80211.c::brcmf_set_key_mgmt` maps the supplicant's
//! first AKM: `WLAN_AKM_SUITE_FT_PSK` to `WPA2_AUTH_PSK | WPA2_AUTH_FT` and
//! `WLAN_AKM_SUITE_FT_OVER_SAE` to `WPA3_AUTH_SAE_PSK | WPA2_AUTH_FT`, and
//! sets `profile->is_ft`. The firmware supplicant then performs the FT
//! initial mobility-domain association and, within the mobility domain,
//! the over-the-air FT reassociation during its own roam; the host sees the
//! ordinary `BRCMF_E_ROAM` + `PSK_SUP` sequence handled by `station_roam`.
//! An FT AKM is admitted only toward a BSS advertising a Mobility Domain
//! element (IEEE 802.11-2020 9.4.2.46, element ID 54, length 3).
use super::Error;
use narf_wireless::rsn::{RsnIe, AKM_FT_PSK, AKM_FT_SAE, AKM_PSK, AKM_SAE};

/// `brcmu_wifi.h` `WPA2_AUTH_PSK` / `WPA2_AUTH_FT`.
pub const WPA2_AUTH_PSK: u32 = 0x0080;
pub const WPA2_AUTH_FT: u32 = 0x4000;
/// Mobility Domain element.
pub const MDE: u8 = 54;

pub fn is_ft(akm: u8) -> bool {
    matches!(akm, AKM_FT_PSK | AKM_FT_SAE)
}
pub fn is_sae(akm: u8) -> bool {
    matches!(akm, AKM_SAE | AKM_FT_SAE)
}

/// Firmware `wpa_auth` for a negotiated AKM (`brcmf_set_key_mgmt`).
pub fn wpa_auth(akm: u8) -> u32 {
    match akm {
        AKM_PSK => WPA2_AUTH_PSK,
        AKM_FT_PSK => WPA2_AUTH_PSK | WPA2_AUTH_FT,
        AKM_SAE => super::sae::WPA3_AUTH_SAE_PSK,
        AKM_FT_SAE => super::sae::WPA3_AUTH_SAE_PSK | WPA2_AUTH_FT,
        _ => 0,
    }
}

/// The caller's RSNE AKM selects FT over the base credential's AKM. Any
/// other requested AKM must equal the base one (checked later).
pub fn select(base: u8, request_ies: &[u8]) -> Result<u8, Error> {
    let mut ies = request_ies;
    while ies.len() >= 2 {
        let end = 2 + usize::from(ies[1]);
        let body = ies.get(2..end).ok_or(Error::Malformed)?;
        if ies[0] == 48 {
            let rsn = RsnIe::decode_body(body).ok_or(Error::Malformed)?;
            let wanted = match base {
                AKM_PSK => AKM_FT_PSK,
                AKM_SAE => AKM_FT_SAE,
                _ => return Ok(base),
            };
            return Ok(
                if rsn.akms.len() == 1 && rsn.akms[0] == narf_wireless::rsn::Suite::standard(wanted)
                {
                    wanted
                } else {
                    base
                },
            );
        }
        ies = &ies[end..];
    }
    Ok(base)
}

/// The BSS advertises a well-formed Mobility Domain element.
pub fn has_mobility_domain(mut ies: &[u8]) -> bool {
    while ies.len() >= 2 {
        let end = 2 + usize::from(ies[1]);
        if end > ies.len() {
            return false;
        }
        if ies[0] == MDE {
            return ies[1] == 3;
        }
        ies = &ies[end..];
    }
    false
}
