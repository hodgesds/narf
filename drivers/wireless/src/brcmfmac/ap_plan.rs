// SPDX-License-Identifier: GPL-2.0-or-later
//! Atomic host request validation before the first primary-bsscfg mutation.
//! Firmware-generated standard beacon fields must later match actual native
//! rate/BSS observations; arbitrary caller templates are never treated as RF.
use super::ap_wire;
use crate::cyw43439::runtime::Error;
use alloc::vec::Vec;
use narf_wireless::{ApConfig, ApStartSettings};

pub(crate) struct Plan {
    pub(super) config: ApConfig,
    pub(super) settings: ApStartSettings,
    pub(super) own: [u8; 6],
    pub(super) primary: u8,
    pub(super) chanspec: u16,
    pub(super) capability: u16,
    pub(super) rates: Vec<u8>,
    pub(super) rsne: Option<Vec<u8>>,
    pub(super) wpa_auth: u32,
    pub(super) beacon_vendor: Vec<u8>,
    pub(super) probe_vendor: Vec<u8>,
}
pub(super) struct Elements {
    pub(super) rates: Vec<u8>,
    pub(super) rsne: Option<Vec<u8>>,
    pub(super) vendor: Vec<u8>,
}
#[derive(Clone, Copy)]
enum Ssid {
    Visible,
    Hidden,
    Observed,
}
fn elements(mut ies: &[u8], config: &ApConfig, form: Ssid) -> Result<Elements, Error> {
    let mut ssid = false;
    let mut seen_rates = [false; 2];
    let mut rates = Vec::new();
    let mut rsne = None;
    let mut vendor = Vec::new();
    let mut vendor_count = 0;
    while !ies.is_empty() {
        let length = usize::from(*ies.get(1).ok_or(Error::Malformed)?);
        let element = ies.get(..2 + length).ok_or(Error::Malformed)?;
        let body = &element[2..];
        match element[0] {
            0 => {
                let valid = match form {
                    Ssid::Visible => body == config.ssid,
                    Ssid::Hidden => body.is_empty(),
                    Ssid::Observed => {
                        body == config.ssid || config.hidden_ssid == 1 && body.is_empty()
                    }
                };
                if ssid || !valid {
                    return Err(Error::Malformed);
                }
                ssid = true;
            }
            1 | 50 => {
                let at = usize::from(element[0] == 50);
                if seen_rates[at] || body.is_empty() || at == 0 && length > 8 {
                    return Err(Error::Malformed);
                }
                seen_rates[at] = true;
                rates.extend_from_slice(body);
            }
            3 => {
                let primary = channel(config.frequency_mhz)?;
                if body != [primary] {
                    return Err(Error::Malformed);
                }
            }
            // Firmware supplies the mutable TIM itself; head/tail brackets
            // it, as in mac80211. No caller TIM/CSA/country/optional PHY proof.
            5 | 7 | 37 | 45 | 61 | 191 | 192 | 244 | 255 => return Err(Error::Unsupported),
            42 if body == [0] && config.frequency_mhz < 3000 => {}
            48 => {
                if rsne.replace(element.to_vec()).is_some() {
                    return Err(Error::Malformed);
                }
            }
            221 => {
                // Linux's vndr_ie omits native WPA/WME, and P2P is a
                // distinct role. This legacy profile disables native WMM.
                if body.len() < 5
                    || body.starts_with(&[0, 0x50, 0xf2, 1])
                    || body.starts_with(&[0, 0x50, 0xf2, 2])
                    || body.starts_with(&[0x50, 0x6f, 0x9a, 9])
                {
                    return Err(Error::Unsupported);
                }
                vendor_count += 1;
                vendor.extend_from_slice(element);
                if vendor_count > 5 || vendor.len() + vendor_count * 12 > 512 {
                    return Err(Error::Unsupported);
                }
            }
            _ => return Err(Error::Unsupported),
        }
        ies = &ies[element.len()..];
    }
    if !ssid || !seen_rates[0] || rates.is_empty() || rates.len() > 12 {
        return Err(Error::Malformed);
    }
    // Parse the same complete bounded rate record the native GET uses;
    // the later native observation still supplies actual rate authority.
    let mut encoded = [0; 20];
    encoded[..4].copy_from_slice(&(rates.len() as u32).to_le_bytes());
    encoded[4..4 + rates.len()].copy_from_slice(&rates);
    ap_wire::rates(&encoded)?;
    if config.frequency_mhz > 3000 && rates.iter().any(|r| matches!(r & 127, 2 | 4 | 11 | 22)) {
        return Err(Error::Malformed);
    }
    Ok(Elements {
        rates,
        rsne,
        vendor,
    })
}
fn channel(frequency: u32) -> Result<u8, Error> {
    let primary = match frequency {
        2412..=2472 if (frequency - 2407) % 5 == 0 => (frequency - 2407) / 5,
        5180..=5825 if (frequency - 5000) % 5 == 0 => (frequency - 5000) / 5,
        _ => return Err(Error::Unsupported),
    };
    u8::try_from(primary).map_err(|_| Error::Unsupported)
}
fn header(bytes: &[u8], config: &ApConfig, own: [u8; 6], probe: bool) -> Result<u16, Error> {
    if !(36..=2048).contains(&bytes.len())
        || bytes[0] != if probe { 0x50 } else { 0x80 }
        || bytes[1] != 0
        || !probe && bytes[4..10] != [255; 6]
        || bytes[10..16] != own
        || bytes[16..22] != own
        || bytes[22] & 15 != 0
        || u16::from_le_bytes(bytes[32..34].try_into().unwrap()) != config.beacon_interval as u16
    {
        return Err(Error::Malformed);
    }
    let capability = u16::from_le_bytes(bytes[34..36].try_into().unwrap());
    if capability & 3 != 1 || capability & !0x0431 != 0 || (capability & 16 != 0) != config.privacy
    {
        return Err(Error::Unsupported);
    }
    Ok(capability)
}
impl Plan {
    pub(super) fn observed_elements(
        ies: &[u8],
        config: &ApConfig,
        country: [u8; 2],
    ) -> Result<Elements, Error> {
        let mut checked = Vec::new();
        let mut rest = ies;
        while !rest.is_empty() {
            let length = usize::from(*rest.get(1).ok_or(Error::Malformed)?);
            let element = rest.get(..2 + length).ok_or(Error::Malformed)?;
            let body = &element[2..];
            match element[0] {
                5 => {
                    if body.len() < 4
                        || u32::from(body[1]) != config.dtim_period
                        || body[0] >= body[1]
                    {
                        return Err(Error::Malformed);
                    }
                }
                // This observed native Country IE supplies no permission:
                // original signed policy and occupied spans remain authority.
                7 => {
                    if body.len() < 3 || body[..2] != country {
                        return Err(Error::Malformed);
                    }
                }
                _ => checked.extend_from_slice(element),
            }
            rest = &rest[element.len()..];
        }
        elements(&checked, config, Ssid::Observed)
    }
    pub(crate) fn new(
        config: ApConfig,
        settings: ApStartSettings,
        own: [u8; 6],
    ) -> Result<Self, Error> {
        if !ap_wire::unicast(own)
            || config.ssid.is_empty()
            || config.ssid.len() > 32
            || !(10..=65535).contains(&config.beacon_interval)
            || !(1..=255).contains(&config.dtim_period)
            || config.hidden_ssid > 1
            || !matches!(config.channel_width, 0 | 1)
            || config
                .center_freq1_mhz
                .is_some_and(|f| f != config.frequency_mhz)
            || config.center_freq2_mhz.is_some()
            || config.mbssid.is_some()
            || !config.mbssid_elems.is_empty()
            || !config.ema_rnr_elems.is_empty()
            || config.fils_discovery.is_some()
            || config.unsol_bcast_probe_resp.is_some()
            || config.ftm_responder.is_some()
            || config.twt_responder
            || config.he_obss_pd.is_some()
            || config.he_bss_color.is_some()
            || settings.p2p_go.is_some()
            || settings.auth_type.is_some_and(|a| a != 0)
            || settings.control_port.no_preauth
            || settings.control_port.enabled
                && (!settings.control_port.over_nl80211
                    || settings.control_port.ethertype != 0x888e)
            || config.privacy && !settings.control_port.enabled
            || config
                .beacon_head
                .len()
                .checked_add(config.beacon_tail.len())
                .is_none_or(|len| len > 2048)
        {
            return Err(Error::Unsupported);
        }
        let primary = channel(config.frequency_mhz)?;
        let chanspec = if primary <= 14 { 0x1000 } else { 0xd000 } | u16::from(primary);
        let capability = header(&config.beacon_head, &config, own, false)?;
        let mut ies = config.beacon_head[36..].to_vec();
        ies.extend_from_slice(&config.beacon_tail);
        let beacon = elements(
            &ies,
            &config,
            if config.hidden_ssid == 1 {
                Ssid::Hidden
            } else {
                Ssid::Visible
            },
        )?;
        let wpa_auth = if let Some(element) = &beacon.rsne {
            use narf_wireless::rsn::{RsnIe, Suite, CIPHER_CCMP_128, RSN_OUI};
            let rsn = RsnIe::decode_body(&element[2..]).ok_or(Error::Malformed)?;
            if rsn.group_cipher != Suite::standard(CIPHER_CCMP_128)
                || rsn.pairwise_ciphers != [Suite::standard(CIPHER_CCMP_128)]
                || rsn.akms.len() != 1
                || rsn.akms[0].oui != RSN_OUI
                || !matches!(rsn.akms[0].suite_type, 1 | 2)
                || rsn.rsn_capabilities != 0
                || !rsn.pmkids.is_empty()
                || rsn.group_management_cipher.is_some()
                || !config.privacy
                || settings.wpa_versions.is_some_and(|v| v != 2)
                || settings
                    .group_cipher
                    .is_some_and(|v| v != narf_wireless::CIPHER_SUITE_CCMP)
                || settings
                    .pairwise_ciphers
                    .as_ref()
                    .is_some_and(|v| v.as_slice() != [narf_wireless::CIPHER_SUITE_CCMP])
                || settings.akms.as_ref().is_some_and(|v| {
                    v.as_slice() != [0x000fac00 | u32::from(rsn.akms[0].suite_type)]
                })
            {
                return Err(Error::Unsupported);
            }
            if rsn.akms[0].suite_type == 1 {
                0x40
            } else {
                0x80
            }
        } else {
            if config.privacy
                || settings.wpa_versions.is_some()
                || settings.group_cipher.is_some()
                || settings.pairwise_ciphers.is_some()
                || settings.akms.is_some()
            {
                return Err(Error::Malformed);
            }
            0
        };
        let probe_vendor = if let Some(probe) = &config.probe_resp {
            if header(probe, &config, own, true)? != capability {
                return Err(Error::Malformed);
            }
            let probe = elements(&probe[36..], &config, Ssid::Visible)?;
            if !same_rates(&probe.rates, &beacon.rates) || probe.rsne != beacon.rsne {
                return Err(Error::Malformed);
            }
            probe.vendor
        } else {
            beacon.vendor.clone()
        };
        Ok(Self {
            config,
            settings,
            own,
            primary,
            chanspec,
            capability,
            rates: beacon.rates,
            rsne: beacon.rsne,
            wpa_auth,
            beacon_vendor: beacon.vendor,
            probe_vendor,
        })
    }
}
pub(super) fn same_rates(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().all(|rate| right.contains(rate))
}
