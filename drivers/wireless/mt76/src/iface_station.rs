//! The station helpers both netdevs share: scan channel plans, scan-result
//! translation, join validation and resolution. Moved verbatim from
//! `iface.rs` so the built-in `Mt76Iface` and the module's station netdev
//! (`iface_module.rs`) run the same code.

use crate::mt7921::firmware_transport::{RadioInfo, ScanBss};
use alloc::vec::Vec;
use narf_wireless::{scan::BssInfo, AssociateRequest, ScanRequest, WirelessError};

pub(crate) fn transmit_admitted(bytes: &[u8], local: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == local
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && bytes[12..14] != [0x88, 0x8e]
}

/// Scan channel ids (`channel::rx_channel`: 2.4/5 GHz channel numbers, 6 GHz
/// RXD CH_FREQ values 181..=239). 6 GHz entries come only from 6 GHz
/// frequencies (or, for a default colocated scan, the whole 6 GHz sband):
/// a bare channel number never selects 6 GHz.
pub(crate) fn scan_channels(
    req: &ScanRequest,
    bands: u8,
    six: bool,
) -> Result<Vec<u8>, WirelessError> {
    use crate::mt7921::channel;
    if req.duration_mandatory || req.duration_tu.is_some() {
        return Err(WirelessError::NotSupported);
    }
    if req.colocated_6ghz && !six {
        return Err(WirelessError::NotSupported);
    }
    crate::mt7921::firmware_transport::validate_scan_options(
        crate::mt7921::firmware_transport::ScanOptions {
            extra_ies: &req.extra_ies,
            random_mac: req.random_mac,
        },
    )
    .map_err(|_| WirelessError::InvalidArgs)?;
    if !req.active && !req.extra_ies.is_empty() {
        return Err(WirelessError::InvalidArgs);
    }
    if !req.active && !req.ssids.is_empty()
        || req.ssids.len() > 4
        || req.ssids.iter().any(|ssid| ssid.len() > 32)
    {
        return Err(WirelessError::InvalidArgs);
    }
    let requested = if req.frequencies_mhz.is_empty() {
        req.channels.clone()
    } else {
        let channels = req
            .frequencies_mhz
            .iter()
            .map(|&freq| {
                if let Some((narf_wireless::association::channel::Band::Ghz6, number)) =
                    narf_wireless::association::channel::from_frequency_band(freq)
                {
                    if !six {
                        return Err(WirelessError::NotSupported);
                    }
                    return channel::rx_channel(channel::Band::Ghz6, number)
                        .map(u32::from)
                        .ok_or(WirelessError::NotSupported);
                }
                channel::from_frequency(freq)
                    .map(u32::from)
                    .ok_or(WirelessError::NotSupported)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The legacy selector names channel numbers, not scan ids.
        let numbers: Vec<u32> = channels
            .iter()
            .filter_map(|&id| {
                channel::from_rx_channel(u8::try_from(id).ok()?).map(|(_, n)| u32::from(n))
            })
            .collect();
        if !req.channels.is_empty()
            && (req.channels.len() != numbers.len()
                || !req.channels.iter().all(|channel| numbers.contains(channel)))
        {
            return Err(WirelessError::InvalidArgs);
        }
        channels
    };
    if requested.is_empty() {
        let mut channels = channel::channels(bands);
        // cfg80211 includes every 6 GHz channel; the colocated plan below
        // narrows them (cfg80211_scan_6ghz). Without the flag a default
        // scan keeps its 2.4/5 GHz profile.
        if req.colocated_6ghz {
            channels.extend(
                channel::channels_6ghz()
                    .filter_map(|number| channel::rx_channel(channel::Band::Ghz6, number)),
            );
        }
        return Ok(channels);
    }
    let mut channels = Vec::new();
    for requested in requested {
        let value = u8::try_from(requested).map_err(|_| WirelessError::InvalidArgs)?;
        let (band, _) = channel::from_rx_channel(value).ok_or(WirelessError::InvalidArgs)?;
        if band != channel::Band::Ghz6 && bands & band.capability() == 0 {
            return Err(WirelessError::NotSupported);
        }
        if band == channel::Band::Ghz6 && req.frequencies_mhz.is_empty() {
            return Err(WirelessError::InvalidArgs);
        }
        if channels.contains(&value) {
            return Err(WirelessError::InvalidArgs);
        }
        channels.push(value);
    }
    Ok(channels)
}

/// A native scan result as cfg80211 reports it.
pub(crate) fn bss_info(bss: &ScanBss) -> BssInfo {
    BssInfo {
        bssid: bss.bssid,
        ssid: bss.ssid.clone(),
        frequency_mhz: scan_frequency(bss).unwrap_or(0),
        channel: u32::from(bss.channel),
        rssi: bss.signal_dbm.unwrap_or(-128),
        security: scan_security(bss),
    }
}

/// A scan result's centre frequency in its own band.
pub(crate) fn scan_frequency(bss: &crate::mt7921::firmware_transport::ScanBss) -> Option<u32> {
    use crate::mt7921::channel;
    if crate::mt7921::association::is_six_ghz(bss) {
        channel::frequency_in(channel::Band::Ghz6, bss.channel)
    } else {
        channel::frequency(bss.channel)
    }
}

/// cfg80211 `cfg80211_scan_6ghz` for the split 6 GHz phase: the colocated
/// APs of the 2.4/5 GHz results' Reduced Neighbor Reports
/// (`parse_colocated_aps`) select the requested 6 GHz channels through the
/// shared `plan_6ghz_scan`. Without `colocated_6ghz` every requested 6 GHz
/// channel is scanned. The result is in scan-id form, deduplicated.
///
/// Linux v7.2 mt7921 programs no per-target fields: `mt76_connac_mcu_hw_scan`
/// sends only the 6 GHz channel list (band 3), and the RNR BSSID table of
/// `mt76_connac_mcu_build_rnr_scan_param` is consumed by mt7925 alone.
pub(crate) fn six_ghz_scan_ids(
    req: &ScanRequest,
    requested: &[u8],
    found: &[crate::mt7921::firmware_transport::ScanBss],
) -> Vec<u8> {
    use crate::mt7921::channel;
    use narf_wireless::association::channel::{from_frequency_band, Band};
    if requested.is_empty() {
        return Vec::new();
    }
    let colocated: Vec<narf_wireless::scan::ColocatedAp> = found
        .iter()
        .filter(|bss| !crate::mt7921::association::is_six_ghz(bss))
        .flat_map(|bss| narf_wireless::scan::parse_colocated_aps(&bss.information_elements))
        .collect();
    let six_request = ScanRequest {
        ssids: req.ssids.clone(),
        frequencies_mhz: requested
            .iter()
            .filter_map(|&id| channel::from_rx_channel(id))
            .filter_map(|(band, number)| channel::frequency_in(band, number))
            .collect(),
        channels: Vec::new(),
        active: req.active,
        random_mac: req.random_mac,
        colocated_6ghz: req.colocated_6ghz,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    };
    let plan = narf_wireless::scan::plan_6ghz_scan(&six_request, &colocated, None);
    let mut ids = Vec::new();
    for mhz in plan.frequencies_mhz {
        if let Some((Band::Ghz6, number)) = from_frequency_band(mhz) {
            if let Some(id) = channel::rx_channel(channel::Band::Ghz6, number) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
    }
    ids
}

pub(crate) fn active_channels(
    request: &ScanRequest,
    mut channels: Vec<u8>,
    domain: &narf_wireless::reg::RegulatoryDomain,
) -> Result<Vec<u8>, WirelessError> {
    let allowed = |channel: &u8| {
        crate::mt7921::association::TxPermission::from_domain(domain, *channel).is_some()
    };
    if request.channels.is_empty() && request.frequencies_mhz.is_empty() {
        channels.retain(allowed);
    } else if !channels.iter().all(allowed) {
        return Err(WirelessError::Denied);
    }
    if channels.is_empty() {
        return Err(WirelessError::Denied);
    }
    Ok(channels)
}

pub(crate) fn scan_security(
    bss: &crate::mt7921::firmware_transport::ScanBss,
) -> narf_wireless::scan::BssSecurity {
    use narf_wireless::{rsn, scan::BssSecurity};
    let mut ies = &bss.information_elements[..];
    let mut wpa = false;
    while ies.len() >= 2 {
        let len = usize::from(ies[1]);
        let Some(value) = ies.get(2..2 + len) else {
            break;
        };
        if ies[0] == 48 {
            if let Some(rsn) = rsn::RsnIe::decode_body(value) {
                return if !rsn.akms.contains(&rsn::Suite::standard(rsn::AKM_PSK))
                    && rsn.akms.contains(&rsn::Suite::standard(rsn::AKM_SAE))
                {
                    BssSecurity::Wpa3
                } else {
                    BssSecurity::Wpa2
                };
            }
        }
        wpa |= ies[0] == 221 && value.starts_with(&[0, 0x50, 0xf2, 1]);
        ies = &ies[2 + len..];
    }
    if wpa {
        BssSecurity::Wpa
    } else if bss.capability & 0x10 != 0 {
        BssSecurity::Wep
    } else {
        BssSecurity::Open
    }
}
/// Request validation shared by the home station, the concurrent
/// P2P-client group netdev (built in) and the module's station; returns
/// whether the target is 6 GHz. Runs before any recovery I/O.
pub(crate) fn validate_join(
    radio: RadioInfo,
    req: &AssociateRequest,
) -> Result<bool, WirelessError> {
    let channel = u8::try_from(req.channel).map_err(|_| WirelessError::InvalidArgs)?;
    // A 6 GHz request is identified by its frequency: channel numbers
    // alone collide with 2.4/5 GHz.
    let six = narf_wireless::association::channel::from_frequency_band(req.frequency_mhz)
        == Some((narf_wireless::association::channel::Band::Ghz6, channel));
    if !six && crate::mt7921::channel::frequency(channel) != Some(req.frequency_mhz) {
        return Err(WirelessError::InvalidArgs);
    }
    if six && !crate::mt7921::six_ghz::qualified(radio) {
        return Err(WirelessError::NotSupported);
    }
    if req.ssid.is_empty() || req.ssid.len() > 32 || req.bssid == [0; 6] || req.bssid[0] & 1 != 0 {
        return Err(WirelessError::InvalidArgs);
    }
    use narf_wireless::association::SmeRsna;
    let rsna = match &req.security {
        narf_wireless::SecurityConfig::Open => SmeRsna::Open,
        // The supplicant's own AKM and PMF selection (PSK-SHA256,
        // ieee80211w=1/2) is what the owner will negotiate.
        narf_wireless::SecurityConfig::Wpa2 { psk } => {
            match crate::mt7921::association::Security::wpa2_from_supplicant(*psk, &req.ie) {
                Some(crate::mt7921::association::Security::Wpa2PskSelected {
                    akm, pmf, ..
                }) => SmeRsna::Wpa2 {
                    akm,
                    mfp: match pmf {
                        narf_wireless::association::Pmf::Disabled => 0,
                        narf_wireless::association::Pmf::Optional => {
                            narf_wireless::rsn::RSN_CAP_MFP_CAPABLE
                        }
                        narf_wireless::association::Pmf::Required => {
                            narf_wireless::rsn::RSN_CAP_MFP_CAPABLE
                                | narf_wireless::rsn::RSN_CAP_MFP_REQUIRED
                        }
                    },
                },
                Some(_) => SmeRsna::Wpa2Psk,
                None => return Err(WirelessError::NotSupported),
            }
        }
        narf_wireless::SecurityConfig::Wpa3 { .. } => SmeRsna::Wpa3Sae,
        _ => return Err(WirelessError::NotSupported),
    };
    narf_wireless::association::validate_sme_ies_for(&req.ie, rsna).map_err(
        |error| match error {
            crate::mt7921::association::Error::InvalidBss => WirelessError::InvalidArgs,
            _ => WirelessError::NotSupported,
        },
    )?;
    Ok(six)
}
/// Resolve the cached scan target and the native security owner, and
/// require a current transmit permission for it.
///
/// `follow_heard_ap` (the infrastructure station only) admits a radar or
/// NO_IR channel when the latest scan received the BSS's own Beacon;
/// the returned flag says whether the grant depends on that.
pub(crate) fn resolve_join(
    radio: RadioInfo,
    scan: &[ScanBss],
    beaconed: &[([u8; 6], u8)],
    req: &AssociateRequest,
    security: narf_wireless::SecurityConfig,
    six: bool,
    follow_heard_ap: bool,
) -> Result<(ScanBss, crate::mt7921::association::Security, bool), WirelessError> {
    let security = match security {
        narf_wireless::SecurityConfig::Open => crate::mt7921::association::Security::Open,
        narf_wireless::SecurityConfig::Wpa2 { psk } => {
            crate::mt7921::association::Security::wpa2_from_supplicant(psk, &req.ie)
                .ok_or(WirelessError::NotSupported)?
        }
        // WPA3-Personal: the driver runs SAE (sae_pwe=2) and PMF itself.
        narf_wireless::SecurityConfig::Wpa3 { password } => {
            crate::mt7921::association::Security::Wpa3Sae {
                password: crate::mt7921::association::SaePassword::new(&password)
                    .ok_or(WirelessError::InvalidArgs)?,
            }
        }
        // No external-supplicant mode: mt7921's firmware path runs the
        // handshake from the PMK (nl80211 never builds this for it).
        narf_wireless::SecurityConfig::External(_) => return Err(WirelessError::NotSupported),
    };
    let bss = scan
        .iter()
        .find(|b| {
            b.bssid == req.bssid
                && b.ssid == req.ssid
                && u32::from(b.channel) == req.channel
                && crate::mt7921::association::is_six_ghz(b) == six
        })
        .cloned()
        .ok_or(WirelessError::InvalidArgs)?;

    let domain = crate::platform::reg_db::ensure_domain().map_err(|_| WirelessError::Denied)?;
    let heard = follow_heard_ap && !six && beaconed.contains(&(bss.bssid, bss.channel));
    let grant = if six {
        crate::mt7921::association::TxPermission::from_ap(&domain, radio, &bss)
    } else if heard {
        crate::mt7921::association::TxPermission::from_heard_ap(&domain, bss.channel)
    } else {
        crate::mt7921::association::TxPermission::from_domain(&domain, bss.channel)
    }
    .ok_or(WirelessError::Denied)?;

    Ok((bss, security, grant.follows_heard_ap()))
}

/// Legacy 20 MHz channels on firmware-reported bands (the wiphy's sbands).
pub(crate) fn bands(radio: RadioInfo) -> Vec<narf_wireless::iface::WirelessBand> {
    use narf_wireless::iface::WirelessBand;
    let mut bands = Vec::new();
    if radio.capabilities.phy.bands & 1 != 0 {
        bands.push(WirelessBand {
            freq_mhz: 2400,
            channels: (1..=11).collect(),
        });
    }
    if radio.capabilities.phy.bands & 2 != 0 {
        bands.push(WirelessBand {
            freq_mhz: 5000,
            channels: crate::mt7921::channel::CHANNELS_5GHZ
                .into_iter()
                .map(u32::from)
                .collect(),
        });
    }
    // mt7921_set_stream_he_caps: the 6 GHz sband exists only with
    // MT_NIC_CAP_6G (and inside has_5ghz).
    if crate::mt7921::six_ghz::qualified(radio) {
        bands.push(WirelessBand {
            freq_mhz: 6000,
            channels: crate::mt7921::channel::channels_6ghz()
                .map(u32::from)
                .collect(),
        });
    }
    bands
}

/// The cipher suites the station owner installs (the built-in wiphy's).
pub(crate) const CIPHER_SUITES: &[u32] = &[
    narf_wireless::CIPHER_SUITE_CCMP,
    narf_wireless::CIPHER_SUITE_CCMP_256,
    narf_wireless::CIPHER_SUITE_GCMP,
    narf_wireless::CIPHER_SUITE_GCMP_256,
    narf_wireless::CIPHER_SUITE_AES_CMAC,
    narf_wireless::CIPHER_SUITE_BIP_CMAC_256,
    narf_wireless::CIPHER_SUITE_BIP_GMAC_128,
    narf_wireless::CIPHER_SUITE_BIP_GMAC_256,
];
