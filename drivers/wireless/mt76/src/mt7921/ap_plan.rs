//! Native AP template validation before any firmware publication.
//! Linux mac80211 AP templates insert TIM between head/tail; CONNAC2 owns
//! beacon timing and station PS (IEEE80211_HW_AP_LINK_PS).

use super::{LegacyRate, TxPermission, RATES};
use crate::mt7921::{
    channel,
    firmware_transport::{Error, RadioInfo},
};
use alloc::vec::Vec;
use narf_wireless::{
    reg::RegulatoryDomain,
    rsn::{self, RsnIe, Suite},
    ApConfig,
};

#[derive(Clone)]
pub(crate) struct Plan {
    pub config: ApConfig,
    pub own: [u8; 6],
    pub channel: u8,
    pub five_ghz: bool,
    pub permission: TxPermission,
    pub rate: LegacyRate,
    pub rates: u16,
    pub basic_rates: u16,
    pub beacon: Vec<u8>,
    pub tim_offset: usize,
    pub probe: Vec<u8>,
    /// AP or P2P-GO BSS connection type; bound from the START authority's
    /// actual mode, never inferred from beacon/P2P elements.
    pub network: crate::mt7921::p2p_wire::Network,
}

impl core::fmt::Debug for Plan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApPlan")
            .field("own", &self.own)
            .field("channel", &self.channel)
            .field("rate", &self.rate)
            .finish_non_exhaustive()
    }
}

impl Plan {
    pub fn prepare(
        info: RadioInfo,
        config: ApConfig,
        domain: &RegulatoryDomain,
    ) -> Result<Self, Error> {
        let own = info.capabilities.mac;
        let (band, channel) =
            narf_wireless::association::channel::from_frequency_band(config.frequency_mhz)
                .ok_or(Error::Bounds)?;
        let five_ghz = match band {
            narf_wireless::association::channel::Band::Ghz2 => false,
            narf_wireless::association::channel::Band::Ghz5 => true,
            _ => return Err(Error::UnsupportedFirmware),
        };
        if own == [0; 6]
            || own[0] & 1 != 0
            || info.capabilities.phy.bands & if five_ghz { 2 } else { 1 } == 0
            || channel::frequency(channel) != Some(config.frequency_mhz)
            || config.channel_width != 0
            || config
                .center_freq1_mhz
                .is_some_and(|center| center != config.frequency_mhz)
            || config.center_freq2_mhz.is_some_and(|center| center != 0)
            || config.ssid.is_empty()
            || config.ssid.len() > 32
            || config.hidden_ssid > 2
            || !(1..=65535).contains(&config.beacon_interval)
            || !(1..=255).contains(&config.dtim_period)
            || config.mbssid.is_some()
            || !config.mbssid_elems.is_empty()
            || !config.ema_rnr_elems.is_empty()
            || config.fils_discovery.is_some()
            || config.unsol_bcast_probe_resp.is_some()
            || config.ftm_responder.is_some()
            || config.twt_responder
            || config.he_obss_pd.is_some()
            || config.he_bss_color.is_some()
        {
            return Err(Error::Bounds);
        }
        // No inferred country/profile or DFS/CAC permission: this is the
        // same actual full occupied-channel grant used by native station TX.
        let permission = TxPermission::from_domain(domain, channel).ok_or(Error::Authority)?;
        header(&config.beacon_head, 0x80, own, &config)?;
        // TIM insertion is at the head/tail boundary. A split IE would be
        // malformed after insertion even if simple concatenation decoded.
        for mut rest in [&config.beacon_head[36..], &config.beacon_tail[..]] {
            while !rest.is_empty() {
                let header = rest.get(..2).ok_or(Error::Bounds)?;
                let length = 2 + usize::from(header[1]);
                rest = rest.get(length..).ok_or(Error::Bounds)?;
            }
        }
        let mut ies = config.beacon_head[36..].to_vec();
        ies.extend_from_slice(&config.beacon_tail);
        let (rates, basic_rates) = elements(&ies, &config, five_ghz, false)?;
        let tim_offset = config.beacon_head.len();
        let mut beacon = config.beacon_head.clone();
        // Three bitmap bytes cover actual MT7921_MAX_AID20. Firmware owns
        // the PS/TIM bits; this starts with no buffered station traffic.
        beacon.extend_from_slice(&[5, 6, 0, config.dtim_period as u8, 0, 0, 0, 0]);
        beacon.extend_from_slice(&config.beacon_tail);
        if beacon.len() > 480 {
            return Err(Error::Bounds);
        }
        let probe = if let Some(probe) = &config.probe_resp {
            header(probe, 0x50, own, &config)?;
            elements(&probe[36..], &config, five_ghz, true)?;
            probe.clone()
        } else {
            let mut probe = config.beacon_head[..36].to_vec();
            probe[0] = 0x50;
            let mut rest = &ies[..];
            while !rest.is_empty() {
                let length = 2 + usize::from(rest[1]);
                if rest[0] == 0 {
                    probe.extend_from_slice(&[0, config.ssid.len() as u8]);
                    probe.extend_from_slice(&config.ssid);
                } else {
                    probe.extend_from_slice(&rest[..length]);
                }
                rest = &rest[length..];
            }
            probe
        };
        if probe.len() > 4032 {
            return Err(Error::Bounds);
        }
        Ok(Self {
            config,
            own,
            channel,
            five_ghz,
            permission,
            rate: LegacyRate::lowest(basic_rates),
            rates,
            basic_rates,
            beacon,
            tim_offset,
            probe,
            network: crate::mt7921::p2p_wire::Network::Infrastructure,
        })
    }

    /// Build only a response to an actual received probe request on this
    /// AP's authorized channel. The normal MAC owner decides whether a
    /// registered host MLME listener owns that request instead.
    pub fn probe_response(&self, request: &[u8]) -> Option<Vec<u8>> {
        if request.len() < 26
            || request[..2] != [0x40, 0]
            || request[10..16] == [0; 6]
            || request[10] & 1 != 0
            || request[22] & 15 != 0
            || !(request[4..10] == self.own || request[4..10] == [0xff; 6])
            || !(request[16..22] == self.own || request[16..22] == [0xff; 6])
        {
            return None;
        }
        let mut rest = &request[24..];
        let mut ssid = None;
        while !rest.is_empty() {
            let prefix = rest.get(..2)?;
            let element = rest.get(2..2 + usize::from(prefix[1]))?;
            if prefix[0] == 0 && (ssid.replace(element).is_some() || element.len() > 32) {
                return None;
            }
            rest = &rest[2 + element.len()..];
        }
        let ssid = ssid?;
        if !(ssid == self.config.ssid || ssid.is_empty() && self.config.hidden_ssid == 0) {
            return None;
        }
        let mut response = self.probe.clone();
        response[4..10].copy_from_slice(&request[10..16]);
        Some(response)
    }
}

fn header(frame: &[u8], subtype: u8, own: [u8; 6], config: &ApConfig) -> Result<(), Error> {
    if frame.len() < 36
        || frame[..2] != [subtype, 0]
        || frame[4..10] != [0xff; 6]
        || frame[10..16] != own
        || frame[16..22] != own
        || frame[22] & 15 != 0
        || frame[32..34] != (config.beacon_interval as u16).to_le_bytes()
    {
        return Err(Error::Bounds);
    }
    let capability = u16::from_le_bytes([frame[34], frame[35]]);
    if capability & 1 == 0 || capability & !0x0431 != 0 || (capability & 16 != 0) != config.privacy
    {
        return Err(Error::Bounds);
    }
    Ok(())
}

fn elements(ies: &[u8], config: &ApConfig, five: bool, probe: bool) -> Result<(u16, u16), Error> {
    let mut rest = ies;
    let mut ssid = false;
    let mut supported = false;
    let mut extended = false;
    let mut rsn = false;
    let mut rates = 0u16;
    let mut basic = 0u16;
    while !rest.is_empty() {
        let prefix = rest.get(..2).ok_or(Error::Bounds)?;
        let body = rest
            .get(2..2 + usize::from(prefix[1]))
            .ok_or(Error::Bounds)?;
        match prefix[0] {
            0 => {
                if ssid || body.len() > 32 {
                    return Err(Error::Bounds);
                }
                ssid = true;
                let valid = if probe || config.hidden_ssid == 0 {
                    body == config.ssid
                } else if config.hidden_ssid == 1 {
                    body.is_empty()
                } else {
                    body.len() == config.ssid.len() && body.iter().all(|byte| *byte == 0)
                };
                if !valid {
                    return Err(Error::Bounds);
                }
            }
            1 | 50 => {
                let seen = if prefix[0] == 1 {
                    &mut supported
                } else {
                    &mut extended
                };
                if *seen || body.is_empty() || prefix[0] == 1 && body.len() > 8 {
                    return Err(Error::Bounds);
                }
                *seen = true;
                for &rate in body {
                    let index = RATES
                        .iter()
                        .position(|known| *known == rate & 127)
                        .ok_or(Error::Bounds)?;
                    if five && index < 4 {
                        return Err(Error::Bounds);
                    }
                    rates |= 1 << index;
                    if rate & 128 != 0 {
                        basic |= 1 << index;
                    }
                }
            }
            3 if body != [((config.frequency_mhz - if five { 5000 } else { 2407 }) / 5) as u8] => {
                return Err(Error::Bounds)
            }
            48 => {
                if rsn || !config.privacy {
                    return Err(Error::UnsupportedFirmware);
                }
                rsn = true;
                let parsed = RsnIe::decode_body(body).ok_or(Error::UnsupportedFirmware)?;
                if parsed.group_cipher != Suite::standard(rsn::CIPHER_CCMP_128)
                    || parsed.pairwise_ciphers != [Suite::standard(rsn::CIPHER_CCMP_128)]
                    || parsed.akms != [Suite::standard(rsn::AKM_PSK)]
                    || parsed.rsn_capabilities & (3 << 6) != 0
                {
                    return Err(Error::UnsupportedFirmware);
                }
            }
            5 | 37 | 40 | 45 | 60 | 61 | 191 | 192 | 255 => return Err(Error::Bounds),
            221 if body.starts_with(&[0, 0x50, 0xf2, 1])
                || body.starts_with(&[0, 0x50, 0xf2, 2]) =>
            {
                return Err(Error::UnsupportedFirmware)
            }
            _ => {}
        }
        rest = &rest[2 + body.len()..];
    }
    if !ssid || !supported || basic == 0 || rsn != config.privacy {
        return Err(Error::Bounds);
    }
    Ok((rates, basic))
}
