//! Source-pinned AP plan and native MLD MAC/LINK/STA/beacon/key bytes.
//! These codecs confer no source, radio, key-install or peer authority.
use super::{
    boot_context::{put16, put32},
    native_band::Channel,
    rates::Rates,
    station_api,
};
use alloc::{vec, vec::Vec};
use narf_wireless::{ApConfig, ApStartSettings, StationConfig};

pub(super) const MCAST: u8 = 0;
pub(super) const BCAST: u8 = 1;
pub(super) const FIRST_PEER: u8 = 2;
pub(super) const MAX_PEERS: usize = 8;

pub(super) struct Plan {
    pub config: ApConfig,
    pub channel: Channel,
    pub rates: Rates,
    pub rsn: Option<narf_wireless::rsn::RsnIe>,
    pub beacon: Vec<u8>,
    pub tim: usize,
    pub go: Option<super::p2p_go::Identity>,
}
impl Plan {
    pub fn new(
        config: ApConfig,
        settings: &ApStartSettings,
        own: [u8; 6],
    ) -> Result<Self, &'static str> {
        if config.ssid.is_empty()
            || config.ssid.len() > 32
            || !(10..=65535).contains(&config.beacon_interval)
            || !(1..=255).contains(&config.dtim_period)
            || !matches!(config.channel_width, 0 | 1)
            || config.center_freq2_mhz.is_some()
            || config
                .center_freq1_mhz
                .is_some_and(|f| f != config.frequency_mhz)
            || config.hidden_ssid > 2
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
        {
            return Err("unsupported native AP geometry/optional service");
        }
        let channel = (1..=196)
            .filter_map(Channel::legacy)
            .find(|ch| ch.frequency() == config.frequency_mhz)
            .ok_or("AP frequency has no actual legacy native channel")?;
        let mut beacon = config.beacon_head.clone();
        if !(36..=2048).contains(&beacon.len())
            || beacon[0] != 0x80
            || beacon[1] & 0xc7 != 0
            || beacon[4..10] != [0xff; 6]
            || beacon[10..16] != own
            || beacon[16..22] != own
        {
            return Err("AP beacon physical identity/header invalid");
        }
        let mut elements = beacon[36..].to_vec();
        elements.extend_from_slice(&config.beacon_tail);
        let mut ssid = None;
        let mut rsn = None;
        for (id, body) in elements_iter(&elements)? {
            if matches!(id, 5 | 45 | 61 | 191 | 192)
                || id == 255
                    && body
                        .first()
                        .is_some_and(|x| matches!(x, 35 | 36 | 59 | 106 | 107 | 108))
            {
                return Err("AP20 legacy profile cannot advertise unsupported TIM/HT/HE/EHT/MLD");
            }
            if id == 0 && ssid.replace(body).is_some() {
                return Err("AP duplicate SSID");
            }
            if id == 3 && body != [channel.number] {
                return Err("AP DS channel differs from native frequency");
            }
            if id == 48 {
                if rsn.is_some() {
                    return Err("AP duplicate RSNE");
                }
                rsn = Some(narf_wireless::rsn::RsnIe::decode_body(body).ok_or("AP invalid RSNE")?);
            }
        }
        let ssid = ssid.ok_or("AP beacon omitted SSID")?;
        let ssid_valid = match config.hidden_ssid {
            0 => ssid == config.ssid,
            1 => ssid.is_empty(),
            _ => ssid.len() == config.ssid.len() && ssid.iter().all(|&b| b == 0),
        };
        if !ssid_valid {
            return Err("AP hidden SSID differs from requested beacon");
        }
        if config.privacy != rsn.is_some() {
            return Err("AP privacy requires an actual supported RSNE");
        }
        if let Some(rsn) = &rsn {
            use narf_wireless::rsn::*;
            if rsn.rsn_capabilities & RSN_CAP_MFP_REQUIRED != 0
                && rsn.rsn_capabilities & RSN_CAP_MFP_CAPABLE == 0
                || rsn.akms.iter().all(|a| matches!(a.suite_type, 8 | 24))
                    && rsn.rsn_capabilities & 0xc0 != 0xc0
                || rsn.group_cipher != Suite::standard(CIPHER_CCMP_128)
                || rsn.pairwise_ciphers.is_empty()
                || rsn
                    .pairwise_ciphers
                    .iter()
                    .any(|&s| s != Suite::standard(CIPHER_CCMP_128))
                || rsn.akms.is_empty()
                || rsn
                    .akms
                    .iter()
                    .any(|s| s.oui != RSN_OUI || !matches!(s.suite_type, 2 | 6 | 8 | 24))
                || rsn
                    .group_management_cipher
                    .is_some_and(|s| s != Suite::standard(CIPHER_BIP_CMAC_128))
            {
                return Err("AP cipher/AKM has no native CCMP/CMAC contract");
            }
            if settings.wpa_versions.is_some_and(|v| v != 2)
                || settings.pairwise_ciphers.as_ref().is_some_and(|s| {
                    s.len() != rsn.pairwise_ciphers.len() || s.iter().any(|&c| c != 0x000f_ac04)
                })
                || settings.group_cipher.is_some_and(|c| c != 0x000f_ac04)
                || settings.akms.as_ref().is_some_and(|s| {
                    s.len() != rsn.akms.len()
                        || s.iter().any(|&a| {
                            !rsn.akms
                                .iter()
                                .any(|x| a == (0x000f_ac00 | u32::from(x.suite_type)))
                        })
                })
            {
                return Err("AP START crypto metadata differs from on-air RSNE");
            }
        } else if settings.wpa_versions.is_some()
            || settings.pairwise_ciphers.is_some()
            || settings.group_cipher.is_some()
            || settings.akms.is_some()
        {
            return Err("open AP received secure START settings");
        }
        if settings.auth_type.is_some_and(|a| !matches!(a, 0 | 4))
            || settings.control_port.enabled
                && (!settings.control_port.over_nl80211
                    || settings.control_port.ethertype != 0x888e)
            || rsn.is_some() && !settings.control_port.enabled
        {
            return Err("AP userspace SME/control-port contract absent");
        }
        let h2e = rsn
            .as_ref()
            .is_some_and(|r| r.akms.iter().any(|a| matches!(a.suite_type, 8 | 24)))
            && elements_iter(&elements)?.iter().any(|(id, b)| {
                *id == 244
                    && b.first()
                        .is_some_and(|v| v & narf_wireless::rsn::RSNX_CAP_SAE_H2E != 0)
            });
        let rates = Rates::parse_for_security(&elements, channel.number, 0, h2e)?;
        beacon[24..32].fill(0);
        put16(&mut beacon, 32, config.beacon_interval as u16);
        let capability = u16::from_le_bytes(beacon[34..36].try_into().unwrap());
        if capability & 3 != 1 || (capability & 0x10 != 0) != config.privacy {
            return Err("AP ESS/privacy beacon capability mismatch");
        }
        if let Some(probe) = &config.probe_resp {
            if !(36..=2048).contains(&probe.len())
                || probe[0] != 0x50
                || probe[1] & 0xc7 != 0
                || probe[10..16] != own
                || probe[16..22] != own
                || probe[34..36] != beacon[34..36]
            {
                return Err("AP probe template identity/capability invalid");
            }
            let mut probe_ssid = None;
            let mut probe_rsn = None;
            for (id, body) in elements_iter(&probe[36..])? {
                if matches!(id, 5 | 45 | 61 | 191 | 192)
                    || id == 255
                        && body
                            .first()
                            .is_some_and(|x| matches!(x, 35 | 36 | 59 | 106 | 107 | 108))
                {
                    return Err("AP probe cannot advertise an unsupported PHY/TIM/MLD");
                }
                if id == 0 && probe_ssid.replace(body).is_some() {
                    return Err("AP duplicate probe SSID");
                }
                if id == 3 && body != [channel.number] {
                    return Err("AP probe DS channel differs from native frequency");
                }
                if id == 48 {
                    if probe_rsn.is_some() {
                        return Err("AP duplicate probe RSNE");
                    }
                    probe_rsn = Some(
                        narf_wireless::rsn::RsnIe::decode_body(body)
                            .ok_or("AP invalid probe RSNE")?,
                    );
                }
            }
            let probe_rates = Rates::parse_for_security(&probe[36..], channel.number, 0, h2e)?;
            if probe_ssid != Some(config.ssid.as_slice())
                || probe_rsn != rsn
                || probe_rates.supported != rates.supported
                || probe_rates.basic != rates.basic
            {
                return Err("AP probe SSID/security/rates differ from beacon owner");
            }
        }
        let tim = beacon.len();
        beacon.extend_from_slice(&[5, 4, 0, config.dtim_period as u8, 0, 0]);
        beacon.extend_from_slice(&config.beacon_tail);
        if beacon.len() > 2048 {
            return Err("AP native beacon exceeds bounded template");
        }
        Ok(Self {
            config,
            channel,
            rates,
            rsn,
            beacon,
            tim,
            go: None,
        })
    }
    /// GO is an actual P2P beacon/probe/rate contract, distinct from the
    /// firmware GO8 value also used by ordinary AP3. This plan grants no RF.
    /// `noa_index` versions the driver-owned NoA attribute: 0 at GO
    /// start, +1 per live power-save update (tracked by the Session).
    pub fn new_go(
        config: ApConfig,
        settings: &ApStartSettings,
        own: [u8; 6],
        noa_index: u8,
    ) -> Result<Self, &'static str> {
        // Ordinary APs refuse GO power-save fields; GO plans own them
        // below, so strip them before the shared geometry validation.
        let mut stripped = settings.clone();
        stripped.p2p_go = None;
        let mut plan = Self::new(config, &stripped, own)?;
        let identity = super::p2p_go::Identity::beacon(&plan.beacon[36..])?;
        if !plan.secure() {
            return Err("GO requires an actual protected group/key owner");
        }
        if plan.rates.supported & 15 != 0 || plan.rates.basic & 15 != 0 {
            return Err("GO actual P2P beacon cannot advertise CCK rates");
        }
        if let Some(probe) = &plan.config.probe_resp {
            identity.probe(&probe[36..])?;
        }
        if let Some(ps) = settings.p2p_go {
            ps.validate()
                .map_err(|_| "GO power-save CTWindow exceeds 127")?;
            // Linux MLD programs GO PS through no MAC_CONFIG field
            // (the v3 union has client/p2p_dev only; mld-mac.c sets
            // ctwin for the client only) — the GO advertises its
            // schedule in the beacon's NoA attribute, which the
            // firmware transmits from this template. The driver-owned
            // attribute replaces any SME-supplied NoA wholesale.
            let ctwindow = ps.ctwindow_tu.unwrap_or(0);
            let opportunistic = ps.opportunistic.unwrap_or(false);
            let elements = super::p2p_go::set_noa_in_elements(
                &plan.beacon[36..],
                noa_index,
                ctwindow,
                opportunistic,
            )?;
            let mut beacon = plan.beacon[..36].to_vec();
            beacon.extend_from_slice(&elements);
            if beacon.len() > 2048 {
                return Err("GO native beacon exceeds bounded template");
            }
            // The rewrite may shift element offsets; re-derive TIM.
            let tim = elements_iter(&beacon[36..])?
                .iter()
                .scan(36usize, |off, (id, body)| {
                    let at = *off;
                    *off += 2 + body.len();
                    Some((at, *id))
                })
                .find(|(_, id)| *id == 5)
                .map(|(at, _)| at)
                .ok_or("GO native beacon lost TIM")?;
            plan.beacon = beacon;
            plan.tim = tim;
        }
        plan.go = Some(identity);
        Ok(plan)
    }
    pub fn secure(&self) -> bool {
        self.rsn.is_some()
    }
    pub fn pmf_required(&self) -> bool {
        self.rsn
            .as_ref()
            .is_some_and(|r| r.rsn_capabilities & 0x40 != 0)
    }
    pub fn beacon_command(&self, version: u8) -> Result<Vec<u8>, &'static str> {
        if !matches!(version, 10..=15) {
            return Err("unsupported AP beacon template version");
        }
        let mut body = vec![0; 32 + self.beacon.len()];
        put16(&mut body, 0, self.beacon.len() as u16);
        let rate = self.rates.management_rate(1);
        let code = if rate & 0x100 != 0 {
            rate & 7
        } else {
            (rate & 3) | (1 << 5)
        };
        put16(&mut body, 2, code as u16);
        put32(&mut body, 16, self.tim as u32);
        if version < 14 {
            put32(&mut body, 20, 4); // TIM body length, excluding ID/length.
        }
        body[32..].copy_from_slice(&self.beacon);
        Ok(body)
    }
    pub fn link(&self, own: [u8; 6], active: bool) -> [u8; 208] {
        let mut body = station_api::link_channel(
            2,
            own,
            active,
            self.channel,
            self.config.beacon_interval as u16,
            self.config.dtim_period as u8,
        );
        self.rates.apply(&mut body);
        let caps = u16::from_le_bytes(self.beacon[34..36].try_into().unwrap());
        put32(&mut body, 44, u32::from(caps & (1 << 5) != 0));
        put32(&mut body, 48, u32::from(caps & (1 << 10) != 0));
        body
    }
}

pub(super) fn elements_iter(mut ies: &[u8]) -> Result<Vec<(u8, &[u8])>, &'static str> {
    let mut out = Vec::new();
    while !ies.is_empty() {
        let len = usize::from(*ies.get(1).ok_or("truncated AP IE header")?);
        let body = ies.get(2..2 + len).ok_or("truncated AP IE extent")?;
        out.push((ies[0], body));
        ies = &ies[2 + len..];
    }
    Ok(out)
}
pub(super) fn mac(action: u32, own: [u8; 6], has_peers: bool) -> [u8; 52] {
    let mut body = [0; 52];
    put32(&mut body, 4, action);
    put32(&mut body, 8, 8); // GO means ordinary AP too.
    body[12..18].copy_from_slice(&own);
    put32(&mut body, 20, 2 | 4 | 32 | if has_peers { 8 } else { 0 });
    body
}
pub(super) fn internal(station: u8, kind: u32) -> [u8; 104] {
    let addr = if kind == 1 {
        [0xff; 6]
    } else {
        [3, 0, 0, 0, 0, 0]
    };
    let mut body = station_api::peer(addr);
    put32(&mut body, 0, u32::from(station));
    put32(&mut body, 24, kind);
    put32(&mut body, 36, u32::from(kind == 1));
    body
}
pub(super) fn peer(id: u8, station: &StationConfig) -> Result<[u8; 104], &'static str> {
    if id < FIRST_PEER
        || usize::from(id - FIRST_PEER) >= MAX_PEERS
        || station.mac == [0; 6]
        || station.mac[0] & 1 != 0
        || !(1..=2007).contains(&station.aid)
        || station.listen_interval == 0
        || station.ht_capability.is_some()
        || station.vht_capability.is_some()
        || station.he_capability.is_some()
        || station.he_6ghz_capability.is_some()
        || station.station_tx_power.is_some()
        || station.uapsd_queues.is_some_and(|q| q & !15 != 0)
        || station.uapsd_max_sp.is_some_and(|sp| sp > 3)
    {
        return Err("AP peer has no admitted native identity/PHY contract");
    }
    let mut body = station_api::peer(station.mac);
    put32(&mut body, 0, u32::from(id));
    put32(&mut body, 28, u32::from(station.aid));
    put32(
        &mut body,
        36,
        u32::from(station.mfp.unwrap_or(false) || station.authorized != Some(true)),
    );
    let sp = station.uapsd_max_sp.unwrap_or(0);
    put32(&mut body, 64, if sp == 0 { 128 } else { u32::from(sp) * 2 });
    let requested = station.uapsd_queues.unwrap_or(0);
    // WMM QoS-info VO/VI/BK/BE bits -> native BK/BE/VI/VO ACs.
    let ac = ((requested >> 2) & 1)
        | ((requested >> 2) & 2)
        | ((requested << 1) & 4)
        | ((requested << 3) & 8);
    put32(&mut body, 68, u32::from(ac | (ac << 4)));
    Ok(body)
}

/// IEEE ToDS/FromDS physical identity, before cipher/PN ownership.
pub(super) fn ethernet_from_ap(
    own: [u8; 6],
    sequence: u16,
    ethernet: &[u8],
    protected: bool,
) -> Option<Vec<u8>> {
    if !(14..=1514).contains(&ethernet.len()) || ethernet[6] & 1 != 0 || ethernet[6..12] == [0; 6] {
        return None;
    }
    let mut frame = vec![0; 24];
    frame[0] = 8;
    frame[1] = 2 | if protected { 0x40 } else { 0 };
    frame[4..10].copy_from_slice(&ethernet[..6]);
    frame[10..16].copy_from_slice(&own);
    frame[16..22].copy_from_slice(&ethernet[6..12]);
    put16(&mut frame, 22, (sequence & 4095) << 4);
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend_from_slice(&ethernet[12..]);
    Some(frame)
}

pub(super) fn ethernet_qos_from_ap(
    own: [u8; 6],
    sequence: u16,
    ethernet: &[u8],
    protected: bool,
    tid: Option<u8>,
) -> Option<(Vec<u8>, usize)> {
    let mut frame = ethernet_from_ap(own, sequence, ethernet, protected)?;
    if let Some(tid) = tid {
        if tid >= 8 {
            return None;
        }
        frame[0] = 0x88;
        frame.splice(24..24, [tid, 0]);
        Some((frame, 26))
    } else {
        Some((frame, 24))
    }
}
