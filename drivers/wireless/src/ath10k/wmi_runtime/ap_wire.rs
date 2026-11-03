// SPDX-License-Identifier: GPL-2.0-or-later
//! TLV AP codecs. A submitted command is neither installed state nor air ACK.
//! Linux7.2 wmi-tlv.c and mac.c; legacy20, RAW/nohwcrypt, one real AP vdev.
use super::{wire, Error};
use alloc::vec::Vec;
use narf_wireless::{ApConfig, ApStartSettings, StationConfig};

pub(super) const MAX_PEERS: usize = 8;
const RATES: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];

pub(super) fn elements(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let length = usize::from(*bytes.get(1).ok_or(Error::Malformed)?);
        let body = bytes.get(2..2 + length).ok_or(Error::Malformed)?;
        out.try_reserve(1).map_err(|_| Error::NoMemory)?;
        out.push((bytes[0], body));
        bytes = &bytes[2 + length..];
    }
    Ok(out)
}
fn rates(bytes: &[u8], frequency: u16) -> Result<(u16, u16), Error> {
    let mut supported = 0;
    let mut basic = 0;
    for byte in bytes {
        let bit = RATES
            .iter()
            .position(|rate| *rate == byte & 127)
            .ok_or(Error::Unsupported)?;
        if frequency > 3000 && bit < 4 || supported & (1 << bit) != 0 {
            return Err(Error::Malformed);
        }
        supported |= 1 << bit;
        if byte & 128 != 0 {
            basic |= 1 << bit;
        }
    }
    if supported == 0 {
        return Err(Error::Malformed);
    }
    Ok((supported, basic))
}
pub(super) struct Plan {
    pub config: ApConfig,
    pub settings: ApStartSettings,
    pub beacon: Vec<u8>,
    pub tim: usize,
    pub rates: u16,
    pub basic: u16,
    pub qos: bool,
    pub wmm: Option<narf_wireless::wmm::Parameters>,
    pub rsn: Option<narf_wireless::rsn::RsnIe>,
    pub probe: Vec<u8>,
    /// The AP-type vdev every template, parameter, peer and VDEV_UP command
    /// of this plan addresses (`arvif->vdev_id` throughout mac.c).
    pub vdev: u8,
    /// The vdev's role: `Ap`, or `P2pGo` for a GO's AP-type vdev with
    /// subtype P2P_GO (`arvif->vdev_subtype`), whose beacon P2P IE moves
    /// to firmware (`templates`).
    pub role: super::p2p::Role,
}
impl Plan {
    pub fn new(
        vdev: u8,
        config: ApConfig,
        settings: ApStartSettings,
        own: [u8; 6],
        uapsd: bool,
    ) -> Result<Self, Error> {
        Self::new_role(vdev, super::p2p::Role::Ap, config, settings, own, uapsd)
    }
    /// A plan for an AP-type vdev of `role` (`Ap` or `P2pGo`). Only a GO's
    /// templates may carry the WFA P2P IE (wpa_supplicant's GO beacon and
    /// Probe Response); `templates` hands the beacon's to firmware.
    pub fn new_role(
        vdev: u8,
        role: super::p2p::Role,
        config: ApConfig,
        settings: ApStartSettings,
        own: [u8; 6],
        uapsd: bool,
    ) -> Result<Self, Error> {
        if !matches!(role, super::p2p::Role::Ap | super::p2p::Role::P2pGo) {
            return Err(Error::Unsupported);
        }
        let go = role == super::p2p::Role::P2pGo;
        let frequency = u16::try_from(config.frequency_mhz).map_err(|_| Error::Unsupported)?;
        if !crate::ath10k::regulatory::Permission::profile_frequency(frequency)
            || settings.p2p_go.is_some()
            || config
                .beacon_head
                .len()
                .checked_add(config.beacon_tail.len())
                .is_none_or(|n| n > 2042)
            || !matches!(config.channel_width, 0 | 1)
            || config
                .center_freq1_mhz
                .is_some_and(|f| f != config.frequency_mhz)
            || config.center_freq2_mhz.is_some()
            || config.ssid.is_empty()
            || config.ssid.len() > 32
            || !(10..=65535).contains(&config.beacon_interval)
            || !(1..=255).contains(&config.dtim_period)
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
        {
            return Err(Error::Unsupported);
        }
        let mut beacon = config.beacon_head.clone();
        if !(36..=2048).contains(&beacon.len())
            || beacon[0] != 0x80
            || beacon[1] != 0
            || beacon[4..10] != [0xff; 6]
            || beacon[10..16] != own
            || beacon[16..22] != own
            || beacon[22] & 15 != 0
        {
            return Err(Error::Malformed);
        }
        let capability = u16::from_le_bytes([beacon[34], beacon[35]]);
        if capability & 3 != 1
            || (capability & 16 != 0) != config.privacy
            || u16::from_le_bytes([beacon[32], beacon[33]]) != config.beacon_interval as u16
        {
            return Err(Error::Malformed);
        }
        let mut ies = beacon[36..].to_vec();
        ies.extend_from_slice(&config.beacon_tail);
        let mut ssid = None;
        let mut rsn = None;
        let mut legacy = Vec::new();
        let mut seen = [false; 2];
        let mut qos = false;
        let channel = if frequency < 3000 {
            (frequency - 2407) / 5
        } else {
            (frequency - 5000) / 5
        };
        for (id, body) in elements(&ies)? {
            match id {
                0 => {
                    if ssid.replace(body).is_some() {
                        return Err(Error::Malformed);
                    }
                }
                1 | 50 => {
                    let i = usize::from(id == 50);
                    if seen[i] || body.is_empty() || id == 1 && body.len() > 8 {
                        return Err(Error::Malformed);
                    }
                    seen[i] = true;
                    legacy.extend_from_slice(body);
                }
                3 => {
                    if body != [channel as u8] {
                        return Err(Error::Malformed);
                    }
                }
                48 => {
                    if rsn.is_some() {
                        return Err(Error::Malformed);
                    }
                    rsn =
                        Some(narf_wireless::rsn::RsnIe::decode_body(body).ok_or(Error::Malformed)?);
                }
                // TIM belongs to firmware; no optional PHY/MLD/Country/CSA
                // assertion is silently accepted by this actual20 owner.
                5 | 7 | 37 | 45 | 61 | 191 | 192 | 244 | 255 => return Err(Error::Unsupported),
                42 if body != [0] => return Err(Error::Unsupported),
                221 if body.starts_with(&[0, 0x50, 0xf2, 1])
                    || !go && body.starts_with(&[0x50, 0x6f, 0x9a, 9]) =>
                {
                    return Err(Error::Unsupported)
                }
                221 if body.starts_with(&[0, 0x50, 0xf2, 2]) => {
                    if qos || body.len() != 24 || body.get(4) != Some(&1) {
                        return Err(Error::Unsupported);
                    }
                    qos = true;
                }
                _ => {}
            }
        }
        let wmm = narf_wireless::wmm::Parameters::parse(&ies).map_err(|_| Error::Malformed)?;
        if wmm.is_some() != qos
            || wmm.is_some_and(|wmm| {
                wmm.uapsd && !uapsd || wmm.ac.iter().any(|ac| ac.admission_control)
            })
        {
            return Err(Error::Unsupported);
        }
        let ssid = ssid.ok_or(Error::Malformed)?;
        let valid_ssid = match config.hidden_ssid {
            0 => ssid == config.ssid,
            1 => ssid.is_empty(),
            _ => ssid.len() == config.ssid.len() && ssid.iter().all(|b| *b == 0),
        };
        let (supported, basic) = rates(&legacy, frequency)?;
        if !valid_ssid || !seen[0] || basic == 0 || config.privacy != rsn.is_some() {
            return Err(Error::Malformed);
        }
        if let Some(rsn) = &rsn {
            use narf_wireless::rsn::*;
            if rsn.group_cipher != Suite::standard(CIPHER_CCMP_128)
                || rsn.pairwise_ciphers != [Suite::standard(CIPHER_CCMP_128)]
                || rsn.akms.is_empty()
                || rsn
                    .akms
                    .iter()
                    .any(|a| a.oui != RSN_OUI || !matches!(a.suite_type, 1 | 2 | 6))
                || rsn.rsn_capabilities & 0xc0 != 0
                || rsn.group_management_cipher.is_some()
                || settings.wpa_versions.is_some_and(|v| v != 2)
                || settings
                    .group_cipher
                    .is_some_and(|v| v != narf_wireless::CIPHER_SUITE_CCMP)
                || settings
                    .pairwise_ciphers
                    .as_ref()
                    .is_some_and(|v| v.as_slice() != [narf_wireless::CIPHER_SUITE_CCMP])
                || settings.akms.as_ref().is_some_and(|v| {
                    v.len() != rsn.akms.len()
                        || v.iter().any(|v| {
                            !rsn.akms
                                .iter()
                                .any(|s| *v == 0xfac00 | u32::from(s.suite_type))
                        })
                })
            {
                return Err(Error::Unsupported);
            }
        } else if settings.wpa_versions.is_some()
            || settings.group_cipher.is_some()
            || settings.pairwise_ciphers.is_some()
            || settings.akms.is_some()
        {
            return Err(Error::Malformed);
        }
        if settings.auth_type.is_some_and(|a| a != 0)
            || settings.control_port.enabled
                && (!settings.control_port.over_nl80211
                    || settings.control_port.ethertype != 0x888e)
            || config.privacy && !settings.control_port.enabled
        {
            return Err(Error::Unsupported);
        }
        let probe = if let Some(probe) = &config.probe_resp {
            if !(36..=2048).contains(&probe.len())
                || probe[0] != 0x50
                || probe[1] != 0
                || probe[10..16] != own
                || probe[16..22] != own
                || probe[22] & 15 != 0
                || probe[34..36] != beacon[34..36]
            {
                return Err(Error::Malformed);
            }
            // Validate the same complete IE/security/PHY contract once. The
            // recursive value has no supplied probe, so nesting is bounded.
            let mut candidate = config.clone();
            candidate.probe_resp = None;
            candidate.hidden_ssid = 0;
            candidate.beacon_head = probe.clone();
            candidate.beacon_head[0] = 0x80;
            candidate.beacon_head[4..10].fill(0xff);
            candidate.beacon_tail.clear();
            let parsed = Self::new_role(vdev, role, candidate, settings.clone(), own, uapsd)?;
            if parsed.rsn != rsn
                || parsed.rates != supported
                || parsed.basic != basic
                || parsed.wmm != wmm
            {
                return Err(Error::Malformed);
            }
            let mut probe = probe.clone();
            probe[24..32].fill(0);
            probe[32..34].copy_from_slice(&(config.beacon_interval as u16).to_le_bytes());
            probe
        } else {
            let mut probe = beacon[..36].to_vec();
            probe[0] = 0x50;
            probe[4..10].fill(0);
            probe[24..32].fill(0);
            probe[32..34].copy_from_slice(&(config.beacon_interval as u16).to_le_bytes());
            for (id, body) in elements(&ies)? {
                let body = if id == 0 { &config.ssid[..] } else { body };
                probe.push(id);
                probe.push(body.len() as u8);
                probe.extend_from_slice(body);
            }
            if probe.len() > 2048 {
                return Err(Error::Unsupported);
            }
            probe
        };
        beacon[24..32].fill(0);
        beacon[32..34].copy_from_slice(&(config.beacon_interval as u16).to_le_bytes());
        let tim = beacon.len();
        beacon.extend_from_slice(&[5, 4, 0, config.dtim_period as u8, 0, 0]);
        beacon.extend_from_slice(&config.beacon_tail);
        if beacon.len() > 2048 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            role,
            config,
            settings,
            beacon,
            tim,
            rates: supported,
            basic,
            qos,
            wmm,
            rsn,
            probe,
            vdev,
        })
    }
    pub fn peer_rates(&self, station: &StationConfig) -> Result<u16, Error> {
        if !unicast(station.mac)
            || !(1..=2007).contains(&station.aid)
            || station.listen_interval == 0
            || station.ht_capability.is_some()
            || station.vht_capability.is_some()
            || station.he_capability.is_some()
            || station.he_6ghz_capability.is_some()
            || station.station_tx_power.is_some()
            || station.mfp == Some(true)
            || station.uapsd_queues.is_some_and(|v| v & !15 != 0)
            || station.uapsd_max_sp.is_some_and(|v| v > 3)
            || station.uapsd_queues.is_some_and(|v| v != 0) && station.wme != Some(true)
            || station.uapsd_queues.is_some_and(|v| v != 0) && self.wmm.is_none_or(|wmm| !wmm.uapsd)
            || !self.qos
                && (station.wme == Some(true) || station.uapsd_queues.is_some_and(|v| v != 0))
        {
            return Err(Error::Unsupported);
        }
        let (supported, _) = rates(&station.supported_rates, self.config.frequency_mhz as u16)?;
        if supported & self.basic != self.basic || supported & !self.rates != 0 {
            return Err(Error::Unsupported);
        }
        // hostapd's non-ERP classification on11g: no supported rate above
        // 11Mbps. Such a client triggers ERP/CTS protection, which this bounded
        // owner does not advertise or implement. Reject before any peer/port,
        // command, PN or DMA change; pure11b and5GHz keep their real profiles.
        if self.config.frequency_mhz < 3000
            && self.rates & !15 != 0
            && !station.supported_rates.iter().any(|rate| rate & 127 > 22)
        {
            return Err(Error::Unsupported);
        }
        // A short-slot/preamble beacon also cannot silently admit a client
        // lacking those facts and wait for unsupported SME protection changes.
        let capability = u16::from_le_bytes([self.beacon[34], self.beacon[35]]);
        if self.config.frequency_mhz < 3000
            && capability & ((1 << 5) | (1 << 10)) & !station.capability.unwrap_or(0) != 0
        {
            return Err(Error::Unsupported);
        }
        Ok(supported)
    }
}
/// rx_desc.h L-SIG codes, before any replay/MIC state is touched.
pub(super) fn legacy_rate(info: u32, frequency: u16) -> Option<(usize, u8)> {
    if info >> 24 != 4 {
        return None;
    }
    let code = info & 15;
    let index = if info & 16 != 0 {
        if frequency > 3000 {
            return None;
        }
        match code {
            8 | 12 => 3,
            9 | 13 => 2,
            10 | 14 => 1,
            11 => 0,
            _ => return None,
        }
    } else {
        match code {
            8 => 10,
            9 => 8,
            10 => 6,
            11 => 4,
            12 => 11,
            13 => 9,
            14 => 7,
            15 => 5,
            _ => return None,
        }
    };
    Some((index, RATES[index]))
}
pub(super) fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
pub(super) fn command(id: u32, tag: u32, values: &[u32]) -> Result<Vec<u8>, Error> {
    let mut bytes = wire::packet(id, 4 + values.len() * 4)?;
    wire::put(&mut bytes, 4, tag << 16 | (values.len() * 4) as u32);
    for (i, value) in values.iter().enumerate() {
        wire::put(&mut bytes, 8 + i * 4, *value);
    }
    Ok(bytes)
}
/// A TLV AP-type vdev (VDEV_TYPE_AP; subtype NONE, or P2P_GO for a GO).
pub(super) fn create(vdev: super::p2p::Vdev, own: [u8; 6]) -> Result<Vec<u8>, Error> {
    if vdev.role().vdev_type() != 1 {
        return Err(Error::Unsupported);
    }
    let tlv = wire::Wire::new(crate::ath10k::wmi_boot::Dialect::Tlv);
    vdev.create(&tlv, own)
}
/// TLV `WMI_VDEV_DELETE_CMDID` for the AP-owned vdev.
pub(super) fn delete(vdev: super::p2p::Vdev) -> Result<Vec<u8>, Error> {
    vdev.delete(&wire::Wire::new(crate::ath10k::wmi_boot::Dialect::Tlv))
}
pub(super) fn beacon(plan: &Plan) -> Result<Vec<u8>, Error> {
    beacon_template(plan.vdev, plan.tim, &plan.beacon)
}
fn beacon_template(vdev: u8, tim: usize, frame: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = command(
        0x7003,
        103,
        &[u32::from(vdev), tim as u32, frame.len() as u32],
    )?;
    out.extend_from_slice(&((105u32 << 16) | 8).to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    let padded = frame.len().next_multiple_of(4);
    out.extend_from_slice(&((17u32 << 16) | padded as u32).to_le_bytes());
    out.extend_from_slice(frame);
    out.resize(out.len() + padded - frame.len(), 0);
    Ok(out)
}
/// The template commands one beacon publication sends, in
/// `mac.c::ath10k_mac_setup_bcn_tmpl` order: for a GO the
/// `WMI_TLV_P2P_GO_SET_BEACON_IE` (`ath10k_mac_setup_bcn_p2p_ie`) first,
/// then the beacon template without that P2P IE
/// (`ath10k_mac_remove_vendor_ie`), then the probe-response template
/// (`ath10k_mac_setup_prb_tmpl`, unchanged: firmware adds no NoA there and
/// neither does Linux).
pub(super) fn templates(plan: &Plan) -> Result<Vec<Vec<u8>>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(3).map_err(|_| Error::NoMemory)?;
    let vdev = super::p2p::Vdev::new(plan.vdev, plan.role);
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(plan.beacon.len())
        .map_err(|_| Error::NoMemory)?;
    frame.extend_from_slice(&plan.beacon);
    let mut tim = plan.tim;
    if let Some(ie) = super::p2p::go_beacon_ie(vdev, &mut frame)? {
        // The TIM sits between head and tail; a P2P IE in the head precedes
        // it and moves the offset firmware patches.
        let elements = plan
            .beacon
            .get(super::p2p::BEACON_IES..)
            .ok_or(Error::Malformed)?;
        let range = super::p2p::find_p2p_ie(elements)?.ok_or(Error::Malformed)?;
        if super::p2p::BEACON_IES + range.start < tim {
            tim -= range.len();
        }
        out.push(ie);
    }
    out.push(beacon_template(plan.vdev, tim, &frame)?);
    out.push(probe(plan)?);
    Ok(out)
}
pub(super) fn probe(plan: &Plan) -> Result<Vec<u8>, Error> {
    let mut out = command(
        0x7007,
        104,
        &[u32::from(plan.vdev), plan.probe.len() as u32],
    )?;
    out.extend_from_slice(&((105u32 << 16) | 8).to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    let padded = plan.probe.len().next_multiple_of(4);
    out.extend_from_slice(&((17u32 << 16) | padded as u32).to_le_bytes());
    out.extend_from_slice(&plan.probe);
    out.resize(out.len() + padded - plan.probe.len(), 0);
    Ok(out)
}
/// Linux mac.c basic-management/multicast rate and actual legacy AP vdev
/// controls. Default firmware forwarding cannot bypass the host port/CCMP.
pub(super) fn parameters(plan: &Plan) -> Result<Vec<Vec<u8>>, Error> {
    let index = plan.basic.trailing_zeros() as usize;
    let rate = *[0x43u32, 0x42, 0x41, 0x40, 3, 7, 2, 6, 1, 5, 0, 4]
        .get(index)
        .ok_or(Error::Malformed)?;
    let capability = u16::from_le_bytes([plan.beacon[34], plan.beacon[35]]);
    let mut out = Vec::new();
    out.try_reserve_exact(9).map_err(|_| Error::NoMemory)?;
    for (parameter, value) in [
        (25, rate),
        (35, rate),
        (36, rate),
        (32, 0),
        (34, 1),
        (21, 0),
        (20, u32::from(plan.qos)),
        (7, if capability & (1 << 10) != 0 { 2 } else { 1 }),
        (8, if capability & (1 << 5) != 0 { 2 } else { 1 }),
    ] {
        out.push(command(
            0x5008,
            95,
            &[u32::from(plan.vdev), parameter, value],
        )?);
    }
    Ok(out)
}
/// TLV `WMI_PEER_SET_PARAM` for `mac` on the AP `vdev`.
pub(super) fn peer_parameter(
    vdev: u8,
    mac: [u8; 6],
    id: u32,
    value: u32,
) -> Result<Vec<u8>, Error> {
    let mut out = command(0x6004, 100, &[u32::from(vdev), 0, 0, id, value])?;
    out[12..18].copy_from_slice(&mac);
    Ok(out)
}
/// TLV `WMI_AP_PS_PEER_PARAM` for `mac` on the AP `vdev`.
pub(super) fn power_save(
    vdev: u8,
    mac: [u8; 6],
    queues: u8,
    max_sp: u8,
) -> Result<[Vec<u8>; 3], Error> {
    if queues & !15 != 0 || max_sp > 3 {
        return Err(Error::Malformed);
    }
    let mut ac = 0u32;
    // WMM QoS info order VO/VI/BK/BE maps native BE/BK/VI/VO.
    for (bit, native) in [(0, 3), (1, 2), (2, 1), (3, 0)] {
        if queues & (1 << bit) != 0 {
            ac |= 3 << (native * 2);
        }
    }
    let make = |id, value| {
        let mut out = command(0xe001, 130, &[u32::from(vdev), 0, 0, id, value])?;
        out[12..18].copy_from_slice(&mac);
        Ok::<_, Error>(out)
    };
    Ok([make(0, ac)?, make(1, u32::from(max_sp))?, make(2, 10)?])
}
pub(super) fn associate(
    plan: &Plan,
    station: &StationConfig,
    reassociate: bool,
) -> Result<Vec<u8>, Error> {
    let mask = plan.peer_rates(station)?;
    let rates: Vec<u8> = RATES
        .iter()
        .enumerate()
        .filter_map(|(i, rate)| (mask & (1 << i) != 0).then_some(*rate))
        .collect();
    let padded = rates.len().next_multiple_of(4);
    let mut out = wire::packet(0x6005, 76 + 16 + 16 + padded)?;
    wire::put(&mut out, 4, 101 << 16 | 76);
    out[8..14].copy_from_slice(&station.mac);
    wire::put(&mut out, 16, u32::from(plan.vdev));
    wire::put(&mut out, 20, u32::from(!reassociate));
    wire::put(&mut out, 24, u32::from(station.aid));
    let uapsd = station.wme == Some(true) && station.uapsd_queues.is_some_and(|q| q != 0);
    // AP flags have their actual userspace-SME meaning. Software nohwcrypt
    // does not borrow the STA scan-cache NEED_PTK/NEED_GTK handshake flags.
    wire::put(
        &mut out,
        28,
        1 | u32::from(station.wme == Some(true)) << 1 | u32::from(uapsd) << 11,
    );
    wire::put(&mut out, 32, u32::from(station.capability.unwrap_or(0)));
    wire::put(&mut out, 36, u32::from(station.listen_interval));
    wire::put(&mut out, 52, if uapsd { 0x400 } else { 0 });
    wire::put(&mut out, 56, 1);
    wire::put(
        &mut out,
        64,
        if plan.config.frequency_mhz > 3000 {
            0
        } else if mask & !15 != 0 {
            1
        } else {
            2
        },
    );
    wire::put(&mut out, 76, rates.len() as u32);
    wire::put(&mut out, 84, 17 << 16 | padded as u32);
    out[88..88 + rates.len()].copy_from_slice(&rates);
    wire::put(&mut out, 88 + padded, 17 << 16);
    wire::put(&mut out, 92 + padded, 102 << 16 | 16);
    Ok(out)
}
pub(super) fn echo(sequence: u32) -> Result<Vec<u8>, Error> {
    command(0x1d001, 149, &[sequence])
}
pub(super) fn echo_received(bytes: &[u8], sequence: u32) -> Result<bool, Error> {
    if wire::word(bytes, 0)? & 0xffffff != 0x1d001 {
        return Ok(false);
    }
    let body = wire::tag(&bytes[4..], 54)?;
    Ok(body.len() == 4 && wire::word(body, 0)? == sequence)
}
