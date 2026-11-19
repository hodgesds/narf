//! Further affiliated links of a native multiple-link association. Linux
//! mac80211 mlme.c `ieee80211_mgd_assoc`/`ieee80211_assoc_success` makes
//! every accepted link *valid* but keeps only the association link
//! *active* (link.c `ieee80211_vif_set_links`); iwl mld later activates a
//! further link through `_ieee80211_set_active_links`. Each accepted link
//! keeps its own beacon, negotiated PHY/HE/EHT, rates, QoS, power limit and
//! MLO group keys here, so its PHY/LINK/STA/TLC bodies are built only from
//! that link's own facts — never copied from the association link.
use super::{
    boot_context::put32,
    connection::{channel_power_width, Beacon},
    native_band::Channel,
    runtime::Hardware,
    sc_mlo::{FurtherLink, LinkKey, LinkOwner},
    station_api,
};
use alloc::sync::Arc;
use narf_wireless::association::{mlo::Context, MldLink};

/// One further link the caller asks to request: another affiliated AP of
/// the same AP MLD, by its actual received beacon, and the local link
/// address this station uses on it.
#[derive(Clone, Debug)]
pub struct MldLinkCandidate {
    pub beacon: Beacon,
    pub own_link: [u8; 6],
}

/// Further-link candidates for a fresh station association, taken from
/// the driver's own scan table. This is the device-side counterpart of
/// userspace naming `NL80211_ATTR_MLO_LINKS`: every other affiliated AP of
/// the association BSS's AP MLD whose own beacon was received in the most
/// recent scan (`fresh`; iwl mld `iwl_mld_set_link_sel_data` ignores any
/// BSS not seen in the last MLO scan). Each entry must pass cfg80211
/// `cfg80211_mlme_check_mlo`/`_compat` against the association link: a
/// Basic MLE with a link id, the same AP MLD address, EML capabilities and
/// MLD capabilities/operations, and a BSSID that is not our address. One
/// entry per link id, ascending; the association link id is excluded. Each
/// link gets a fresh random local link address (mlme.c
/// `ieee80211_mgd_assoc` `eth_random_addr` for a link without one), never
/// equal to the MLD address, another link address or any AP address.
pub(super) fn scan_candidates(
    assoc: &Beacon,
    scanned: &[Beacon],
    fresh: impl Fn(&Beacon) -> bool,
    local: [u8; 6],
    mut random: impl FnMut() -> Result<[u8; 6], &'static str>,
) -> Result<alloc::vec::Vec<MldLinkCandidate>, &'static str> {
    use narf_wireless::association::mlo::BasicMultiLink;
    let mut found = alloc::vec::Vec::new();
    let Ok(ours) = BasicMultiLink::from_ies(&assoc.information_elements) else {
        return Ok(found);
    };
    let Some(assoc_link) = ours.link_id() else {
        return Ok(found);
    };
    let mut seen = 1u16 << assoc_link;
    let mut links: alloc::vec::Vec<(u8, &Beacon)> = alloc::vec::Vec::new();
    for beacon in scanned {
        if beacon.bssid == assoc.bssid || beacon.bssid == local || !fresh(beacon) {
            continue;
        }
        let Ok(theirs) = BasicMultiLink::from_ies(&beacon.information_elements) else {
            continue;
        };
        let Some(link) = theirs.link_id() else {
            continue;
        };
        if link >= 15
            || seen & (1 << link) != 0
            || theirs.address() != ours.address()
            || theirs.eml_capabilities() != ours.eml_capabilities()
            || theirs.mld_capabilities() != ours.mld_capabilities()
        {
            continue;
        }
        seen |= 1 << link;
        links.push((link, beacon));
    }
    links.sort_unstable_by_key(|(link, _)| *link);
    for (_, beacon) in links {
        let own_link = (0..8)
            .find_map(|_| {
                let mut address = random().ok()?;
                // eth_random_addr: unicast, locally administered.
                address[0] = (address[0] & 0xfe) | 0x02;
                let clash = address == local
                    || address == ours.address()
                    || address == [0; 6]
                    || scanned.iter().any(|b| b.bssid == address)
                    || found
                        .iter()
                        .any(|c: &MldLinkCandidate| c.own_link == address);
                (!clash).then_some(address)
            })
            .ok_or("no random local MLD link address")?;
        found.push(MldLinkCandidate {
            beacon: beacon.clone(),
            own_link,
        });
    }
    Ok(found)
}

/// The association link's final native PHY_CONTEXT, LINK_CONFIG,
/// STA_CONFIG and TLC bodies (as sent after the association response),
/// retained so a primary-link switch can deactivate the association link
/// and later restore it with the same facts and its fixed FWlink0/STA0/PHY0
/// identity (mac80211 re-adding it to `active_links`).
#[derive(Clone, Copy)]
pub(super) struct AssociationBodies {
    pub phy: [u8; 32],
    pub link: [u8; 208],
    pub peer: [u8; 104],
    pub tlc: [u8; 44],
}

/// A further link the AP accepted (a valid, initially inactive link).
pub(super) struct ValidLink {
    pub context: Context,
    pub beacon: Beacon,
    aid: u16,
    tx_chains: u32,
    pmf: bool,
    phy: super::ht_vht::Negotiated,
    he: Option<super::sc_he::Profile>,
    eht: Option<Arc<super::sc_eht::Profile>>,
    rates: super::rates::Rates,
    qos: Option<super::qos::Parameters>,
    max_power: i8,
    /// This link's MLO GTK/IGTK from the latest authenticated delivery.
    pub keys: Option<super::security::LinkGroupKeys>,
    /// This link's own group RX PN floors (`rx->link->gtk[idx]` rx_pn).
    pub group_replay: super::frame_api::GroupReplay,
    /// This link's own IGTK and BIP replay floor (`rx->link` IGTK in
    /// mac80211 rx.c `ieee80211_rx_h_decrypt` for group management).
    pub mfp: narf_wireless::mfp::MfpKeyStore,
    /// Firmware ownership (link/STA ids and PHY id) while active.
    pub active: Option<(LinkOwner, u8)>,
}

/// The native per-link facts a further-link candidate must have before it
/// is requested: the same admission the association link performs, from
/// that link's own beacon on its own channel.
pub(super) struct Admission<'a> {
    pub domain: &'a narf_wireless::reg::RegulatoryDomain,
    pub permissions: &'a super::mld_regulatory::Mcc,
    pub local: super::ht_vht::Local,
}
impl Admission<'_> {
    /// The native local PHY for `beacon`'s channel: 160MHz only where this
    /// channel has a permitted 160MHz span, as for the association link.
    /// 6GHz further links are not admitted by this native path.
    pub fn local_for(&self, beacon: &Beacon) -> Option<super::ht_vht::Local> {
        if beacon.band == super::native_band::Band::Six || beacon.channel == 0 {
            return None;
        }
        let mut local = self.local;
        if !self.permissions.widths.permits(3)
            || ![50, 114, 163].into_iter().any(|center| {
                local.permits160(center)
                    && channel_power_width(
                        self.domain,
                        beacon.channel,
                        3,
                        center,
                        &self.permissions.channels,
                    )
                    .is_some()
            })
        {
            local.width160_channels = 0;
        }
        Some(local)
    }

    /// Build an accepted link's own native facts: beacon PHY admission
    /// with that link's shared offer, then the per-STA response view
    /// (`MldLink::response_elements`, inherited as mlme.c
    /// `ieee80211_assoc_config_link`) confirming PHY/HE/EHT and WMM, the
    /// final span's host/firmware power and the AP's own power limit.
    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        &self,
        hw: &Hardware,
        beacon: &Beacon,
        link: &MldLink,
        h2e: bool,
        aid: u16,
        tx_chains: u32,
        pmf: bool,
    ) -> Result<ValidLink, &'static str> {
        let local = self
            .local_for(beacon)
            .ok_or("native MLD further link band not admitted")?;
        let ies = &beacon.information_elements;
        let view = link
            .response_elements()
            .ok_or("native MLD further link has no accepted response")?;
        let offer = link
            .offered_phy()
            .ok_or("native MLD further link has no PHY offer")?;
        let (domain, permissions) = (self.domain, self.permissions);
        let channel = beacon.channel;
        super::qos::Parameters::parse(ies)?.ok_or("native MLD further link lacks WMM")?;
        let phy = super::ht_vht::Negotiated::parse_with_offer(
            local,
            ies,
            channel,
            true,
            |width, center| {
                permissions.widths.permits(width)
                    && channel_power_width(domain, channel, width, center, &permissions.channels)
                        .is_some()
            },
            Some((offer, h2e)),
        )?;
        if !super::sc_he::matches_native(offer, &phy) || offer.eht().is_none() {
            return Err("native MLD further link EHT offer differs from native PHY");
        }
        let qos = super::qos::Parameters::parse(view)?;
        let phy = phy.confirm(local, ies, view, channel, true)?;
        let negotiated = offer
            .response_elements_with_sae_h2e(view, h2e)
            .map_err(|_| "native MLD further link response did not confirm the offer")?;
        let he = *negotiated
            .he()
            .ok_or("native MLD further link omitted HE")?;
        let width = match negotiated.width() {
            narf_wireless::association::phy::Width::Twenty => 0,
            narf_wireless::association::phy::Width::Forty => 1,
            narf_wireless::association::phy::Width::Eighty => 2,
            narf_wireless::association::phy::Width::OneSixty => 3,
        };
        if negotiated.center_channel() != phy.center
            || width != phy.width
            || !permissions.widths.permits(phy.width)
        {
            return Err("native MLD further link response differs from its PHY/MCC span");
        }
        let static_smps = (negotiated.ht().peer_capability() >> 2) & 3 == 0;
        let he_profile = super::sc_he::Profile::new(
            he,
            view,
            static_smps,
            super::sc_he::rates_version(hw).ok_or("MLD HE rate ABI changed")?,
        )?;
        let eht = *negotiated
            .eht()
            .ok_or("native MLD further link omitted EHT")?;
        let eht = super::sc_eht::Profile::new(
            eht,
            offer
                .eht()
                .ok_or("native MLD further link EHT offer absent")?,
            &he_profile,
            static_smps,
        )?;
        let qos = permissions
            .limit_qos(domain, channel, phy.width, phy.center, qos)
            .ok_or("native MLD further link response did not confirm WMM")?;
        let host = channel_power_width(
            domain,
            channel,
            phy.width,
            phy.center,
            &permissions.channels,
        )
        .ok_or("native MLD further link span prohibited")?;
        let ap = super::mld_power::ap_limit_in_ies(ies, beacon.capabilities, channel)?;
        let max_power = ap.map_or(host, |limit| i16::from(host).min(limit) as i8);
        let rates = super::rates::Rates::parse_for_native_profiles(
            ies, channel, phy.mode, h2e, true, true,
        )?;
        Ok(ValidLink {
            context: *link.context(),
            beacon: beacon.clone(),
            aid,
            tx_chains,
            pmf,
            phy,
            he: Some(he_profile),
            eht: Some(eht),
            rates,
            qos: Some(qos),
            max_power,
            keys: None,
            group_replay: Default::default(),
            mfp: narf_wireless::mfp::MfpKeyStore::new(),
            active: None,
        })
    }
}

impl ValidLink {
    pub fn link_id(&self) -> u8 {
        self.context.link_id()
    }
    /// This link's negotiated PHY (width/center for link grading).
    pub fn negotiated_phy(&self) -> &super::ht_vht::Negotiated {
        &self.phy
    }
    /// This link's negotiated HE profile (RX rate admission).
    pub fn he(&self) -> Option<super::sc_he::Profile> {
        self.he
    }
    /// This link's negotiated EHT profile (RX rate admission).
    pub fn eht(&self) -> Option<&super::sc_eht::Profile> {
        self.eht.as_deref()
    }
    pub fn channel(&self) -> Channel {
        Channel {
            band: self.beacon.band,
            number: self.beacon.channel,
        }
    }
    /// PHY_CONTEXT, LINK_CONFIG, STA_CONFIG and per-link REDUCE_TX_POWER
    /// bodies from this link's own negotiated facts, built with the same
    /// station_api builders the association link uses. `sc_mlo` applies
    /// the owner identity and action fields.
    pub fn further_link(
        &self,
        hw: &Hardware,
        owner: LinkOwner,
        phy_id: u8,
    ) -> Result<FurtherLink, &'static str> {
        let channel = self.channel();
        let mut phy = station_api::phy_channel(1, channel);
        self.phy.apply_phy(&mut phy, channel.number);
        let mut link = station_api::link_channel(
            2,
            self.context.own_link(),
            true,
            channel,
            self.beacon.interval,
            self.beacon.dtim,
        );
        self.rates.apply(&mut link);
        put32(
            &mut link,
            44,
            u32::from(self.beacon.capabilities & (1 << 5) != 0),
        );
        put32(
            &mut link,
            48,
            u32::from(self.beacon.capabilities & (1 << 10) != 0),
        );
        if let Some(qos) = &self.qos {
            qos.apply(&mut link);
        }
        self.phy.apply_link(&mut link);
        if let Some(he) = self.he {
            he.apply_link(&mut link);
        }
        hw.station_link(&mut link);
        let mut peer = station_api::peer(self.context.peer_link());
        self.phy.apply_peer(&mut peer, self.aid);
        if let Some(he) = self.he {
            he.apply_sta(&mut peer);
        }
        if let Some(eht) = &self.eht {
            eht.apply_sta(&mut peer);
        }
        put32(&mut peer, 36, u32::from(self.pmf));
        // Linux mld/power.c iwl_mld_set_tx_power: SET_LINK mode with the
        // link's FW id; only the v10/v11 MLD layouts carry a link id.
        let version = hw.version(1, 0x9f).ok_or("missing TX power command")?.0;
        if !matches!(version, 10 | 11) {
            return Err("native MLD per-link TX power command absent");
        }
        let mut power = station_api::tx_power(version, self.max_power)?;
        put32(&mut power, 4, u32::from(owner.fw_link));
        Ok(FurtherLink {
            owner,
            phy_id,
            phy,
            link,
            peer,
            power,
        })
    }
    /// Linux mld/tlc.c `iwl_mld_config_tlc_link`: TLC_MNG_CONFIG for the
    /// link STA alone (`sta_mask = BIT(fw_sta_id)`), from this link's own
    /// rates and PHY/HE/EHT.
    pub fn tlc(&self, hw: &Hardware, station: u8) -> Result<[u8; 44], &'static str> {
        let version = hw.version(5, 0xf).ok_or("firmware has no TLC command")?.0;
        let mut tlc = self.rates.tlc(version, self.tx_chains)?;
        self.phy.apply_tlc(&mut tlc);
        if let Some(he) = self.he {
            he.apply_tlc(&mut tlc)?;
        }
        if let Some(eht) = &self.eht {
            eht.apply_tlc(&mut tlc);
        }
        put32(&mut tlc, 0, 1 << station);
        Ok(tlc)
    }
    /// This link's group keys for its link STA only.
    pub fn group_keys(&self) -> alloc::vec::Vec<LinkKey<'_>> {
        let mut keys = alloc::vec::Vec::new();
        if let Some(group) = &self.keys {
            keys.push(LinkKey {
                id: group.group_id,
                key: &group.group,
                rx_pn: group.group_rx_pn,
            });
            if let Some((igtk, id, ipn)) = &group.igtk {
                keys.push(LinkKey {
                    id: *id as u8,
                    key: igtk,
                    rx_pn: *ipn,
                });
            }
        }
        keys
    }
}
