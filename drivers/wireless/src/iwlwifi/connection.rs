//! Station association and controlled-port state for the MLD interface.

use super::{
    boot_context::{put16, put32},
    frame_api, mlme,
    runtime::Hardware,
    scan_api, security, station_api,
};
use alloc::{collections::VecDeque, vec::Vec};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug)]
pub struct Beacon {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub channel: u8,
    pub(super) band: super::native_band::Band,
    pub interval: u16,
    pub dtim: u8,
    pub rsn: Option<Vec<u8>>,
    pub privacy: bool,
    pub capabilities: u16,
    pub information_elements: Vec<u8>,
}

/// RSS selects a physical queue before CCMP/reorder admission. Linux keeps
/// pairwise PN and BA reorder state separately on each such queue; a lower
/// packet number arriving later on another queue must not corrupt that queue.
struct QueueRx {
    replay: frame_api::Replay,
    ba: [Option<super::aggregation::Window>; super::aggregation::MAX_TIDS],
}
impl Default for QueueRx {
    fn default() -> Self {
        Self {
            replay: frame_api::Replay::default(),
            ba: core::array::from_fn(|_| None),
        }
    }
}

pub struct Connection {
    pub beacon: Beacon,
    local: [u8; 6],
    management_queue: u16,
    data_queues: [Option<u16>; 4],
    qos: Option<super::qos::Parameters>,
    sequence: u16,
    security: Option<security::Session>,
    replay: frame_api::Replay,
    extra_rx: Vec<QueueRx>,
    receive_epoch: u64,
    pub authorized: bool,
    pub last_beacon: u64,
    group_keys: [Option<[u8; 16]>; 4],
    pairwise_key: Option<[u8; 16]>,
    tx_antenna: u32,
    rates: super::rates::Rates,
    phy: super::ht_vht::Negotiated,
    local_phy: super::ht_vht::Local,
    regulatory: super::mld_policy::Program,
    ap_power_limit: Option<i16>,
    power_pending: bool,
    power_inflight: bool,
    rx_ba: [Option<super::aggregation::Window>; super::aggregation::MAX_TIDS],
    actions: VecDeque<Vec<u8>>,
    /// 802.11w IGTK store (BIP-CMAC-128), populated from message 3 on
    /// negotiated PSK/SAE PMF. `mfp_active` records actual IGTK adoption.
    mfp: narf_wireless::mfp::MfpKeyStore,
    mfp_active: bool,
    pmf_negotiated: bool,
    management_pn: u64,
    key_history: super::sc_security::KeyHistory,
    he: Option<super::sc_he::Profile>,
    eht: Option<alloc::sync::Arc<super::sc_eht::Profile>>,
    six: Option<alloc::sync::Arc<super::six_ghz_station::Profile>>,
    mld: Option<alloc::sync::Arc<super::sc_mlo::Binding>>,
    /// Accepted further links (valid; at most one also active).
    mld_links: Vec<super::sc_mlo_assoc::ValidLink>,
    /// Requested further links the AP refused: (link id, own link
    /// address, AP link BSSID, per-STA profile status), reported by the
    /// MLO CONNECT event (`cfg80211_connect_resp_params::links[].status`).
    mld_rejected: Vec<(u8, [u8; 6], [u8; 6], u16)>,
    /// The AP MLD's EML capabilities and medium sync delay from the
    /// association response Basic MLE (mlme.c `vif->cfg.eml_cap`).
    ap_eml: Option<narf_wireless::association::mlo::EmlCapabilities>,
    ap_med_sync: Option<u16>,
    /// EMLSR decision state (mld/mlo.c) and a pending active-link set
    /// (`ieee80211_set_active_links_async`) applied by maintenance.
    emlsr: super::sc_emlsr::Emlsr,
    /// Internal MLO scan, measurements and link-selection triggers.
    mlo_select: super::sc_emlsr::Selector,
    active_request: Option<u16>,
    /// The association link's final PHY/LINK/STA/TLC bodies, retained so a
    /// primary-link switch can deactivate and later restore it.
    mld_association: Option<super::sc_mlo_assoc::AssociationBodies>,
    /// Advertised TID-to-link mapping and dormant links (mlme.c).
    ttlm: super::sc_emlsr::TtlmState,
    client: Option<alloc::sync::Arc<super::p2p_client::Native>>,
    mld_eapol: VecDeque<(u64, [u8; 32])>,
    tx_amsdu: super::sc_tx_amsdu::Limits,
    amsdu_memory: Option<super::Gen2SharedMemory>,
    amsdu_memory_attempted: bool,
    tlc_notification_version: Option<u8>,
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection")
            .field("authorized", &self.authorized)
            .finish_non_exhaustive()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(key) = &mut self.pairwise_key {
            key.zeroize();
        }
        for key in self.group_keys.iter_mut().flatten() {
            key.zeroize();
        }
        for key in [&mut self.mfp.active, &mut self.mfp.next]
            .into_iter()
            .flatten()
        {
            key.key.zeroize();
        }
    }
}

/// Authentication / key-management the station drives for this
/// association. WPA2-PSK supplies a 32-byte PMK directly; WPA3-SAE
/// supplies the password and derives the PMK via the SAE exchange.
pub enum AuthMethod {
    Open,
    Wpa2Psk([u8; 32]),
    Wpa3Sae { password: Vec<u8> },
}

impl core::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the PMK / password.
        let kind = match self {
            AuthMethod::Open => "Open",
            AuthMethod::Wpa2Psk(_) => "Wpa2Psk",
            AuthMethod::Wpa3Sae { .. } => "Wpa3Sae",
        };
        f.debug_struct("AuthMethod").field("kind", &kind).finish()
    }
}

impl Connection {
    fn admits_channel(&self, mpdu: &scan_api::Mpdu<'_>) -> bool {
        let received = super::native_band::Channel::received(mpdu.channel, mpdu.raw_band, true);
        if let Some(mld) = &self.mld {
            // Each active owner admits its own channel (iwl mld resolves
            // the receiving link from the firmware link id).
            return received.is_some() && mld.owner_channel(mpdu) == received;
        }
        received
            == Some(super::native_band::Channel {
                band: self.beacon.band,
                number: self.beacon.channel,
            })
    }
    /// The accepted further link that received `mpdu`, or None for the
    /// association link (whose facts live in this connection).
    fn receiving_further(
        &self,
        mpdu: &scan_api::Mpdu<'_>,
    ) -> Option<&super::sc_mlo_assoc::ValidLink> {
        let mld = self.mld.as_ref()?;
        let link = mld.receiving_link(mpdu)?;
        if link == mld.association().spec_link {
            return None;
        }
        self.mld_links.iter().find(|valid| valid.link_id() == link)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn open_model() -> Self {
        Self {
            beacon: Beacon {
                bssid: [4; 6],
                ssid: Vec::new(),
                channel: 1,
                band: super::native_band::Band::Two,
                interval: 100,
                dtim: 1,
                rsn: None,
                privacy: false,
                capabilities: 1,
                information_elements: Vec::new(),
            },
            local: [2; 6],
            management_queue: 1,
            data_queues: [None, Some(17), None, None],
            qos: None,
            sequence: 0,
            security: None,
            replay: frame_api::Replay::default(),
            extra_rx: Vec::new(),
            receive_epoch: 0, // explicit post-association RAM fixture owner
            authorized: true,
            last_beacon: narf_time::now_cycles(),
            group_keys: [None; 4],
            pairwise_key: None,
            tx_antenna: 1,
            rates: super::rates::Rates::parse(&[1, 1, 0x82], 1).unwrap(),
            phy: super::ht_vht::Negotiated::default(),
            local_phy: super::ht_vht::Local::from_nvm(0, 1, 1),
            regulatory: Self::model_policy_program(),
            ap_power_limit: None,
            power_pending: false,
            power_inflight: false,
            rx_ba: core::array::from_fn(|_| None),
            actions: VecDeque::new(),
            mfp: narf_wireless::mfp::MfpKeyStore::new(),
            mfp_active: false,
            pmf_negotiated: false,
            management_pn: 0,
            key_history: super::sc_security::KeyHistory::default(),
            he: None,
            eht: None,
            six: None,
            mld: None,
            mld_links: Vec::new(),
            mld_rejected: Vec::new(),
            ap_eml: None,
            ap_med_sync: None,
            emlsr: super::sc_emlsr::Emlsr::default(),
            mlo_select: super::sc_emlsr::Selector::default(),
            active_request: None,
            mld_association: None,
            ttlm: Default::default(),
            client: None,
            mld_eapol: VecDeque::new(),
            tx_amsdu: super::sc_tx_amsdu::Limits::default(),
            amsdu_memory: None,
            amsdu_memory_attempted: false,
            tlc_notification_version: None,
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn model_policy_domain() -> narf_wireless::reg::RegulatoryDomain {
        narf_wireless::reg::RegulatoryDomain {
            country_code: *b"US",
            rules: alloc::vec![narf_wireless::reg::RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2422,
                max_bandwidth_mhz: 20,
                max_power_dbm: 10,
                flags: narf_wireless::reg::RegFlags::empty(),
            }],
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn model_policy_program() -> super::mld_policy::Program {
        super::mld_policy::Program::new(
            &Self::model_policy_domain(),
            super::mld_regulatory::Mcc {
                channels: alloc::vec![13;51].into(),
                country: *b"US",
                etsi_5ghz: false,
                he_allowed: false,
                eht_allowed: false,
                widths: super::gen3_wire::Widths {
                    forty: true,
                    eighty: true,
                    one_sixty: true,
                    three_twenty: false,
                },
            },
            1,
            0,
            1,
            10,
            None,
            super::mld_policy::Validity::new(),
        )
        .unwrap()
    }
    pub(super) fn regulatory_program(&self) -> super::mld_policy::Program {
        self.regulatory.clone()
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn secure_model() -> Self {
        let mut connection = Self::open_model();
        connection.security = Some(security::Session::new(
            security::Akm::Wpa2Psk,
            [0x11; 32],
            [4; 6],
            [2; 6],
            [0x33; 32],
            narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body(),
        ));
        connection.beacon.privacy = true;
        connection
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn sequence_for_test(&self) -> u16 {
        self.sequence
    }

    pub async fn associate(
        hw: &mut Hardware,
        local: [u8; 6],
        beacon: Beacon,
        auth: AuthMethod,
        tx_chains: u32,
        local_phy: super::ht_vht::Local,
        roam_from: Option<[u8; 6]>,
    ) -> Result<Self, &'static str> {
        let domain = narf_wireless::reg::db::ensure_domain()
            .map_err(|_| "wireless regulatory domain is not configured")?;
        let policy = super::mld_policy::Source::native();
        hw.install_rf_policy(super::mld_policy::Authority::Transaction(
            policy.transaction(&domain)?,
        ))?;
        let connection = Self::associate_in_domain(
            hw, local, beacon, auth, tx_chains, local_phy, roam_from, &domain,
        )
        .await?;
        let fence = policy.bind(connection.regulatory_program())?;
        hw.install_rf_policy(super::mld_policy::Authority::Station(fence))?;
        Ok(connection)
    }

    // The private model supplies its explicit policy through the same full
    // association owner; public callers always snapshot the authenticated db.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn associate_in_domain(
        hw: &mut Hardware,
        local: [u8; 6],
        beacon: Beacon,
        auth: AuthMethod,
        tx_chains: u32,
        local_phy: super::ht_vht::Local,
        roam_from: Option<[u8; 6]>,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Self, &'static str> {
        Self::associate_client_in_domain(
            hw, local, beacon, auth, tx_chains, local_phy, roam_from, domain, None,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn associate_client_in_domain(
        hw: &mut Hardware,
        local: [u8; 6],
        beacon: Beacon,
        auth: AuthMethod,
        tx_chains: u32,
        local_phy: super::ht_vht::Local,
        roam_from: Option<[u8; 6]>,
        domain: &narf_wireless::reg::RegulatoryDomain,
        client: Option<(super::p2p_client::Plan, narf_net::native_emission::Lifetime)>,
    ) -> Result<Self, &'static str> {
        Self::associate_links_in_domain(
            hw,
            local,
            beacon,
            auth,
            tx_chains,
            local_phy,
            roam_from,
            domain,
            client,
            Vec::new(),
        )
        .await
    }

    /// Associate as a non-AP MLD requesting the further affiliated links
    /// in `further` (mlme.c `ieee80211_mgd_assoc` with several links).
    /// Links the native profile cannot admit are not requested; accepted
    /// links stay valid but inactive until `activate_mld_link`.
    #[allow(clippy::too_many_arguments)]
    pub async fn associate_mld_links(
        hw: &mut Hardware,
        local: [u8; 6],
        beacon: Beacon,
        auth: AuthMethod,
        tx_chains: u32,
        local_phy: super::ht_vht::Local,
        further: Vec<super::MldLinkCandidate>,
    ) -> Result<Self, &'static str> {
        let domain = narf_wireless::reg::db::ensure_domain()
            .map_err(|_| "wireless regulatory domain is not configured")?;
        let policy = super::mld_policy::Source::native();
        hw.install_rf_policy(super::mld_policy::Authority::Transaction(
            policy.transaction(&domain)?,
        ))?;
        let connection = Self::associate_links_in_domain(
            hw, local, beacon, auth, tx_chains, local_phy, None, &domain, None, further,
        )
        .await?;
        let fence = policy.bind(connection.regulatory_program())?;
        hw.install_rf_policy(super::mld_policy::Authority::Station(fence))?;
        Ok(connection)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn associate_links_in_domain(
        hw: &mut Hardware,
        local: [u8; 6],
        beacon: Beacon,
        auth: AuthMethod,
        tx_chains: u32,
        mut local_phy: super::ht_vht::Local,
        roam_from: Option<[u8; 6]>,
        domain: &narf_wireless::reg::RegulatoryDomain,
        client: Option<(super::p2p_client::Plan, narf_net::native_emission::Lifetime)>,
        further: Vec<super::MldLinkCandidate>,
    ) -> Result<Self, &'static str> {
        if let Some((plan, _)) = &client {
            if !super::p2p_go::host_allows(domain, plan.channel) {
                return Err("P2P client current host NO_P2P prohibits association");
            }
            if roam_from.is_some() || matches!(auth, AuthMethod::Open) {
                return Err("P2P client requires a fresh protected owner");
            }
            local_phy = super::ht_vht::Local::from_nvm(0, 1, 1);
        }
        //6GHz admission precedes even receive-queue I/O. MVM API59 and
        // AP-power API1 are source facts, never inferred from the channel.
        local_phy.eht &= hw.eht_supported();
        local_phy.eht_320 &= local_phy.eht && hw.eht_320_supported();
        let six_preflight = if beacon.band == super::native_band::Band::Six {
            if !hw.band_in_rx_supported()
                || !super::sc_he::native_supported(hw)
                || hw.version(4, 0xc).map(|v| v.0) != Some(1)
            {
                return Err("6GHz native RX/HE/AP-power command contract absent");
            }
            Some(super::six_ghz_station::prepare(
                &beacon, local, &auth, local_phy, domain, None,
            )?)
        } else {
            None
        };
        // Reserve before any native await. Neither old notifications nor
        // descriptors copied while this port is closed belong to the new key.
        let receive_epoch = hw.close_receive_epoch()?;
        let client = client
            .map(|(plan, role)| hw.install_p2p_client(plan, role))
            .transpose()?;
        hw.prepare_receive_queues().await?;
        let secure = !matches!(auth, AuthMethod::Open);
        let (mut profile, mut six) = match six_preflight {
            Some((profile, six)) => (profile, Some(six)),
            None => (
                super::sc_security::Profile::negotiate(&beacon, local, &auth, local_phy)?,
                None,
            ),
        };
        let akm = profile.akm;
        if secure && hw.version(5, 0x18).map(|v| v.0) != Some(1) {
            return Err("unsupported MLD security key command");
        }
        // Fail before station firmware changes if secure association cannot
        // obtain an unpredictable SNonce. Open networks do not sample entropy.
        let snonce = if secure {
            Some(Zeroizing::new(security::fresh_nonce()?))
        } else {
            None
        };
        let qos = super::qos::Parameters::parse(&beacon.information_elements)?;
        if six.is_some() && qos.is_none() {
            return Err("6GHz native HE requires WMM");
        }
        let permissions = regulatory_channels_in_domain(hw, domain).await?;
        if six.is_some() {
            let admitted = super::six_ghz_station::prepare(
                &beacon,
                local,
                &auth,
                local_phy,
                domain,
                Some(&permissions),
            )?;
            profile = admitted.0;
            six = Some(admitted.1);
        }
        let original_local = local_phy;
        // Rebuild the shared offer with the native owner's current width
        // limit. A forbidden160 span retains a genuine HE/VHT80 fallback;
        // an unbounded shared160 offer cannot relabel that narrower program.
        if six.is_none()
            && (!permissions.widths.permits(3)
                || ![50, 114, 163].into_iter().any(|center| {
                    local_phy.permits160(center)
                        && channel_power_width(
                            domain,
                            beacon.channel,
                            3,
                            center,
                            &permissions.channels,
                        )
                        .is_some()
                }))
        {
            local_phy.width160_channels = 0;
        }
        if six.is_none()
            && local_phy.he
            && (!permissions.he_allowed || !super::sc_he::native_supported(hw))
        {
            local_phy.he = false;
        }
        local_phy.eht &= local_phy.he && permissions.eht_allowed && hw.eht_supported();
        if six.is_none() && local_phy != original_local {
            profile = super::sc_security::Profile::negotiate(&beacon, local, &auth, local_phy)?;
        }
        let phy = if let Some(six) = &six {
            let mut phy =
                super::ht_vht::Negotiated::he_six(beacon.channel, six.plan.peer_capability());
            phy.width = six.span.width;
            phy.center = six.span.center;
            phy
        } else {
            super::ht_vht::Negotiated::parse_with_offer(
                local_phy,
                &beacon.information_elements,
                beacon.channel,
                qos.is_some(),
                |width, center| {
                    permissions.widths.permits(width)
                        && channel_power_width(
                            domain,
                            beacon.channel,
                            width,
                            center,
                            &permissions.channels,
                        )
                        .is_some()
                },
                profile
                    .offer
                    .as_ref()
                    .map(|offer| (offer, profile.sae.as_ref().is_some_and(|join| join.h2e()))),
            )?
        };
        let he_offer = profile
            .offer
            .filter(|offer| qos.is_some() && super::sc_he::matches_native(offer, &phy));
        if he_offer.is_none() && profile.offer.is_some_and(|offer| offer.he().is_some()) {
            local_phy.he = false;
            profile = super::sc_security::Profile::negotiate(&beacon, local, &auth, local_phy)?;
        }
        let mut rates = if six.is_some() {
            super::rates::Rates::parse_six_eht(
                &beacon.information_elements,
                true,
                six.as_ref().is_some_and(|six| six.plan.eht().is_some()),
            )?
        } else {
            super::rates::Rates::parse_for_native_profiles(
                &beacon.information_elements,
                beacon.channel,
                phy.mode,
                profile.sae.as_ref().is_some_and(|join| join.h2e()),
                he_offer.is_some(),
                he_offer.is_some_and(|offer| offer.eht().is_some()),
            )?
        };
        if client.is_some() {
            rates.supported &= !15;
            rates.basic &= !15;
        }
        let max_power = if let Some(six) = &six {
            six.rule(domain, Some(&permissions))
                .filter(|rule| rule.allows_6ghz_client(six.power_type()))
                .map(|rule| rule.max_power_dbm)
                .ok_or("6GHz current host/NVM/MCC power prohibited")?
        } else {
            channel_power_width(
                domain,
                beacon.channel,
                phy.width,
                phy.center,
                &permissions.channels,
            )
            .ok_or("channel transmission prohibited by host/firmware regulatory policy")?
        };
        let ap_power = if six.is_some() {
            None
        } else {
            super::mld_power::ap_limit_in_ies(
                &beacon.information_elements,
                beacon.capabilities,
                beacon.channel,
            )?
        };
        let max_power = ap_power.map_or(max_power, |limit| i16::from(max_power).min(limit) as i8);
        let qos = if six.is_some() {
            permissions.limit_qos_band(
                domain,
                beacon.band,
                beacon.channel,
                phy.width,
                phy.center,
                qos,
            )
        } else {
            permissions.limit_qos(domain, beacon.channel, phy.width, phy.center, qos)
        };
        let regulatory = if let Some(six) = &six {
            super::mld_policy::Program::new_six(
                domain,
                permissions.clone(),
                six,
                max_power,
                qos,
                hw.rf_policy_validity()?,
            )?
        } else {
            super::mld_policy::Program::new(
                domain,
                permissions.clone(),
                beacon.channel,
                phy.width,
                phy.center,
                max_power,
                qos,
                hw.rf_policy_validity()?,
            )?
        };
        let regulatory = if let Some(client) = &client {
            regulatory.with_client(client.plan.binding())?
        } else {
            regulatory
        };
        let mld = profile
            .mld
            .as_deref()
            .map(|context| {
                super::sc_mlo::Binding::new(
                    *context,
                    super::native_band::Channel {
                        band: beacon.band,
                        number: beacon.channel,
                    },
                    local,
                    beacon.bssid,
                )
            })
            .transpose()?;
        if mld.is_some() && (!local_phy.eht || !hw.eht_supported() || !profile.pmf) {
            return Err("native MLD current EHT/PMF source absent");
        }
        let admission = super::sc_mlo_assoc::Admission {
            domain,
            permissions: &permissions,
            local: local_phy,
        };
        // Further links only for a 2.4/5GHz MLD station owner on the Sc/Bz
        // MLD ABI with a fresh (non-roaming, non-P2P) association.
        if mld.is_some()
            && six.is_none()
            && client.is_none()
            && roam_from.is_none()
            && !hw.is_mvm89()
            && !further.is_empty()
        {
            let candidates: Vec<_> = further
                .iter()
                .filter_map(|candidate| {
                    admission
                        .local_for(&candidate.beacon)
                        .map(|phy| (&candidate.beacon, candidate.own_link, phy))
                })
                .collect();
            // A candidate the shared plan cannot request is simply not
            // requested; the association link is unchanged either way.
            let _ = profile.negotiate_links(&beacon, local, local_phy, &candidates);
        }
        hw.ensure_platform_power().await?;
        if client.is_some() {
            hw.prepare_p2p_client().await?;
        }
        if let Some(mld) = &mld {
            let mut mac = station_api::mac(2, local, None);
            mld.apply_mac(&mut mac);
            hw.command(3, 8, &mac).await?;
            // spec_link_id is an ADD-time fact in Linux. Replace the
            // inactive default link instead of pretending MODIFY sets it.
            let mut removed = station_api::link(3, local, false, beacon.channel, 0, 1);
            mld.apply_link(&mut removed);
            hw.command(3, 9, &removed).await?;
            let mut added = station_api::link(1, local, false, beacon.channel, 0, 1);
            mld.apply_link(&mut added);
            hw.command(3, 9, &added).await?;
        }
        let mut phy_command = station_api::phy_channel(
            1,
            super::native_band::Channel {
                band: beacon.band,
                number: beacon.channel,
            },
        );
        phy.apply_phy(&mut phy_command, beacon.channel);
        hw.station_phy(&phy_command, beacon.channel).await?;
        // PHY binding is accepted only while the link stays inactive.
        // Combining the bind with activation causes firmware to ignore
        // phy_id, leaving the link detached from its channel context.
        let mut binding = station_api::link_channel(
            2,
            local,
            false,
            super::native_band::Channel {
                band: beacon.band,
                number: beacon.channel,
            },
            beacon.interval,
            beacon.dtim,
        );
        put32(&mut binding, 12, 0);
        if let Some(mld) = &mld {
            mld.apply_link(&mut binding);
        }
        hw.command(3, 9, &binding).await?;
        // Program host/AP power before any active link or autonomous TX.
        let power = station_api::tx_power(
            hw.version(1, 0x9f).ok_or("missing TX power command")?.0,
            max_power,
        )?;
        hw.command(1, 0x9f, &power).await?;
        let mut link = station_api::link_channel(
            2,
            local,
            true,
            super::native_band::Channel {
                band: beacon.band,
                number: beacon.channel,
            },
            beacon.interval,
            beacon.dtim,
        );
        rates.apply(&mut link);
        put32(
            &mut link,
            44,
            u32::from(beacon.capabilities & (1 << 5) != 0),
        );
        put32(
            &mut link,
            48,
            u32::from(beacon.capabilities & (1 << 10) != 0),
        );
        if let Some(qos) = &qos {
            qos.apply(&mut link);
        }
        phy.apply_link(&mut link);
        if let Some(mld) = &mld {
            mld.apply_link(&mut link);
        }
        hw.command(3, 9, &link).await?;
        if let Some(six) = &six {
            // Linux's AP-power command is issued on an active link. No
            // station/TX queue exists yet, and no management TX precedes
            // this actual native receipt or a queued stricter AP beacon.
            six.apply_pending(hw).await?;
            hw.install_six_tx_profile(six.clone())?;
        }
        let mut peer = station_api::peer(beacon.bssid);
        phy.apply_peer(&mut peer, 0);
        put32(&mut peer, 36, u32::from(profile.pmf));
        if let Some(mld) = &mld {
            mld.apply_peer(&mut peer);
        }
        hw.station_peer(&peer).await?;
        if let Some(mld) = &mld {
            hw.install_mld_link(mld.clone())?;
        }
        let management_queue = hw.allocate_tx(0, 15).await?;
        let mut data_queues = [None; 4];
        for (ac, &tid) in super::qos::TIDS.iter().enumerate() {
            if qos.is_some() || ac == 1 {
                data_queues[ac] = Some(hw.allocate_tx(0, tid).await?);
            }
        }
        let mut session = [0; 24];
        put32(&mut session, 4, 1);
        put32(&mut session, 12, 10000); // 10.24s channel residency for authentication
        hw.command(3, 5, &session).await?;
        let started = hw.wait_notification(3, 0xfb, 1000).await?;
        if started.payload.len() != 16 || started.payload[4..12] != [1, 0, 0, 0, 1, 0, 0, 0] {
            return Err("association channel residency rejected");
        }
        let mut this = Self {
            beacon,
            local,
            management_queue,
            data_queues,
            qos,
            sequence: 0,
            // Set once the PMK is known (after SAE for WPA3).
            security: None,
            replay: frame_api::Replay::default(),
            extra_rx: (1..hw.receive_queue_count())
                .map(|_| QueueRx::default())
                .collect(),
            receive_epoch,
            authorized: false,
            last_beacon: narf_time::now_cycles(),
            group_keys: [None; 4],
            pairwise_key: None,
            tx_antenna: tx_chains & tx_chains.wrapping_neg(),
            rates,
            phy,
            local_phy,
            regulatory,
            ap_power_limit: ap_power,
            power_pending: false,
            power_inflight: false,
            rx_ba: core::array::from_fn(|_| None),
            actions: VecDeque::new(),
            mfp: narf_wireless::mfp::MfpKeyStore::new(),
            mfp_active: false,
            pmf_negotiated: profile.pmf,
            management_pn: 0,
            key_history: super::sc_security::KeyHistory::default(),
            he: None,
            eht: None,
            six,
            mld,
            mld_links: Vec::new(),
            mld_rejected: Vec::new(),
            ap_eml: None,
            ap_med_sync: None,
            emlsr: super::sc_emlsr::Emlsr::default(),
            mlo_select: super::sc_emlsr::Selector::default(),
            active_request: None,
            mld_association: None,
            ttlm: Default::default(),
            client,
            mld_eapol: VecDeque::new(),
            tx_amsdu: super::sc_tx_amsdu::Limits::default(),
            amsdu_memory: None,
            amsdu_memory_attempted: false,
            tlc_notification_version: hw.version(5, 0xf7).map(|v| v.1),
        };
        // Authenticate: open-system auth for Open/WPA2-PSK; the SAE
        // commit/confirm exchange for WPA3, which also yields the PMK.
        this.check_six_pending(hw)?;
        let pmk: Option<[u8; 32]> = match &auth {
            AuthMethod::Open | AuthMethod::Wpa2Psk(_) => {
                let frame = this.management(0xb0, &mlme::build_open_auth_body());
                hw.transmit(management_queue, &frame, 24, this.rate())
                    .await?;
                let reply = this.wait_management(hw, 0xb0).await?;
                if !mlme::AuthResponse::decode(&reply).is_some_and(|reply| reply.is_success()) {
                    return Err("AP rejected authentication");
                }
                match &auth {
                    AuthMethod::Wpa2Psk(psk) => Some(*psk),
                    _ => None,
                }
            }
            AuthMethod::Wpa3Sae { password } => {
                let join = profile.sae.as_ref().ok_or("MLD SAE negotiation missing")?;
                let (pmk, pmkid) = this.sae_authenticate(hw, password, join).await?;
                profile.rsne = Some(join.station_rsne(Some(pmkid)));
                Some(pmk)
            }
        };
        // With the PMK in hand, arm the 4-way handshake session.
        if let (Some(pmk), Some(akm)) = (pmk, akm) {
            let (station_rsnxe, ap_rsnxe) =
                profile.rsn_extensions(&this.beacon.information_elements)?;
            let session = security::Session::new(
                akm,
                pmk,
                this.beacon.bssid,
                local,
                **snonce.as_ref().ok_or("missing secure association nonce")?,
                this.beacon.rsn.clone().ok_or("AP has no RSN IE")?,
            )
            .with_pmf(profile.pmf)
            .with_station_rsn(profile.rsne.clone().ok_or("MLD station RSNE missing")?)
            .with_rsn_extensions(station_rsnxe, ap_rsnxe)?;
            this.security = Some(match &this.mld {
                Some(mld) => session.with_mld(mld.context)?,
                None => session,
            });
        }
        let rsn = profile.rsne.clone();
        let rates = this.rates.elements();
        let params = mlme::AssocParamsRsn {
            base: mlme::AssocParams {
                sta_addr: this.management_addresses().0,
                ap_bssid: this.management_addresses().1,
                ssid: this.beacon.ssid.clone(),
                supported_rates: rates[..rates.len().min(8)].to_vec(),
                capability_info: 1
                    | (this.beacon.capabilities & 0x420)
                    | if secure { 0x10 } else { 0 },
                listen_interval: 10,
                seq_num: this.sequence,
            },
            rsn_ie_body: rsn,
            ext_rates: rates.get(8..).unwrap_or(&[]).to_vec(),
        };
        // Roaming sends a Reassociation Request carrying the current AP
        // address and expects a Reassociation Response (subtype 0x30).
        let (mut request, response_subtype) = match roam_from {
            Some(current_ap) => (mlme::build_reassoc_request_rsn(&params, current_ap), 0x30),
            None => (mlme::build_assoc_request_rsn(&params), 0x10),
        };
        if let Some(rsnxe) = profile.sae.as_ref().and_then(|join| join.station_rsnxe()) {
            request.extend_from_slice(&[244, rsnxe.len() as u8]);
            request.extend_from_slice(&rsnxe);
        }
        if this.qos.is_some() {
            request.extend_from_slice(&super::qos::INFORMATION_IE);
        }
        request.extend_from_slice(&this.phy.association_ies(local_phy, this.beacon.channel));
        if let Some(six) = &this.six {
            six.append_capabilities(&mut request);
        }
        if let Some(he) = he_offer.as_ref().and_then(|offer| offer.he()) {
            let capability = he.local_capability();
            request.extend_from_slice(&[255, capability.len() as u8]);
            request.extend_from_slice(&capability);
        }
        if let Some(eht) = he_offer.as_ref().and_then(|offer| offer.eht()) {
            let capability = eht.local_capability();
            request.extend_from_slice(&[255, capability.len() as u8]);
            request.extend_from_slice(&capability);
        }
        if let Some(mld) = &this.mld {
            // mlme.c places the Basic MLE before EHT Capabilities; the
            // Reassociation Request has the 6-octet current AP field too.
            let ies_start = if response_subtype == 0x30 { 34 } else { 28 };
            // A multiple-link request carries one COMPLETE per-STA profile
            // per further link, inheriting against this exact frame.
            let element = match profile.links.as_deref() {
                Some(plan) => plan
                    .mld_request_element(request.get(ies_start..).unwrap_or(&[]))
                    .map_err(|_| "native MLD multiple-link request element invalid")?,
                None => mld.request_element().to_vec(),
            };
            narf_wireless::association::mlo::insert_request_element(
                &mut request,
                ies_start,
                &element,
            );
            mld.project_management(&mut request);
        }
        if let Some(client) = &this.client {
            request.extend_from_slice(&client.plan.elements);
        }
        this.sequence = this.sequence.wrapping_add(1);
        this.check_six_pending(hw)?;
        hw.transmit(management_queue, &request, 24, this.rate())
            .await?;
        let reply = this.wait_management(hw, response_subtype).await?;
        let response =
            mlme::AssocResponseFields::decode(&reply).ok_or("invalid association response")?;
        if !response.is_success() || !(1..=2007).contains(&response.aid) {
            return Err("AP rejected association");
        }
        profile.check_response(&reply[6..])?;
        if this.mld.is_some() {
            let mle = narf_wireless::association::mlo::BasicMultiLink::from_ies(&reply[6..]).ok();
            this.ap_eml = mle.and_then(|mle| mle.eml_capabilities());
            this.ap_med_sync = mle.and_then(|mle| mle.medium_sync_delay());
        }
        let mut valid_links = Vec::new();
        let mut rejected = Vec::new();
        let mut link_security = Vec::new();
        let candidate_rsnxe: Vec<_> = further
            .iter()
            .map(|candidate| {
                profile
                    .rsn_extensions(&candidate.beacon.information_elements)
                    .map(|extensions| extensions.1)
            })
            .collect();
        if let Some(plan) = profile.links.as_deref_mut() {
            plan.accept_mld_links(&reply[6..], response.aid)
                .map_err(|_| "native MLD per-link association response invalid")?;
            let h2e = profile.sae.as_ref().is_some_and(|join| join.h2e());
            // Every requested link, accepted or rejected, is named in M2
            // and needs its M3 Link KDE (hostap wpa.c req_links).
            for link in plan.mld_links() {
                let at = further
                    .iter()
                    .position(|candidate| {
                        candidate.beacon.bssid == link.context().peer_link()
                            && candidate.own_link == link.context().own_link()
                    })
                    .ok_or("native MLD link response names an unrequested link")?;
                let candidate = &further[at];
                link_security.push(security::FurtherLinkSecurity {
                    context: *link.context(),
                    ap_rsn: candidate
                        .beacon
                        .rsn
                        .clone()
                        .ok_or("native MLD further link has no RSNE")?,
                    ap_rsnxe: candidate_rsnxe[at].clone()?,
                    accepted: link.accepted(),
                });
                if !link.accepted() {
                    rejected.push((
                        link.link_id(),
                        link.context().own_link(),
                        link.context().peer_link(),
                        // WLAN_STATUS_UNSPECIFIED_FAILURE if no code.
                        link.status().filter(|code| *code != 0).unwrap_or(1),
                    ));
                    continue;
                }
                // mlme.c fails the association when an accepted link
                // cannot be configured.
                valid_links.push(admission.accept(
                    hw,
                    &candidate.beacon,
                    link,
                    h2e,
                    response.aid,
                    tx_chains,
                    profile.pmf,
                )?);
            }
        }
        if !link_security.is_empty() {
            this.security
                .as_mut()
                .ok_or("native MLD further links without a secure session")?
                .with_further_links(link_security)?;
        }
        this.mld_links = valid_links;
        this.mld_rejected = rejected;
        if let Some(mld) = &this.mld {
            // mlme.c ieee80211_assoc_success: a response TTLM must already
            // be in effect and map a valid link; the rest are dormant.
            let association = mld.association().spec_link;
            let valid = this.mld_valid_links() | 1 << association;
            let (dormant, info) = super::sc_emlsr::response_dormant(&reply[6..], valid)
                .map_err(|()| "invalid advertised TTLM in association response")?;
            if dormant & (1 << association) != 0 {
                // mac80211 would serve another link at once; the native
                // association link cannot start dormant here.
                return Err("advertised TTLM makes the association link dormant");
            }
            this.ttlm.associated(dormant, info);
        }
        this.emlsr
            .links_activated(this.mld_active_links(), now_ms());
        if let Some(client) = &this.client {
            client.plan.response(&reply[6..])?;
        }
        if this.qos.is_some() {
            // Association response may refine contention parameters from
            // the beacon. Only use QoS if the AP confirms WMM support.
            this.qos = super::qos::Parameters::parse(&reply[6..])?;
        }
        if this.six.is_some() && this.qos.is_none() {
            return Err("6GHz response did not confirm WMM");
        }
        if let Some(original) = this.six.clone() {
            let six = original.refine(&reply[6..], domain, &permissions)?;
            let static_smps = six.plan.peer_capability().sm_ps() == 0
                || original.original().peer_capability().sm_ps() == 0;
            this.he = Some(
                super::sc_he::Profile::new(
                    *six.plan.he(),
                    &reply[6..],
                    static_smps,
                    super::sc_he::rates_version(hw).ok_or("6GHz native HE rate ABI changed")?,
                )?
                .bound_original(original.original().he())?,
            );
            if let Some(eht) = six.plan.eht() {
                this.eht = Some(super::sc_eht::Profile::new_six(
                    *eht,
                    original
                        .original()
                        .eht()
                        .ok_or("6GHz response invented EHT")?,
                    this.he.as_ref().unwrap(),
                    static_smps,
                )?);
            }
            let mut phy =
                super::ht_vht::Negotiated::he_six(this.beacon.channel, six.plan.peer_capability());
            // A response cannot enlarge the original peer's aggregation or
            // relax its MPDU spacing/SMPS promises.
            phy.ampdu_exp = phy.ampdu_exp.min(this.phy.ampdu_exp);
            phy.density = phy.density.max(this.phy.density);
            phy.dynamic_smps |= this.phy.dynamic_smps;
            phy.width = six.span.width;
            phy.center = six.span.center;
            this.phy = phy;
            this.six = Some(six);
        } else {
            this.phy = this.phy.confirm(
                local_phy,
                &this.beacon.information_elements,
                &reply[6..],
                this.beacon.channel,
                this.qos.is_some(),
            )?;
            if let Some(offer) = he_offer {
                let negotiated = offer
                    .response_elements_with_sae_h2e(
                        &reply[6..],
                        profile.sae.as_ref().is_some_and(|join| join.h2e()),
                    )
                    .map_err(|_| "MLD association response did not confirm the HE offer")?;
                let he = *negotiated.he().ok_or("MLD response omitted HE")?;
                if negotiated.center_channel() != this.phy.center
                    || match negotiated.width() {
                        narf_wireless::association::phy::Width::Twenty => this.phy.width != 0,
                        narf_wireless::association::phy::Width::Forty => this.phy.width != 1,
                        narf_wireless::association::phy::Width::Eighty => this.phy.width != 2,
                        narf_wireless::association::phy::Width::OneSixty => this.phy.width != 3,
                    }
                {
                    return Err("MLD HE response differs from native PHY/MCC span");
                }
                this.he = Some(super::sc_he::Profile::new(
                    he,
                    &reply[6..],
                    (negotiated.ht().peer_capability() >> 2) & 3 == 0,
                    super::sc_he::rates_version(hw).ok_or("MLD HE rate ABI changed")?,
                )?);
                if let Some(eht) = negotiated.eht() {
                    this.eht = Some(super::sc_eht::Profile::new(
                        *eht,
                        offer
                            .eht()
                            .ok_or("MLD response invented an unoffered EHT profile")?,
                        this.he.as_ref().unwrap(),
                        (negotiated.ht().peer_capability() >> 2) & 3 == 0,
                    )?);
                }
            }
        }
        this.qos = permissions.limit_qos_band(
            domain,
            this.beacon.band,
            this.beacon.channel,
            this.phy.width,
            this.phy.center,
            this.qos,
        );
        // The response can choose a different secondary channel while
        // narrowing bandwidth. Revalidate the resulting entire span.
        if !permissions.widths.permits(this.phy.width) {
            return Err("association response exceeds native MCC width capability");
        }
        let final_power = if let Some(six) = &this.six {
            six.rule(domain, Some(&permissions))
                .filter(|rule| rule.allows_6ghz_client(six.power_type()))
                .map(|rule| rule.max_power_dbm)
                .ok_or("6GHz response lost native channel power")?
        } else {
            channel_power_width(
                domain,
                this.beacon.channel,
                this.phy.width,
                this.phy.center,
                &permissions.channels,
            )
            .ok_or("association response selected a prohibited channel span")?
        };
        if final_power < max_power {
            let power = station_api::tx_power(
                hw.version(1, 0x9f).ok_or("missing TX power command")?.0,
                final_power,
            )?;
            hw.command(1, 0x9f, &power).await?;
        }
        // Recheck membership selectors after a response downgrades PHY.
        this.rates = if this.six.is_some() {
            super::rates::Rates::parse_six_eht(
                &this.beacon.information_elements,
                true,
                this.eht.is_some(),
            )?
        } else {
            super::rates::Rates::parse_for_native_profiles(
                &this.beacon.information_elements,
                this.beacon.channel,
                this.phy.mode,
                profile.sae.as_ref().is_some_and(|join| join.h2e()),
                this.he.is_some(),
                this.eht.is_some(),
            )?
        };
        let mut phy_command = station_api::phy_channel(
            2,
            super::native_band::Channel {
                band: this.beacon.band,
                number: this.beacon.channel,
            },
        );
        this.phy.apply_phy(&mut phy_command, this.beacon.channel);
        hw.station_phy(&phy_command, this.beacon.channel).await?;
        let association_link = {
            let mut link = station_api::link_channel(
                2,
                local,
                true,
                super::native_band::Channel {
                    band: this.beacon.band,
                    number: this.beacon.channel,
                },
                this.beacon.interval,
                this.beacon.dtim,
            );
            this.rates.apply(&mut link);
            put32(
                &mut link,
                44,
                u32::from(this.beacon.capabilities & (1 << 5) != 0),
            );
            put32(
                &mut link,
                48,
                u32::from(this.beacon.capabilities & (1 << 10) != 0),
            );
            if let Some(qos) = &this.qos {
                qos.apply(&mut link);
            }
            this.phy.apply_link(&mut link);
            if let Some(mld) = &this.mld {
                mld.apply_link(&mut link);
            }
            if let Some(he) = this.he {
                he.apply_link(&mut link);
            }
            hw.station_link(&mut link);
            hw.command(3, 9, &link).await?;
            link
        };
        let mut peer = station_api::peer(this.beacon.bssid);
        this.phy.apply_peer(&mut peer, response.aid);
        if let Some(he) = this.he {
            he.apply_sta(&mut peer);
        }
        if let Some(eht) = &this.eht {
            eht.apply_sta(&mut peer);
        }
        put32(&mut peer, 36, u32::from(this.pmf_negotiated));
        if let Some(mld) = &this.mld {
            mld.apply_peer(&mut peer);
        }
        hw.station_peer(&peer).await?;
        let mut mac = match &this.client {
            Some(client) => client.mac(2, Some(response.aid), client.desired())?,
            None => station_api::mac(2, local, Some(response.aid)),
        };
        if let Some(he) = this.he {
            he.apply_mac(&mut mac);
        }
        if let Some(eht) = &this.eht {
            eht.apply_mac(&mut mac);
        }
        if let Some(mld) = &this.mld {
            mld.apply_mac(&mut mac);
            // mld/iface.c iwl_mld_mac_cmd_fill_sta: MLD client esr fields.
            let (timeout, sync) = super::sc_emlsr::client_mld_fields(this.ap_eml, this.ap_med_sync);
            mac[37] = timeout;
            put16(&mut mac, 38, sync);
        }
        hw.command(3, 8, &mac).await?;
        if let Some(client) = &this.client {
            client.associated(response.aid)?;
            client.commit_window(
                u32::from_le_bytes(mac[48..52].try_into().unwrap()),
                u32::from_le_bytes(mac[20..24].try_into().unwrap()) & 32 != 0,
            )?;
        }
        let mut tlc = this.rates.tlc(
            if hw.is_mvm89() {
                6
            } else {
                hw.version(5, 0xf).ok_or("firmware has no TLC command")?.0
            },
            tx_chains,
        )?;
        if this.phy.mode != 0 {
            hw.enable_aggregation()?;
        }
        this.phy.apply_tlc(&mut tlc);
        if let Some(he) = this.he {
            he.apply_tlc(&mut tlc)?;
        }
        if let Some(eht) = &this.eht {
            eht.apply_tlc(&mut tlc);
        }
        hw.station_tlc(&tlc).await?;
        if this.mld.is_some() {
            this.mld_association = Some(super::sc_mlo_assoc::AssociationBodies {
                phy: phy_command,
                link: association_link,
                peer,
                tlc,
            });
        }
        if let Some(six) = &this.six {
            six.apply_pending(hw).await?;
            hw.install_six_tx_profile(six.clone())?;
        }
        // The response-refined native span/power is the handshake's owner;
        // a beacon received during M4 can update that same shared proof.
        this.regulatory = if let Some(six) = &this.six {
            super::mld_policy::Program::new_six(
                domain,
                permissions,
                six,
                final_power.min(max_power),
                this.qos,
                hw.rf_policy_validity()?,
            )?
        } else {
            super::mld_policy::Program::new(
                domain,
                permissions,
                this.beacon.channel,
                this.phy.width,
                this.phy.center,
                final_power.min(max_power),
                this.qos,
                hw.rf_policy_validity()?,
            )?
            .with_he(this.he.is_some())?
        }
        .with_eht(this.eht.is_some())?;
        if secure {
            let deadline = narf_time::Deadline::after_ms(8000);
            while !this.security.as_ref().unwrap().complete() {
                let activity = hw.activity();
                hw.poll()?;
                while let Some(packet) = hw.notifications.pop_front() {
                    this.amsdu_feedback(&packet);
                    if packet.receive_queue != 0
                        || packet.header.group_id != 0
                        || packet.header.cmd != 0xc1
                    {
                        continue;
                    }
                    let Some(mpdu) = scan_api::mpdu(&packet.payload) else {
                        continue;
                    };
                    this.receive(hw, &mpdu).await?;
                }
                if deadline.expired() {
                    return Err("WPA2 handshake timed out");
                }
                activity.await;
            }
        }
        if hw.receive_capture_epoch() != Some(this.receive_epoch) {
            this.open_receive_epoch(hw).await?;
        }
        hw.poll()?;
        this.authorized = true;
        Ok(this)
    }

    fn rate(&self) -> Option<u32> {
        Some(self.rates.management_rate(self.tx_antenna))
    }

    fn management_addresses(&self) -> ([u8; 6], [u8; 6]) {
        self.mld
            .as_ref()
            .map_or((self.local, self.beacon.bssid), |mld| {
                (mld.context.own_mld(), mld.context.peer_mld())
            })
    }
    fn data_addresses(&self, mpdu: &scan_api::Mpdu<'_>) -> Option<([u8; 6], [u8; 6])> {
        match &self.mld {
            Some(mld) => mld.data_addresses(mpdu),
            None => Some((self.local, self.beacon.bssid)),
        }
    }

    fn management(&mut self, subtype: u8, body: &[u8]) -> Vec<u8> {
        let (own, peer) = self.management_addresses();
        let mut frame = frame_api::management(subtype, own, peer, self.sequence, body);
        if subtype == 0xb0 {
            if let Some(mld) = &self.mld {
                frame.extend_from_slice(mld.authentication_element());
            }
        }
        if let Some(mld) = &self.mld {
            mld.project_management(&mut frame);
        }
        if self.pmf_negotiated
            && self.pairwise_key.is_some()
            && matches!(subtype, 0xa0 | 0xc0 | 0xd0)
        {
            frame[1] |= 0x40;
        }
        self.sequence = self.sequence.wrapping_add(1);
        frame
    }

    async fn wait_management(
        &mut self,
        hw: &mut Hardware,
        subtype: u8,
    ) -> Result<Vec<u8>, &'static str> {
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let activity = hw.activity();
            hw.poll()?;
            while let Some(packet) = hw.notifications.pop_front() {
                if packet.receive_queue != 0
                    || packet.header.group_id != 0
                    || packet.header.cmd != 0xc1
                {
                    continue;
                }
                let Some(mpdu) = scan_api::mpdu(&packet.payload) else {
                    continue;
                };
                let frame = mpdu.frame;
                if self.admits_channel(&mpdu)
                    && frame.len() >= 36
                    && frame[0] == 0x80
                    && frame[10..16] == self.beacon.bssid
                    && frame[16..22] == self.beacon.bssid
                {
                    if let Some(six) = &self.six {
                        six.confirm(
                            mpdu.body(24, 0)
                                .and_then(|body| body.get(12..))
                                .ok_or("invalid6GHz association beacon")?,
                        )?;
                    }
                }
                let header = self.mld.as_ref().map_or_else(
                    || {
                        frame.len() >= 24
                            && frame[4..10] == self.local
                            && frame[10..16] == self.beacon.bssid
                            && frame[16..22] == self.beacon.bssid
                    },
                    |mld| mld.management_header(&mpdu),
                );
                if !self.admits_channel(&mpdu) || !header {
                    continue;
                }
                if matches!(frame[0], 0xa0 | 0xc0) {
                    return Err("AP disconnected during association");
                }
                if frame[0] == subtype {
                    let body = mpdu.body(24, 0).ok_or("invalid management body")?;
                    let body = if subtype == 0xb0 {
                        match &self.mld {
                            Some(mld) => mld
                                .context
                                .authentication_body(body)
                                .map_err(|_| "native MLD auth omitted matching Basic ML trailer")?,
                            None => body,
                        }
                    } else {
                        body
                    };
                    return Ok(body.to_vec());
                }
            }
            if deadline.expired() {
                return Err("AP management response timed out");
            }
            activity.await;
        }
    }

    /// Drive the admitted group19 SAE profile, including AKM24's suite
    /// selector in the complete H2E transcript. SAE-PK retains its AP
    /// KeyAuth verification before either the PMK or PMKID is used.
    async fn sae_authenticate(
        &mut self,
        hw: &mut Hardware,
        password: &[u8],
        join: &narf_wireless::association::SaeJoin,
    ) -> Result<([u8; 32], [u8; 16]), &'static str> {
        use narf_wireless::sae::{SaeSession, SaeState, SAE_STATUS_HASH_TO_ELEMENT};
        let ssid = self.beacon.ssid.clone();
        let (own, peer) = self.management_addresses();
        let sae = if join.h2e() {
            SaeSession::new_h2e_bytes(&ssid, password, own, peer)
        } else {
            SaeSession::new_hunt_and_peck(password, own, peer)
        };
        let mut sae = match join.akm_suite_selector() {
            Some(selector) => sae
                .with_akm_suite_selector(selector)
                .map_err(|_| "MLD SAE AKM selector refused")?,
            None => sae,
        };
        sae.try_build_commit()
            .map_err(|_| "SAE commit entropy/parameters unavailable")?;
        let status = if join.h2e() {
            SAE_STATUS_HASH_TO_ELEMENT
        } else {
            0
        };
        let mut token: Option<Vec<u8>> = None;
        let mut commit_reply = Vec::new();
        let mut accepted = false;
        // Initial Commit plus at most three token retries. Reuse the actual
        // scalar/element; commit_body positions tokens according to the PWE.
        for _ in 0..=3 {
            let commit = sae.commit_body(token.as_deref());
            let frame = self.management(0xb0, &mlme::build_sae_auth_body(1, status, &commit));
            self.check_six_pending(hw)?;
            hw.transmit(self.management_queue, &frame, 24, self.rate())
                .await?;
            commit_reply = self.wait_management(hw, 0xb0).await?;
            let header =
                mlme::AuthResponse::decode(&commit_reply).ok_or("invalid SAE commit response")?;
            if header.algorithm != mlme::auth_algorithm::SAE || header.seq != 1 {
                return Err("AP did not answer SAE commit");
            }
            match header.status {
                0 | SAE_STATUS_HASH_TO_ELEMENT if header.status == status => {
                    accepted = true;
                    break;
                }
                76 => {
                    let body = commit_reply
                        .get(6..)
                        .ok_or("SAE token response missing body")?;
                    if body.get(..2) != Some(&19u16.to_le_bytes()) {
                        return Err("SAE token response changed group");
                    }
                    let bytes = &body[2..];
                    token = if join.h2e() {
                        if bytes.len() < 4
                            || bytes[0] != 255
                            || bytes[2] != 93
                            || usize::from(bytes[1]) + 2 != bytes.len()
                        {
                            return Err("SAE H2E token container malformed");
                        }
                        extract_anti_clogging_token(bytes)
                    } else {
                        (!bytes.is_empty()).then(|| bytes.to_vec())
                    };
                    if token.is_none() {
                        return Err("SAE anti-clogging token missing");
                    }
                }
                _ => return Err("AP rejected SAE commit/PWE"),
            }
        }
        if !accepted {
            return Err("SAE anti-clogging retries exhausted");
        }
        // Do not truncate the H2E elements: on_commit checks the AKM Suite
        // Selector and rejected-group salt before deriving the KCK/PMK.
        sae.on_commit(&commit_reply[6..])
            .map_err(|_| "SAE commit processing failed")?;
        let confirm = sae.build_confirm();
        let frame = self.management(0xb0, &mlme::build_sae_auth_body(2, 0, &confirm));
        self.check_six_pending(hw)?;
        hw.transmit(self.management_queue, &frame, 24, self.rate())
            .await?;
        let reply = self.wait_management(hw, 0xb0).await?;
        let header = mlme::AuthResponse::decode(&reply).ok_or("invalid SAE confirm response")?;
        if header.algorithm != mlme::auth_algorithm::SAE || header.seq != 2 || header.status != 0 {
            return Err("AP rejected SAE confirm");
        }
        sae.on_confirm(&reply[6..])
            .map_err(|_| "SAE confirm verification failed")?;
        if sae.state() != SaeState::Accepted {
            return Err("SAE did not reach Accepted");
        }
        if sae.is_sae_pk() {
            let ssid = core::str::from_utf8(&ssid).map_err(|_| "SAE-PK SSID is not UTF-8")?;
            let password =
                core::str::from_utf8(password).map_err(|_| "SAE-PK password is not UTF-8")?;
            self.verify_sae_pk(&sae, ssid, password)?;
        }
        Ok((
            *sae.pmk().ok_or("SAE produced no PMK")?,
            *sae.pmkid().ok_or("SAE produced no PMKID")?,
        ))
    }

    /// WPA3 SAE-PK AP authentication: recover the Modifier from the AP's
    /// Confirm element (AES-SIV under the SAE KEK), confirm the password's
    /// public-key fingerprint, and verify the ECDSA KeyAuth signature over the
    /// SAE exchange transcript. Returns `Err` (aborting the association) unless
    /// every check passes.
    fn verify_sae_pk(
        &self,
        sae: &narf_wireless::sae::SaeSession,
        ssid: &str,
        password: &str,
    ) -> Result<(), &'static str> {
        use narf_wireless::sae::pk;
        let kek = sae.kek().ok_or("SAE-PK: KEK not derived")?;
        let elements = pk::parse_elements(sae.peer_confirm_ies())
            .ok_or("SAE-PK: Confirm elements missing or malformed")?;
        let modifier = pk::recover_modifier(kek, &elements.encrypted_modifier)
            .ok_or("SAE-PK: Modifier recovery (AES-SIV) failed")?;
        let (ele_ap, ele_sta, sca_ap, sca_sta) = sae.sae_pk_transcript();
        let verification = pk::ApVerification {
            ssid: ssid.as_bytes(),
            password,
            modifier: &modifier,
            public_key_der: &elements.public_key_der,
            key_auth: &elements.key_auth,
            ele_ap: &ele_ap,
            ele_sta: &ele_sta,
            sca_ap: &sca_ap,
            sca_sta: &sca_sta,
            ap_bssid: &self.management_addresses().1,
            sta_mac: &self.management_addresses().0,
        };
        if pk::authenticate_ap(&verification) {
            Ok(())
        } else {
            Err("SAE-PK AP authentication failed")
        }
    }

    pub async fn send(&mut self, hw: &mut Hardware, ethernet: &[u8]) -> Result<(), &'static str> {
        if !self.authorized {
            return Err("controlled port closed");
        }
        self.send_ethernet(hw, ethernet, self.security.is_some())
            .await
    }

    pub fn enqueue(&mut self, hw: &mut Hardware, ethernet: &[u8]) -> Result<(), &'static str> {
        if !self.authorized {
            return Err("controlled port closed");
        }
        self.enqueue_for_ac(hw, ethernet, None)
    }

    pub fn enqueue_for_ac(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
        ac: Option<usize>,
    ) -> Result<(), &'static str> {
        if self.try_enqueue_for_ac(hw, ethernet, ac)? {
            Ok(())
        } else {
            Err("TX queue full")
        }
    }

    pub(super) fn try_enqueue_for_ac(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
        ac: Option<usize>,
    ) -> Result<bool, &'static str> {
        self.try_enqueue_assisted(hw, ethernet, ac, 0)
    }

    /// `assist` is the checksum `offload_assist` from `csum::prepare_tx`
    /// for this already-prepared Ethernet frame.
    pub(super) fn try_enqueue_assisted(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
        ac: Option<usize>,
        assist: u32,
    ) -> Result<bool, &'static str> {
        if !self.authorized {
            return Err("controlled port closed");
        }
        if self.power_pending {
            return Ok(false);
        }
        let (queue, frame, header) = self.ethernet_frame(ethernet, self.security.is_some(), ac)?;
        if !hw.transmit_space(queue)? {
            return Ok(false);
        }
        match hw.enqueue_transmit_assisted(queue, &frame, header, None, assist) {
            Err(super::six_ghz_station::UPDATE_REQUIRED | super::p2p_client::UPDATE_REQUIRED) => {
                return Ok(false)
            }
            result => result?,
        }
        self.sequence = self.sequence.wrapping_add(1);
        Ok(true)
    }

    fn replay_for(&mut self, queue: usize) -> &mut frame_api::Replay {
        if queue == 0 {
            &mut self.replay
        } else {
            &mut self.extra_rx[queue - 1].replay
        }
    }
    fn windows_for(
        &mut self,
        queue: usize,
    ) -> &mut [Option<super::aggregation::Window>; super::aggregation::MAX_TIDS] {
        if queue == 0 {
            &mut self.rx_ba
        } else {
            &mut self.extra_rx[queue - 1].ba
        }
    }
    fn windows(&self) -> impl Iterator<Item = &super::aggregation::Window> {
        self.rx_ba
            .iter()
            .chain(self.extra_rx.iter().flat_map(|rx| rx.ba.iter()))
            .flatten()
    }
    fn windows_mut(&mut self) -> impl Iterator<Item = &mut super::aggregation::Window> {
        self.rx_ba
            .iter_mut()
            .chain(self.extra_rx.iter_mut().flat_map(|rx| rx.ba.iter_mut()))
            .flatten()
    }
    fn ba_expired(&self, tid: usize, now: u64) -> bool {
        // One native BA session spans the physical queues. Reorder holes
        // remain per queue, while any queue's valid traffic refreshes the
        // session's inactivity timeout.
        let mut windows = self
            .windows()
            .filter(|window| usize::from(window.tid) == tid);
        windows.next().is_some_and(|first| first.expired(now))
            && windows.all(|window| window.expired(now))
    }
    pub(super) fn maintenance_pending(&self) -> bool {
        self.power_pending
            || self.six.as_ref().is_some_and(|six| six.pending())
            || self.client.as_ref().is_some_and(|client| client.pending())
            || self.amsdu_memory_pending()
            || self.active_request.is_some()
            || !self.actions.is_empty()
            || (0..super::aggregation::MAX_TIDS)
                .any(|tid| self.ba_expired(tid, narf_time::now_cycles()))
    }

    fn ethernet_frame(
        &self,
        ethernet: &[u8],
        protected: bool,
        requested_ac: Option<usize>,
    ) -> Result<(u16, Vec<u8>, usize), &'static str> {
        let (own, peer) = self.management_addresses();
        let (ac, frame, header) = if let Some(qos) = &self.qos {
            let ac = requested_ac
                .map_or_else(|| qos.classify(ethernet), |ac| qos.admitted(ac))
                .ok_or("no admitted access category")?;
            (
                ac,
                frame_api::transmit_qos(
                    own,
                    peer,
                    self.sequence,
                    ethernet,
                    protected,
                    super::qos::TIDS[ac],
                ),
                26,
            )
        } else {
            (
                1,
                frame_api::transmit(own, peer, self.sequence, ethernet, protected),
                24,
            )
        };
        Ok((
            self.data_queues[ac].ok_or("missing data queue")?,
            frame.ok_or("invalid Ethernet frame")?,
            header,
        ))
    }

    async fn send_ethernet(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
        protected: bool,
    ) -> Result<(), &'static str> {
        self.service_power(hw).await?;
        let (queue, frame, header) = self.ethernet_frame(ethernet, protected, None)?;
        self.sequence = self.sequence.wrapping_add(1);
        hw.transmit(queue, &frame, header, None).await
    }

    pub async fn receive(
        &mut self,
        hw: &mut Hardware,
        mpdu: &scan_api::Mpdu<'_>,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        if !self.admits_channel(mpdu) || !self.admits_data_header(mpdu) {
            return Ok(None);
        }
        let Some((local, peer)) = self.data_addresses(mpdu) else {
            return Ok(None);
        };
        if !self.authorized && mpdu.frame.first() == Some(&0x80) {
            self.receive_frame(mpdu)?;
            self.service_power(hw).await?;
            return Ok(None);
        }
        if !self.authorized {
            // Closed-port ordinary data must not consume PN even when it is
            // buffered beside a genuine initial EAPOL message.
            let Some(ethernet) = frame_api::receive(
                mpdu,
                local,
                peer,
                self.security.is_some(),
                &mut self.replay.clone(),
            ) else {
                return Ok(None);
            };
            if ethernet.get(12..14) != Some(&[0x88, 0x8e]) {
                return Ok(None);
            }
        }
        let Some(ethernet) = self.receive_frame(mpdu)? else {
            return Ok(None);
        };
        if ethernet[12..14] == [0x88, 0x8e] {
            self.handle_eapol(hw, &ethernet).await?;
            return Ok(None);
        }
        Ok(self.authorized.then_some(ethernet))
    }

    /// Reorder raw authenticated MPDUs before advancing CCMP packet numbers.
    /// This runs in both the executor pump and nonblocking network drain.
    pub fn receive_packet(
        &mut self,
        packet: &super::runtime::Packet,
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        Ok(self
            .receive_packet_checked(packet, None)?
            .into_iter()
            .map(|(frame, _)| frame)
            .collect())
    }

    /// As [`Self::receive_packet`], also reporting the hardware checksum
    /// verdict for a directly delivered (unreordered, non-A-MSDU) MPDU.
    /// `includes_snap` is `Hardware::rx_checksum_includes_snap`.
    pub fn receive_packet_checked(
        &mut self,
        packet: &super::runtime::Packet,
        includes_snap: Option<bool>,
    ) -> Result<Vec<(Vec<u8>, narf_net::RxMeta)>, &'static str> {
        let mut output = Vec::new();
        let queue = usize::from(packet.receive_queue);
        if queue > self.extra_rx.len() {
            return Err("Sc packet belongs to an unowned physical RFH queue");
        }
        if queue != 0 && !self.authorized {
            return Ok(output);
        }
        self.amsdu_feedback(packet);
        if packet.header.group_id != 0 {
            if self.mld.is_some() {
                self.mlo_notification(packet)?;
            }
            return Ok(output);
        }
        if self.mlo_select.scan_running
            && matches!(
                packet.header.cmd,
                super::sc_emlsr::SCAN_START_NOTIF | super::sc_emlsr::SCAN_COMPLETE_NOTIF
            )
        {
            let now = now_ms();
            if packet.header.cmd == super::sc_emlsr::SCAN_START_NOTIF {
                self.mlo_select.scan_started(&packet.payload, now);
            } else if self.mlo_select.scan_completed(&packet.payload) {
                self.select_links(now);
            }
            return Ok(output);
        }
        if packet.receive_epoch != Some(self.receive_epoch)
            && (matches!(packet.header.cmd, 0xc2 | 0xc3)
                || packet.header.cmd == 0xc1
                    && scan_api::mpdu(&packet.payload)
                        .is_some_and(|m| m.frame.first().is_some_and(|fc| fc & 12 == 8)))
        {
            return Ok(output);
        }
        let now = narf_time::now_cycles();
        match packet.header.cmd {
            0xc1 => {
                let Some(mpdu) = scan_api::mpdu(&packet.payload) else {
                    return Ok(output);
                };
                if self.mlo_select.scan_running {
                    self.observe_mlo_beacon(&mpdu);
                }
                if !self.admits_channel(&mpdu) {
                    return Ok(output);
                }
                let Some((local, peer)) = self.data_addresses(&mpdu) else {
                    return Ok(output);
                };
                let frame = mpdu.frame;
                if queue != 0 {
                    // The configured RSS classes hash IP flows. Multicast,
                    // management and EAPOL stay on fallback0 and cannot acquire per-RSS PN
                    // ownership by appearing in an additional physical ring.
                    if frame.len() < 24 || frame[0] & 12 != 8 || frame[4..10] != self.local {
                        return Ok(output);
                    }
                    let mut replay = self.replay_for(queue).clone();
                    let Some(ethernet) = frame_api::receive(
                        &mpdu,
                        local,
                        peer,
                        self.security.is_some(),
                        &mut replay,
                    ) else {
                        return Ok(output);
                    };
                    if ethernet.get(12..14) == Some(&[0x88, 0x8e]) {
                        return Ok(output);
                    }
                }
                if !self.admits_data_header(&mpdu) {
                    return Ok(output);
                }
                if frame.len() >= 24 && frame[0] & 12 == 8 {
                    self.count_mpdu(queue, mpdu.raw_fw_link, false);
                }
                if frame.len() >= 24
                    && frame[0] == 0xd0
                    && frame[1] & 0x87 == 0
                    && frame[22] & 15 == 0
                    && frame[4..10] == local
                    && frame[10..16] == peer
                    && frame[16..22] == peer
                    && self.authorized
                {
                    if let Some(body) = super::sc_security::robust_unicast_body(
                        &mpdu,
                        self.pmf_negotiated || self.mfp_active,
                        &mut self.management_pn,
                    ) {
                        let block_ack =
                            self.phy.mode != 0 && super::aggregation::action(body).is_some();
                        let sa_query =
                            self.pmf_negotiated && body.len() == 4 && body[..2] == [8, 0];
                        if (block_ack || sa_query) && self.actions.len() < 16 {
                            self.actions.push_back(body.to_vec());
                        }
                    }
                    return Ok(output);
                }
                if frame.len() >= 26 && frame[0] == 0x88 && frame[4] & 1 == 0 {
                    let baid = ((mpdu.reorder >> 24) & 127) as u8;
                    if baid != 127 && self.phy.mode != 0 {
                        // An unauthenticated frame cannot advance the BA window
                        // on a secured BSS. Replay state stays unchanged here.
                        if (self.security.is_some() && frame[1] & 0x40 == 0)
                            || frame_api::receive(
                                &mpdu,
                                local,
                                peer,
                                self.security.is_some(),
                                &mut self.replay_for(queue).clone(),
                            )
                            .is_none()
                        {
                            return Ok(output);
                        }
                        if let Some(window) = self
                            .windows_for(queue)
                            .iter_mut()
                            .flatten()
                            .find(|w| w.baid == baid)
                        {
                            let released = window.push(&packet.payload, now);
                            self.deliver_reordered(queue, released, &mut output)?;
                        }
                        return Ok(output);
                    }
                }
                if let Some(frame) = self.receive_frame_on(&mpdu, queue)? {
                    // FH_RSCSR_RPA_EN: v3 descriptor `raw_xsum` (big-endian,
                    // offset 32) is valid (`iwl_mld_rx_csum`).
                    let meta = match includes_snap {
                        Some(snap)
                            if packet.header.len_n_flags & super::csum::RSCSR_RPA_EN != 0
                                && !mpdu.amsdu
                                && packet.payload.len() >= 34 =>
                        {
                            super::csum::rx_meta_complete(
                                u16::from_be_bytes([packet.payload[32], packet.payload[33]]),
                                snap,
                                &frame,
                            )
                        }
                        _ => narf_net::RxMeta::default(),
                    };
                    output.push((frame, meta));
                }
            }
            0xc3 if packet.payload.len() == 4 => {
                let baid = packet.payload[0];
                let nssn = u16::from_le_bytes(packet.payload[2..4].try_into().unwrap());
                if let Some(window) = self
                    .windows_for(queue)
                    .iter_mut()
                    .flatten()
                    .find(|w| w.baid == baid)
                {
                    let released = window.release(nssn, now);
                    self.deliver_reordered(queue, released, &mut output)?;
                }
            }
            0xc2 if packet.payload.len() == 8 => {
                let sta_tid = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
                let info = u32::from_le_bytes(packet.payload[4..8].try_into().unwrap());
                if sta_tid & 0x1f0 == 0 {
                    if let Some(window) = self
                        .windows_for(queue)
                        .get_mut((sta_tid & 15) as usize)
                        .and_then(Option::as_mut)
                    {
                        if window.baid == ((info >> 24) & 63) as u8 {
                            let released = window.release((info & 4095) as u16, now);
                            self.deliver_reordered(queue, released, &mut output)?;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(output)
    }

    fn deliver_reordered(
        &mut self,
        queue: usize,
        packets: Vec<Vec<u8>>,
        output: &mut Vec<(Vec<u8>, narf_net::RxMeta)>,
    ) -> Result<(), &'static str> {
        for packet in packets {
            if let Some(mpdu) = scan_api::mpdu(&packet) {
                if let Some(frame) = self.receive_frame_on(&mpdu, queue)? {
                    // Reordered copies no longer carry len_n_flags.
                    output.push((frame, narf_net::RxMeta::default()));
                }
            }
        }
        Ok(())
    }

    pub fn reorder_tick(&mut self) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut output = Vec::new();
        let now = narf_time::now_cycles();
        for queue in 0..=self.extra_rx.len() {
            for tid in 0..super::aggregation::MAX_TIDS {
                if let Some(window) = &mut self.windows_for(queue)[tid] {
                    let packets = window.tick(now);
                    self.deliver_reordered(queue, packets, &mut output)?;
                }
            }
        }
        Ok(output.into_iter().map(|(frame, _)| frame).collect())
    }

    fn check_six_pending(&self, hw: &mut Hardware) -> Result<(), &'static str> {
        if self.six.is_some() || self.mld.is_some() {
            hw.poll()?;
            if let Some(six) = &self.six {
                match six.check_pending(hw) {
                    Ok(()) | Err(super::six_ghz_station::UPDATE_REQUIRED) => {}
                    Err(reason) => return Err(reason),
                }
            }
            if let Some(mld) = &self.mld {
                mld.check_pending(hw)?;
            }
        }
        Ok(())
    }

    async fn service_power(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        hw.service_p2p_client().await?;
        self.check_six_pending(hw)?;
        hw.service_six_power().await?;
        // The association link's power names FWlink0; while a primary-link
        // switch has it inactive the update waits for its restoration.
        if !self.power_pending || self.association_key_mask().is_none() {
            return Ok(());
        }
        if self.power_inflight {
            return Err("MLD AP power command still owns an uncertain receipt");
        }
        let domain = hw.current_policy_domain()?;
        let ceiling = self.regulatory.ceiling(&domain)?;
        let power = i16::from(ceiling).min(
            self.ap_power_limit
                .ok_or("MLD AP power update has no bound")?,
        ) as i8;
        if power == self.regulatory.power() {
            self.power_pending = false;
            return Ok(());
        }
        let command = station_api::tx_power(
            hw.version(1, 0x9f).ok_or("missing native AP power ABI")?.0,
            power,
        )?;
        self.regulatory.reserve_power(power);
        self.power_inflight = true;
        let result = async {
            let receipt = hw.command(1, 0x9f, &command).await?;
            if !receipt.payload.is_empty() {
                return Err("unexpected native AP power receipt");
            }
            hw.source_fence()?.invoke(|| {
                self.regulatory.commit_power(power);
                Ok(())
            })
        }
        .await;
        if let Err(reason) = result {
            self.authorized = false;
            hw.fail();
            return Err(reason);
        }
        self.power_inflight = false;
        self.power_pending = false;
        Ok(())
    }

    pub async fn service_aggregation(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        use super::aggregation::{self, Action};
        self.service_power(hw).await?;
        if !self.authorized {
            self.actions.clear();
            self.active_request = None;
            return Ok(());
        }
        self.service_link_selection(hw).await?;
        self.service_active_links(hw).await?;
        self.prepare_amsdu_memory(hw).await?;
        while let Some(body) = self.actions.pop_front() {
            // 802.11w SA Query Request: echo the authenticated transaction
            // identifier in a protected response under the live pairwise key
            // (mac80211 rx.c ieee80211_process_sa_query_req).
            if self.pmf_negotiated && body.len() == 4 && body[..2] == [8, 0] {
                let frame = self.management(0xd0, &[8, 1, body[2], body[3]]);
                hw.transmit(self.management_queue, &frame, 24, self.rate())
                    .await?;
                continue;
            }
            match aggregation::action(&body) {
                Some(Action::Add {
                    token,
                    tid,
                    window,
                    ssn,
                    timeout,
                    immediate,
                }) => {
                    let mut status = 37; // decline delayed BA and unsupported TIDs
                    if immediate && (tid as usize) < self.rx_ba.len() && self.phy.mode != 0 {
                        let existing = self.rx_ba[tid as usize].as_ref();
                        if existing.is_some_and(|w| w.uncertain()) {
                            return Err("RX BAID still owns uncertain response/removal");
                        }
                        if existing.is_some_and(|old| {
                            old.token == token
                                && old.start == ssn
                                && old.size == window
                                && old.timeout == timeout
                        }) {
                            status = 0; // retransmission: preserve buffered data/PN
                        } else {
                            if existing.is_some() {
                                self.stop_rx_ba(hw, tid).await?;
                            }
                            // Allocate host storage before publishing the FW command.
                            let mut states = Vec::with_capacity(1 + self.extra_rx.len());
                            for _ in 0..=self.extra_rx.len() {
                                let mut state = aggregation::Window::new(
                                    0,
                                    tid,
                                    token,
                                    ssn,
                                    window,
                                    timeout,
                                    narf_time::now_cycles(),
                                )?;
                                state.reserve_response();
                                states.push(state);
                            }
                            let response = hw
                                .command(5, 0x16, &aggregation::allocate(tid, ssn, window))
                                .await?;
                            if response.payload.len() != 4 {
                                return Err("invalid BAID allocation response");
                            }
                            let baid =
                                u32::from_le_bytes(response.payload[..4].try_into().unwrap());
                            if baid >= 32
                                || self
                                    .rx_ba
                                    .iter()
                                    .flatten()
                                    .any(|old| old.baid as u32 == baid)
                            {
                                return Err("firmware reused/returned invalid BAID");
                            }
                            for (queue, mut state) in states.into_iter().enumerate() {
                                state.baid = baid as u8;
                                self.windows_for(queue)[tid as usize] = Some(state);
                            }
                            status = 0;
                        }
                    }
                    let response = aggregation::add_response(token, tid, window, timeout, status);
                    self.service_power(hw).await?;
                    let frame = self.management(0xd0, &response);
                    hw.transmit(self.management_queue, &frame, 24, self.rate())
                        .await?;
                    if status == 0 {
                        for queue in 0..=self.extra_rx.len() {
                            self.windows_for(queue)[tid as usize]
                                .as_mut()
                                .ok_or("RX BAID response lost physical queue reservation")?
                                .activate_response(narf_time::now_cycles())?;
                        }
                    }
                }
                Some(Action::Delete {
                    tid,
                    originator: true,
                }) if (tid as usize) < self.rx_ba.len() => {
                    self.stop_rx_ba(hw, tid).await?;
                }
                _ => {} // firmware owns the TX BA session, including DELBA
            }
        }
        for tid in 0..self.rx_ba.len() {
            if self.ba_expired(tid, narf_time::now_cycles()) {
                self.stop_rx_ba(hw, tid as u8).await?;
                self.service_power(hw).await?;
                let frame = self.management(0xd0, &aggregation::delete(tid as u8));
                hw.transmit(self.management_queue, &frame, 24, self.rate())
                    .await?;
            }
        }
        Ok(())
    }

    async fn stop_rx_ba(&mut self, hw: &mut Hardware, tid: u8) -> Result<(), &'static str> {
        if let Some(window) = self.rx_ba[tid as usize].as_ref() {
            let baid = window.baid;
            for queue in 0..=self.extra_rx.len() {
                let window = self.windows_for(queue)[tid as usize]
                    .as_mut()
                    .ok_or("RX BAID lost physical queue reservation")?;
                if window.baid != baid {
                    return Err("RX BAID physical queue binding changed");
                }
                window.reserve_retirement()?;
            }
            let receipt = hw
                .command(5, 0x16, &super::aggregation::remove(tid))
                .await?;
            // fw/api/datapath.h uses a status-sized BAID response also for
            // REMOVE; Linux ignores its ADD-only BAID value, not its extent.
            if receipt.payload.len() != 4 {
                return Err("invalid BAID removal receipt extent");
            }
            let management = hw.synchronize_rx_baid(baid).await?;
            for packet in management {
                // Bound AP loss/changed PHY/PMF controls must not disappear
                // merely because they preceded a native retirement marker.
                let _ = self.receive_packet(&packet)?;
            }
            for queue in 0..=self.extra_rx.len() {
                self.windows_for(queue)[tid as usize] = None;
            }
        }
        Ok(())
    }

    fn discard_reorder(&mut self) {
        for window in self.windows_mut() {
            window.discard();
        }
    }

    /// Keep original +HTC bytes and CCMP IV offsets. A HE control field
    /// requires the actual response-bound HTC_HE profile; it cannot enter
    /// the BA reorder owner first and acquire that permission later.
    fn admits_data_header(&self, mpdu: &scan_api::Mpdu<'_>) -> bool {
        let frame = mpdu.frame;
        if frame.first().is_none_or(|fc| fc & 15 != 8) {
            return true;
        }
        // A further link's data is admitted against that link's own
        // negotiated PHY/HE/EHT facts.
        let further = self.receiving_further(mpdu);
        let (phy, he, eht) = match further {
            Some(link) => (link.negotiated_phy(), link.he(), link.eht()),
            None => (&self.phy, self.he, self.eht.as_deref()),
        };
        if frame.len() < 24
            || self.six.is_some() && !matches!((mpdu.rate_n_flags >> 8) & 7, 1 | 4 | 5)
            || !phy.admits_wide_rx(self.local_phy, mpdu.rate_n_flags)
            || (mpdu.rate_n_flags >> 8) & 7 >= 5
                && eht.is_none_or(|eht| !eht.admits_rx_rate(mpdu.rate_n_flags))
            || (mpdu.rate_n_flags >> 8) & 7 == 4
                && he.is_none_or(|he| !he.admits_rx_rate(mpdu.rate_n_flags))
        {
            return false;
        }
        if frame[1] & 0x80 == 0 {
            return true;
        }
        frame[0] == 0x88
            && he.is_some_and(|he| he.negotiation.htc_he())
            && frame.get(26..30).is_some_and(|control| control[0] & 3 == 3)
    }

    pub fn receive_frame(
        &mut self,
        mpdu: &scan_api::Mpdu<'_>,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        self.receive_frame_on(mpdu, 0)
    }
    fn receive_frame_on(
        &mut self,
        mpdu: &scan_api::Mpdu<'_>,
        queue: usize,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let frame = mpdu.frame;
        if !self.admits_channel(mpdu) || !self.admits_data_header(mpdu) {
            return Ok(None);
        }
        let Some((local, peer)) = self.data_addresses(mpdu) else {
            return Ok(None);
        };
        if let Some(mld) = &self.mld {
            mld.confirm_mpdu_beacon(mpdu)?;
            // mlme.c ieee80211_mgd_update_bss_param_ch_cnt per receiving link.
            if frame[0] == 0x80 && frame.len() >= 24 && frame[10..16] == peer {
                if let (Some(link), Some(ies)) = (
                    mld.receiving_link(mpdu),
                    mpdu.body(24, 0).and_then(|body| body.get(12..)),
                ) {
                    let valid = self.mld_valid_links() | 1 << mld.association().spec_link;
                    self.emlsr.update_bss_param(link, ies, valid);
                    // mlme.c ieee80211_process_adv_ttlm with the beacon TSF.
                    let tsf = u64::from_le_bytes(
                        mpdu.body(24, 0)
                            .and_then(|body| body.get(..8))
                            .and_then(|tsf| tsf.try_into().ok())
                            .unwrap_or([0; 8]),
                    );
                    if self.ttlm.process(ies, tsf, now_ms())
                        == super::sc_emlsr::TtlmAction::Disconnect
                    {
                        self.authorized = false;
                        return Err("invalid advertised TID-to-link mapping");
                    }
                }
            }
        }
        if frame.len() >= 24 && frame[10..16] == peer && frame[16..22] == peer {
            if frame[0] == 0x80 && self.receiving_further(mpdu).is_some() {
                // A further active link's beacon was proven above against
                // its own spec link; the association link's PHY/power facts
                // are not compared with another link's operation. Any
                // active link's beacon keeps the host beacon monitor alive
                // (iwl mld sets CONNECTION_MONITOR; per-link loss is the
                // firmware's MISSED_BEACONS_NOTIF).
                self.last_beacon = narf_time::now_cycles();
            } else if frame[0] == 0x80 {
                if let Some(six) = &self.six {
                    let result = mpdu
                        .body(24, 0)
                        .and_then(|body| body.get(12..))
                        .ok_or("invalid associated6GHz beacon")
                        .and_then(|ies| six.confirm(ies));
                    if let Err(reason) = result {
                        self.authorized = false;
                        return Err(reason);
                    }
                } else {
                    if let Some(body) = mpdu.body(24, 0) {
                        if let Some(ies) = body.get(12..) {
                            let capabilities = u16::from_le_bytes([body[10], body[11]]);
                            if let Ok(Some(power)) = super::mld_power::ap_limit_in_ies(
                                ies,
                                capabilities,
                                self.beacon.channel,
                            ) {
                                if self.ap_power_limit != Some(power) {
                                    self.ap_power_limit = Some(power);
                                    self.power_pending = true;
                                }
                            }
                            // Missing/invalid later AP data never clears an
                            // already programmed restriction (Linux's no-change).
                        }
                    }
                    if self.phy.mode != 0 {
                        let body = mpdu.body(24, 0).ok_or("invalid associated beacon")?;
                        let ies = body.get(12..).ok_or("short associated beacon")?;
                        // Live channel/PHY changes require reassociation. Stop TX
                        // immediately if the AP's current operating constraints no
                        // longer match the programmed width, MCS or protection.
                        if self.phy.confirm(
                            self.local_phy,
                            ies,
                            ies,
                            self.beacon.channel,
                            self.qos.is_some(),
                        )? != self.phy
                            || self.he.is_some_and(|he| !he.matches(ies))
                            || self.eht.as_ref().is_some_and(|eht| {
                                !eht.matches(
                                    ies,
                                    self.he.as_ref().unwrap().negotiation.peer_capability(),
                                )
                            })
                        {
                            self.authorized = false;
                            return Err("AP changed PHY operation; reassociation required");
                        }
                    }
                }
                self.last_beacon = narf_time::now_cycles();
            }
            if matches!(frame[0], 0xa0 | 0xc0)
                && (frame[4..10] == local || frame[4..10] == [0xff; 6])
            {
                // 802.11w: once MFP is active a deauth/disassoc must be
                // authentic, else it is dropped instead of tearing the link
                // down — this is the forged-broadcast-deauth DoS defense.
                if self.pmf_negotiated || self.mfp_active {
                    if frame[4] & 1 == 1 {
                        // Group-addressed robust mgmt frame: require a valid
                        // BIP MMIE signed by the AP's IGTK.
                        if frame[1] & 0xc7 != 0 || frame[22] & 15 != 0 || mpdu.amsdu {
                            return Ok(None);
                        }
                        let Some(body) = mpdu.body(24, 0).filter(|body| body.len() == 20) else {
                            return Ok(None);
                        };
                        // A further link's group management uses that
                        // link's own IGTK and replay floor.
                        let store = match self.further_group_link(mpdu, queue) {
                            Some(index) => &mut self.mld_links[index].mfp,
                            None => &mut self.mfp,
                        };
                        if narf_wireless::mfp::verify_inbound(store, &frame[..24], body).is_err() {
                            return Ok(None);
                        }
                    } else if super::sc_security::robust_unicast_body(
                        mpdu,
                        true,
                        &mut self.management_pn,
                    )
                    .is_none_or(|body| body.len() != 2)
                    {
                        // A Protected bit alone is not an integrity verdict;
                        // require station0 CCM MIC success and an advancing PN.
                        return Ok(None);
                    }
                } else if super::sc_security::robust_unicast_body(
                    mpdu,
                    false,
                    &mut self.management_pn,
                )
                .is_none_or(|body| body.len() != 2)
                {
                    return Ok(None);
                }
                self.authorized = false;
                return Err("AP disconnected");
            }
        }
        let secure = self.security.is_some();
        let received = match self.further_group_link(mpdu, queue) {
            Some(index) => {
                self.replay
                    .swap_group(&mut self.mld_links[index].group_replay);
                let received = frame_api::receive(mpdu, local, peer, secure, &mut self.replay);
                self.replay
                    .swap_group(&mut self.mld_links[index].group_replay);
                received
            }
            None => frame_api::receive(mpdu, local, peer, secure, self.replay_for(queue)),
        };
        let Some(ethernet) = received else {
            return Ok(None);
        };
        if self.mld.is_some() && ethernet.get(12..14) == Some(&[0x88, 0x8e]) {
            self.mld_eapol
                .retain(|(epoch, _)| *epoch == self.receive_epoch);
            if self.mld_eapol.len() >= 16 {
                return Ok(None);
            }
            let mut hash = narf_crypto::sha256::Sha256::new();
            hash.update(&ethernet);
            self.mld_eapol
                .push_back((self.receive_epoch, hash.finalize()));
        }
        Ok(Some(ethernet))
    }

    /// The active further link whose own group replay table checks this
    /// group-addressed MPDU: mac80211 looks a group frame's key up on the
    /// receiving link (`rx->link->gtk[idx]`, rx.c) with that key's own RX
    /// PN. Group data stays on fallback queue0.
    fn further_group_link(&self, mpdu: &scan_api::Mpdu<'_>, queue: usize) -> Option<usize> {
        let mld = self.mld.as_ref()?;
        if queue != 0 || mpdu.frame.get(4).is_none_or(|addr1| addr1 & 1 == 0) {
            return None;
        }
        let link = mld.receiving_link(mpdu)?;
        if link == mld.association().spec_link {
            return None;
        }
        self.mld_links
            .iter()
            .position(|valid| valid.link_id() == link && valid.active.is_some())
    }

    /// Pairwise SEC_KEY STA mask: every active link STA.
    fn pairwise_mask(&self) -> u32 {
        self.mld.as_ref().map_or(1, |mld| mld.sta_mask())
    }

    /// A pending `ieee80211_cqm_beacon_loss_notify` from the firmware's
    /// missed-beacon report, consumed by the device's nl80211 event.
    pub(super) fn take_cqm_beacon_loss(&mut self) -> bool {
        core::mem::take(&mut self.emlsr.cqm_beacon_loss)
    }

    /// The public multi-link view of this association (sme.c
    /// `__cfg80211_connect_result` with `valid_links`): the AP MLD, the
    /// association link and every requested further link in link-id
    /// order, accepted ones with their negotiated chandef and rejected
    /// ones with their status. `None` for a non-MLD association.
    pub fn mlo_report(&self) -> Option<narf_wireless::MloConnection> {
        let mld = self.mld.as_ref()?;
        let association = mld.association();
        let mut links = alloc::vec![narf_wireless::MloLink {
            link_id: association.spec_link,
            address: association.own_link,
            bssid: association.peer_link,
            status: 0,
            channel: Some(link_channel(
                self.beacon.band,
                self.beacon.channel,
                &self.phy
            )),
        }];
        for valid in &self.mld_links {
            links.push(narf_wireless::MloLink {
                link_id: valid.link_id(),
                address: valid.context.own_link(),
                bssid: valid.context.peer_link(),
                status: 0,
                channel: Some(link_channel(
                    valid.beacon.band,
                    valid.beacon.channel,
                    valid.negotiated_phy(),
                )),
            });
        }
        for (link_id, address, bssid, status) in &self.mld_rejected {
            links.push(narf_wireless::MloLink {
                link_id: *link_id,
                address: *address,
                bssid: *bssid,
                status: *status,
                channel: None,
            });
        }
        links.sort_unstable_by_key(|link| link.link_id);
        Some(narf_wireless::MloConnection {
            ap_mld: mld.context.peer_mld(),
            assoc_link_id: association.spec_link,
            links,
        })
    }

    /// The accepted further links' MLD Link IDs (valid links).
    pub fn mld_valid_links(&self) -> u16 {
        self.mld_links
            .iter()
            .fold(0, |mask, link| mask | 1 << link.link_id())
    }

    /// The currently active Link IDs (association link plus any further).
    pub fn mld_active_links(&self) -> u16 {
        self.mld.as_ref().map_or(0, |mld| mld.active_links())
    }

    /// mlo.h `iwl_mld_vif_has_emlsr_cap` for this association: authorized,
    /// our request advertised IWL_MLD_EMLSR_CAPA and the AP MLD's response
    /// advertised EMLSR. Admitted Sc/Bz profiles are never CDB.
    pub(super) fn emlsr_capable(&self) -> bool {
        super::sc_emlsr::capable(
            self.authorized,
            self.client.is_none(),
            self.mld_eml_advertised(),
            self.ap_eml,
            false,
        )
    }

    /// Whether our association request carried EMLSR capabilities: only a
    /// multiple-link request does (see `sc_security::Profile::negotiate_links`).
    fn mld_eml_advertised(&self) -> bool {
        self.mld.is_some() && !self.mld_links.is_empty()
    }

    /// The spec link of an owned firmware link (`iwl_mld_fw_id_to_link_conf`).
    fn spec_of_fw_link(&self, fw_link: u32) -> Option<u8> {
        let binding = self.mld.as_ref()?;
        core::iter::once(binding.primary())
            .chain(binding.secondary())
            .find(|owner| u32::from(owner.fw_link) == fw_link)
            .map(|owner| owner.spec_link)
    }

    /// MLO firmware notifications (mld/notif.c): MISSED_BEACONS_NOTIF
    /// (link.c `iwl_mld_handle_missed_beacon_notif`), ESR_MODE_NOTIF and
    /// EMLSR_TRANS_FAIL_NOTIF (mlo.c). A connection loss is an error so the
    /// device performs its ordinary bounded stop; a requested single link
    /// is applied by maintenance (`ieee80211_set_active_links_async`). A
    /// notification of the wrong size is dropped, as notif.c's size check.
    fn mlo_notification(&mut self, packet: &super::runtime::Packet) -> Result<(), &'static str> {
        use super::sc_emlsr::{self, MissedBeacons, TransitionFailure};
        let key = (packet.header.group_id, packet.header.cmd);
        let now_ms = narf_time::wall::monotonic_ns() / 1_000_000;
        let capable = self.emlsr_capable();
        let payload = &packet.payload;
        let mut emlsr = self.emlsr;
        let request = if key == sc_emlsr::MISSED_BEACONS_NOTIF {
            match emlsr.missed_beacons(payload, |fw| self.spec_of_fw_link(fw), now_ms) {
                Ok(MissedBeacons::Disconnect) => return Err("MLD beacon loss"),
                Ok(MissedBeacons::Keep(set)) => Some(set),
                Ok(MissedBeacons::Rescan) => {
                    // link.c: not in EMLSR and the link is not heard:
                    // try to switch to a better link.
                    if self.multi_link() {
                        self.mlo_select.scan_requested = true;
                    }
                    None
                }
                _ => None,
            }
        } else if key == sc_emlsr::ESR_MODE_NOTIF {
            emlsr
                .mode_notification(payload, capable, now_ms)
                .ok()
                .flatten()
        } else if key == sc_emlsr::STATISTICS_OPER_NOTIF {
            // stats.c iwl_mld_process_per_phy_stats over existing PHYs.
            if let Ok(loads) = sc_emlsr::per_phy_loads(payload) {
                let phys = self.active_phy_ids();
                self.mlo_select.measure.update_phys(&loads, &phys);
            }
            None
        } else if key == sc_emlsr::EMLSR_TRANS_FAIL_NOTIF {
            match emlsr.transition_failure(payload, |fw| self.spec_of_fw_link(fw), now_ms) {
                Ok(TransitionFailure::Disconnect) => return Err("MLD EMLSR transition failure"),
                Ok(TransitionFailure::Keep(set)) => Some(set),
                _ => None,
            }
        } else {
            None
        };
        self.emlsr = emlsr;
        if request.is_some() {
            self.active_request = request;
        }
        Ok(())
    }

    /// Firmware PHY ids with a channel context: the association link's
    /// PHY0 and an active further link's PHY.
    fn active_phy_ids(&self) -> Vec<u8> {
        let mut phys = Vec::new();
        if self.mld.as_ref().is_none_or(|mld| mld.association_active()) {
            phys.push(0u8);
        }
        phys.extend(
            self.mld_links
                .iter()
                .filter_map(|l| l.active.map(|(_, p)| p)),
        );
        phys
    }

    /// A periodic scan owns the firmware scan slot (no internal MLO scan
    /// starts); conversely `mlo_scan_running` refuses a periodic start.
    pub(super) fn set_scheduled_scan_busy(&mut self, busy: bool) {
        self.mlo_select.scheduled_busy = busy;
    }
    pub(super) fn mlo_scan_running(&self) -> bool {
        self.mlo_select.scan_running
    }

    /// Whether this association can select links: a native MLD with at
    /// least one further valid link (`hweight16(valid_links) > 1`).
    fn multi_link(&self) -> bool {
        self.mld.is_some() && !self.mld_links.is_empty() && self.client.is_none()
    }

    /// sta.c `iwl_mld_count_mpdu_rx`/`_tx` for the AP MLD station (Linux
    /// keeps MPDU counters only for an MLO connection). Crossing the TPT
    /// threshold while blocked unblocks EMLSR (`unblock_tpt_wk`), which
    /// requests an internal MLO scan once nothing else blocks.
    fn count_mpdu(&mut self, queue: usize, fw_link: u8, tx: bool) {
        if !self.multi_link() || !self.emlsr_capable() {
            return;
        }
        let blocked = self.emlsr.blocked & super::sc_emlsr::blocked::TPT != 0;
        let now = now_ms();
        if self
            .mlo_select
            .measure
            .count_mpdus(queue, fw_link, 1, tx, blocked, now)
            && self.emlsr.unblock(super::sc_emlsr::blocked::TPT, true)
        {
            self.mlo_select.scan_requested = true;
        }
    }

    /// Record an affiliated AP's beacon received while the internal MLO
    /// scan runs: its signal and BSS Load feed `iwl_mld_get_link_grade`.
    fn observe_mlo_beacon(&mut self, mpdu: &scan_api::Mpdu<'_>) {
        let frame = mpdu.frame;
        if frame.len() < 36 || !matches!(frame[0], 0x80 | 0x50) {
            return;
        }
        let Some(binding) = self.mld.as_ref() else {
            return;
        };
        let bssid = &frame[16..22];
        let association = binding.association();
        let spec_link =
            if bssid == association.peer_link && mpdu.channel == association.channel.number {
                association.spec_link
            } else if let Some(link) = self
                .mld_links
                .iter()
                .find(|l| l.beacon.bssid == bssid && l.channel().number == mpdu.channel)
            {
                link.link_id()
            } else {
                return;
            };
        let util = mpdu
            .body(24, 0)
            .and_then(|body| body.get(12..))
            .and_then(super::sc_emlsr::bss_load_channel_util);
        self.mlo_select.observe(super::sc_emlsr::Seen {
            spec_link,
            signal_dbm: mpdu.rssi,
            util,
        });
    }

    /// mlo.c `_iwl_mld_select_links` after an internal MLO scan: grade
    /// every valid link seen since that scan started (link.c
    /// `iwl_mld_get_link_grade`), pick the best single link or EMLSR pair
    /// and request it (`ieee80211_set_active_links_async`).
    fn select_links(&mut self, now: u64) {
        use super::sc_emlsr::{self, Candidate};
        if !self.authorized || !self.multi_link() || !self.mlo_select.fresh(now) {
            return;
        }
        let Some(binding) = self.mld.as_ref() else {
            return;
        };
        let association = *binding.association();
        let association_phy = binding.association_active().then_some(0u8);
        let active = self.mld_active_links();
        let mut candidates = Vec::new();
        for seen in &self.mlo_select.seen {
            if self.ttlm.dormant & (1 << seen.spec_link) != 0 {
                continue;
            }
            let (channel, phy, phy_id) = if seen.spec_link == association.spec_link {
                (association.channel, &self.phy, association_phy)
            } else if let Some(valid) = self
                .mld_links
                .iter()
                .find(|l| l.link_id() == seen.spec_link && l.keys.is_some())
            {
                (
                    valid.channel(),
                    valid.negotiated_phy(),
                    valid.active.map(|(_, phy)| phy),
                )
            } else {
                continue;
            };
            let width_mhz = 20u32 << phy.width.min(3);
            let center = if phy.center == 0 {
                channel
            } else {
                super::native_band::Channel {
                    band: channel.band,
                    number: phy.center,
                }
            };
            let measure = &self.mlo_select.measure;
            let by_us = phy_id.map_or(0, |p| measure.load_by_us[usize::from(p)]);
            let chan_load = sc_emlsr::chan_load(channel.band, seen.util, by_us);
            // Punctured EHT operation is refused at admission (shared
            // association/eht.rs), so no accepted link is punctured.
            let Some(grade) = sc_emlsr::link_grade(
                channel.band,
                width_mhz,
                i32::from(seen.signal_dbm),
                chan_load,
                0,
            ) else {
                continue;
            };
            candidates.push(Candidate {
                spec_link: seen.spec_link,
                band: channel.band,
                primary_mhz: channel.frequency(),
                center_mhz: center.frequency(),
                width_mhz,
                signal_dbm: seen.signal_dbm,
                // Channel switch announcements are not followed natively.
                csa_active: false,
                grade,
                chan_load,
                active: active & (1 << seen.spec_link) != 0,
                load_not_by_us: phy_id.map_or(0, |p| measure.avg_not_by_us[usize::from(p)]),
            });
        }
        // BT coexistence notifications are not consumed and no low-latency
        // classification exists: BT is treated as inactive.
        let capable = self.emlsr_capable();
        if let Some(selection) = self.emlsr.select(&candidates, capable, false, false) {
            self.active_request = Some(selection.active);
        }
    }

    /// Link-selection maintenance: the authorized-station setup
    /// (mac80211.c BSS_CHANGED_ASSOC clear + periodic statistics,
    /// AUTHORIZED's TPT block), EMLSR prevention expiry, the periodic TPT
    /// check and starting a requested internal MLO scan.
    async fn service_link_selection(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        use super::sc_emlsr::{self, TptCheck};
        if !self.multi_link() || hw.is_mvm89() {
            return Ok(());
        }
        let now = now_ms();
        let capable = self.emlsr_capable();
        if !self.mlo_select.authorized_setup {
            self.mlo_select.authorized_setup = true;
            let (group, cmd) = sc_emlsr::SYSTEM_STATISTICS_CMD;
            hw.command(group, cmd, &sc_emlsr::stats_command(true, false))
                .await?;
            hw.command(group, cmd, &sc_emlsr::stats_command(false, true))
                .await?;
            if let Some(set) = self.emlsr.block(
                sc_emlsr::blocked::TPT,
                self.emlsr.primary_link(),
                capable,
                now,
            ) {
                self.active_request = Some(set);
            }
        }
        if self.emlsr.prevention_tick(capable, now) {
            self.mlo_select.scan_requested = true;
        }
        if self.emlsr.blocked & sc_emlsr::blocked::TPT == 0 && capable {
            let due = *self
                .mlo_select
                .next_tpt_ms
                .get_or_insert(now + sc_emlsr::MLO_SCAN_FRESH_MS);
            if now >= due {
                self.mlo_select.next_tpt_ms = Some(now + sc_emlsr::MLO_SCAN_FRESH_MS);
                let secondary = self
                    .mld
                    .as_ref()
                    .and_then(|b| b.secondary())
                    .map(|owner| owner.fw_link);
                match self
                    .emlsr
                    .check_tpt(&mut self.mlo_select.measure, secondary, capable, now)
                {
                    TptCheck::Block(set) | TptCheck::Exit(set) => self.active_request = Some(set),
                    TptCheck::Continue => {}
                }
            }
        } else {
            self.mlo_select.next_tpt_ms = None;
        }
        if !self.mlo_select.may_start_scan(now) {
            return Ok(());
        }
        let Some(binding) = self.mld.as_ref() else {
            return Ok(());
        };
        let primary = *binding.primary();
        // iwl_mld_int_mlo_scan scans the usable (non-dormant) links.
        let mut channels = Vec::new();
        if self.ttlm.dormant & (1 << binding.association().spec_link) == 0 {
            channels.push(binding.association().channel);
        }
        for link in &self.mld_links {
            if link.keys.is_some()
                && self.ttlm.dormant & (1 << link.link_id()) == 0
                && !channels.contains(&link.channel())
            {
                channels.push(link.channel());
            }
        }
        if channels.is_empty() {
            self.mlo_select.scan_requested = false;
            return Ok(());
        }
        let version = hw.version(1, 0xd).ok_or("scan command version absent")?.0;
        let body = sc_emlsr::Selector::scan_body(version, &channels, primary.fw_link)?;
        self.mlo_select.scan_requested = false;
        self.mlo_select.scan_running = true;
        self.mlo_select.scan_started_ms = None;
        hw.command(1, 0xd, &body).await?;
        Ok(())
    }

    /// Apply a pending active-link set (mac80211
    /// `_ieee80211_set_active_links`, iwl mld at most two active links).
    /// Every named link must be valid and hold its keys: the association
    /// link, or an accepted further link with its MLO GTK. A set naming
    /// only a further link is a primary-link switch: that link is added
    /// (if inactive) and then the association link is deactivated, as
    /// mac80211 adds new links before releasing removed ones; the
    /// association link later returns with its fixed identity and retained
    /// facts. When adding would exceed two links, removal goes first.
    /// TX is drained around each change.
    async fn service_active_links(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        self.service_ttlm()?;
        let Some(target) = self.active_request.take() else {
            return Ok(());
        };
        let Some(binding) = self.mld.clone() else {
            return Ok(());
        };
        let association = binding.association().spec_link;
        // ieee80211_vif_usable_links: dormant links cannot be activated.
        let usable = self
            .mld_links
            .iter()
            .filter(|valid| valid.keys.is_some())
            .fold(1u16 << association, |mask, valid| {
                mask | 1 << valid.link_id()
            })
            & !self.ttlm.dormant;
        let current = binding.active_links();
        if target == 0
            || target & !usable != 0
            || target.count_ones() as usize > super::sc_mlo::MAX_ACTIVE_LINKS
            || target == current
            || !self.authorized
            || target & (1 << association) == 0 && self.mld_association.is_none()
        {
            return Ok(());
        }
        let add = target & !current;
        let remove = current & !target;
        let remove_first =
            (current.count_ones() + add.count_ones()) as usize > super::sc_mlo::MAX_ACTIVE_LINKS;
        if remove_first {
            self.remove_links(hw, remove).await?;
        }
        for link in (0..15u8).filter(|link| add & (1 << link) != 0) {
            if link == association {
                self.restore_association_link(hw).await?;
            } else {
                self.activate_mld_link(hw, link).await?;
            }
        }
        if !remove_first {
            self.remove_links(hw, remove).await?;
        }
        Ok(())
    }

    /// mlme.c `ieee80211_tid_to_link_map_work`/`ieee80211_ttlm_set_links`
    /// when an advertised mapping's switch time arrives: links outside the
    /// map become dormant; active links keep only mapped ones, else the
    /// lowest usable link serves. No mapped valid link disconnects.
    fn service_ttlm(&mut self) -> Result<(), &'static str> {
        let Some(mld) = &self.mld else {
            return Ok(());
        };
        let valid = self.mld_valid_links() | 1 << mld.association().spec_link;
        let Some((active, dormant)) = self.ttlm.due(now_ms(), valid) else {
            return Ok(());
        };
        if active == 0 {
            self.authorized = false;
            return Err("advertised TID-to-link mapping maps no valid link");
        }
        let current = self.mld_active_links();
        if current != active {
            let mut keep = active & current;
            if keep == 0 {
                keep = 1 << (valid & !dormant).trailing_zeros();
            }
            self.active_request = Some(keep);
        }
        Ok(())
    }

    async fn remove_links(&mut self, hw: &mut Hardware, remove: u16) -> Result<(), &'static str> {
        let association = self
            .mld
            .as_ref()
            .ok_or("no native MLD association")?
            .association()
            .spec_link;
        for link in (0..15u8).filter(|link| remove & (1 << link) != 0) {
            if link == association {
                self.deactivate_association_link(hw).await?;
            } else {
                self.deactivate_mld_link(hw, link).await?;
            }
        }
        Ok(())
    }

    /// The association link's PHY/LINK/STA/power and TLC bodies for its
    /// fixed FWlink0/STA0/PHY0 identity, from the retained post-response
    /// bodies and its committed TX power (Linux mld/power.c
    /// `iwl_mld_set_tx_power` SET_LINK, v10/v11 only).
    fn association_further(
        &self,
        hw: &Hardware,
    ) -> Result<(super::sc_mlo::FurtherLink, [u8; 44]), &'static str> {
        let binding = self.mld.as_ref().ok_or("no native MLD association")?;
        let bodies = self
            .mld_association
            .ok_or("native MLD association link bodies absent")?;
        let owner = *binding.association();
        let version = hw.version(1, 0x9f).ok_or("missing TX power command")?.0;
        if !matches!(version, 10 | 11) {
            return Err("native MLD per-link TX power command absent");
        }
        let mut power = station_api::tx_power(version, self.regulatory.power())?;
        put32(&mut power, 4, u32::from(owner.fw_link));
        let mut tlc = bodies.tlc;
        put32(&mut tlc, 0, 1 << owner.station);
        Ok((
            super::sc_mlo::FurtherLink {
                owner,
                phy_id: 0,
                phy: bodies.phy,
                link: bodies.link,
                peer: bodies.peer,
                power,
            },
            tlc,
        ))
    }

    /// The association link's group keys (GTK 1..3 at their current RX PN
    /// floor, IGTKs at their BIP floor) for its link STA only
    /// (`iwl_mld_get_key_sta_mask`, installed by `ieee80211_key_switch_links`).
    fn association_group_keys(&self) -> Vec<super::sc_mlo::LinkKey<'_>> {
        let mut keys = Vec::new();
        for (id, key) in self.group_keys.iter().enumerate().skip(1) {
            if let Some(key) = key {
                keys.push(super::sc_mlo::LinkKey {
                    id: id as u8,
                    key,
                    rx_pn: self.replay.group[id].iter().copied().max().unwrap_or(0),
                });
            }
        }
        if self.mfp_active {
            for igtk in [&self.mfp.active, &self.mfp.next].into_iter().flatten() {
                keys.push(super::sc_mlo::LinkKey {
                    id: igtk.key_id as u8,
                    key: &igtk.key,
                    rx_pn: igtk.rx_pn,
                });
            }
        }
        keys
    }

    /// The STA mask the association link's group keys name, or None while
    /// the association link is inactive after a primary-link switch: its
    /// changed keys are then retained and installed when it returns.
    fn association_key_mask(&self) -> Option<u32> {
        match &self.mld {
            Some(mld) if !mld.association_active() => None,
            Some(mld) => Some(1 << mld.association().station),
            None => Some(1),
        }
    }

    fn baid_tids(&self) -> Vec<u8> {
        (0..self.rx_ba.len() as u8)
            .filter(|&tid| self.rx_ba[usize::from(tid)].is_some())
            .collect()
    }

    /// Deactivate the association link while a further link stays active
    /// (the primary-link switch's removal half): the same order as a
    /// further link's removal, with the association group keys removed from
    /// STA0. The association link stays valid with its keys and facts.
    async fn deactivate_association_link(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        let binding = self.mld.clone().ok_or("no native MLD association")?;
        if !binding.association_active() || binding.secondary().is_none() {
            return Err("native MLD association link cannot be deactivated now");
        }
        let (further, _) = self.association_further(hw)?;
        let group_ids: Vec<u8> = self.association_group_keys().iter().map(|k| k.id).collect();
        let baid_tids = self.baid_tids();
        let pairwise = self.pairwise_key.is_some().then_some(self.pmf_negotiated);
        hw.drain_transmits().await?;
        let next = super::sc_mlo::deactivate_further_link(
            hw, &binding, &further, pairwise, &baid_tids, &group_ids,
        )
        .await?;
        hw.install_mld_link(next.clone())?;
        self.mld = Some(next);
        self.emlsr
            .links_activated(self.mld_active_links(), now_ms());
        Ok(())
    }

    /// Restore the association link beside the active further link, with
    /// its fixed FWlink0/STA0/PHY0 identity, retained PHY/LINK/STA/TLC
    /// facts, committed power and current group keys.
    async fn restore_association_link(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        let binding = self.mld.clone().ok_or("no native MLD association")?;
        if binding.association_active() || binding.secondary().is_some() || hw.is_mvm89() {
            return Err("native MLD association link cannot be restored now");
        }
        let (further, tlc) = self.association_further(hw)?;
        let owner = further.owner;
        // The fixed ids must be free in the shared device pool.
        let mut ids = hw.mld_fw_ids()?;
        for active in binding.owners() {
            ids.claim(active.fw_link, active.station)?;
        }
        ids.claim(owner.fw_link, owner.station)?;
        if self
            .mld_links
            .iter()
            .any(|valid| valid.active.is_some_and(|(_, phy)| phy == further.phy_id))
        {
            return Err("native MLD association PHY0 is owned by another link");
        }
        let baid_tids = self.baid_tids();
        let pairwise = self.pairwise_key.is_some().then_some(self.pmf_negotiated);
        hw.drain_transmits().await?;
        let next = super::sc_mlo::activate_further_link(
            hw,
            &binding,
            &further,
            pairwise,
            &baid_tids,
            &self.association_group_keys(),
        )
        .await?;
        if let Err(error) = hw.station_tlc(&tlc).await {
            hw.fail();
            return Err(error);
        }
        hw.install_mld_link(next.clone())?;
        self.mld = Some(next);
        self.mlo_select.last_activation_ms = Some(now_ms());
        self.emlsr
            .links_activated(self.mld_active_links(), now_ms());
        Ok(())
    }

    /// Return to the association link alone (before disconnect): restore it
    /// if a primary-link switch removed it, then remove any further link.
    async fn restore_association_only(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        let Some(binding) = self.mld.clone() else {
            return Ok(());
        };
        if binding.association_only() {
            return Ok(());
        }
        if !binding.association_active() {
            self.restore_association_link(hw).await?;
        }
        let association = binding.association().spec_link;
        let further = self.mld_active_links() & !(1u16 << association);
        self.remove_links(hw, further).await
    }

    /// Adopt one further link's authenticated MLO GTK/IGTK. An inactive
    /// link keeps them for its activation (mac80211 installs keys of a
    /// link only when it becomes active, `ieee80211_key_switch_links`);
    /// an active link's changed keys are replaced on its link STA only.
    async fn adopt_link_keys(
        &mut self,
        hw: &mut Hardware,
        keys: security::LinkGroupKeys,
    ) -> Result<(), &'static str> {
        let index = self
            .mld_links
            .iter()
            .position(|link| link.link_id() == keys.link_id)
            .ok_or("MLD key delivery names an unknown link")?;
        if let Some((owner, _)) = self.mld_links[index].active {
            let old = self.mld_links[index].keys.as_ref();
            let mut installs = Vec::new();
            if old.is_none_or(|old| old.group != keys.group || old.group_id != keys.group_id) {
                installs.push((keys.group_id, &keys.group, keys.group_rx_pn));
            }
            if let Some((igtk, id, ipn)) = &keys.igtk {
                if old
                    .and_then(|old| old.igtk.as_ref())
                    .is_none_or(|(old, old_id, _)| old != igtk || old_id != id)
                {
                    installs.push((*id as u8, igtk, *ipn));
                }
            }
            hw.drain_transmits().await?;
            for (id, key, pn) in installs {
                let body = super::sc_security::key_command_for(
                    1 << owner.station,
                    id,
                    true,
                    false,
                    Some(key),
                    pn,
                )?;
                if !hw.command(5, 0x18, &body[..]).await?.payload.is_empty() {
                    hw.fail();
                    return Err("unexpected native per-link key receipt");
                }
            }
        }
        // A changed GTK adopts its authenticated floor in this link's own
        // replay table; an identical retransmission never resets it.
        if self.mld_links[index]
            .keys
            .as_ref()
            .is_none_or(|old| old.group != keys.group || old.group_id != keys.group_id)
        {
            self.mld_links[index]
                .group_replay
                .install(keys.group_id, keys.group_rx_pn);
        }
        // Likewise a changed IGTK adopts its authenticated IPN in this
        // link's own BIP store; an identical retransmission keeps the floor.
        if let Some((igtk, id, ipn)) = &keys.igtk {
            let link = &mut self.mld_links[index];
            if link
                .keys
                .as_ref()
                .and_then(|old| old.igtk.as_ref())
                .is_none_or(|(old, old_id, _)| old != igtk || old_id != id)
            {
                link.mfp
                    .install_active(*igtk, *id)
                    .map_err(|_| "invalid MLD further-link IGTK")?;
                if let Some(active) = link.mfp.active.as_mut() {
                    active.rx_pn = *ipn;
                }
            }
        }
        self.mld_links[index].keys = Some(keys);
        Ok(())
    }

    /// Activate one accepted further link (mac80211
    /// `_ieee80211_set_active_links` adding a link; iwl mld allows two
    /// active links). TX is drained first; the link's PHY/LINK/STA/power
    /// bodies come from its own negotiated facts, its group keys from its
    /// own MLO KDEs, and its link STA gets its own TLC configuration
    /// (`iwl_mld_config_tlc_link`). A device-visible failure fails the
    /// device.
    pub async fn activate_mld_link(
        &mut self,
        hw: &mut Hardware,
        link_id: u8,
    ) -> Result<(), &'static str> {
        let binding = self.mld.clone().ok_or("no native MLD association")?;
        let index = self
            .mld_links
            .iter()
            .position(|link| link.link_id() == link_id)
            .ok_or("native MLD link is not a valid accepted link")?;
        if !self.authorized
            || binding.secondary().is_some()
            || self.mld_links[index].active.is_some()
            || self.mld_links[index].keys.is_none()
            || hw.is_mvm89()
        {
            return Err("native MLD further link cannot be activated now");
        }
        // Every active owner's ids stay claimed (the shared device pool).
        let mut ids = hw.mld_fw_ids()?;
        for owner in binding.owners() {
            ids.claim(owner.fw_link, owner.station)?;
        }
        let (fw_link, station) = ids.allocate()?;
        let mut phys = hw.mld_phy_ids();
        for valid in &self.mld_links {
            if let Some((_, phy)) = valid.active {
                phys.claim(phy);
            }
        }
        let phy_id = phys.allocate()?;
        let valid = &self.mld_links[index];
        let owner = super::sc_mlo::LinkOwner {
            spec_link: link_id,
            fw_link,
            station,
            channel: valid.channel(),
            own_link: valid.context.own_link(),
            peer_link: valid.context.peer_link(),
        };
        let further = valid.further_link(hw, owner, phy_id)?;
        let tlc = valid.tlc(hw, station)?;
        let baid_tids = self.baid_tids();
        let pairwise = self.pairwise_key.is_some().then_some(self.pmf_negotiated);
        hw.drain_transmits().await?;
        let next = super::sc_mlo::activate_further_link(
            hw,
            &binding,
            &further,
            pairwise,
            &baid_tids,
            &valid.group_keys(),
        )
        .await?;
        if let Err(error) = hw.station_tlc(&tlc).await {
            hw.fail();
            return Err(error);
        }
        hw.install_mld_link(next.clone())?;
        self.mld = Some(next);
        self.mld_links[index].active = Some((owner, phy_id));
        self.mlo_select.last_activation_ms = Some(now_ms());
        self.emlsr
            .links_activated(self.mld_active_links(), now_ms());
        Ok(())
    }

    /// Deactivate an active further link, the inverse of
    /// `activate_mld_link`, while another link stays active; the link stays
    /// valid with its keys retained.
    pub async fn deactivate_mld_link(
        &mut self,
        hw: &mut Hardware,
        link_id: u8,
    ) -> Result<(), &'static str> {
        let binding = self.mld.clone().ok_or("no native MLD association")?;
        let index = self
            .mld_links
            .iter()
            .position(|link| link.link_id() == link_id && link.active.is_some())
            .ok_or("native MLD link is not active")?;
        let valid = &self.mld_links[index];
        let (owner, phy_id) = valid.active.ok_or("native MLD link is not active")?;
        let further = valid.further_link(hw, owner, phy_id)?;
        let group_ids: Vec<u8> = valid.group_keys().iter().map(|key| key.id).collect();
        let baid_tids = self.baid_tids();
        let pairwise = self.pairwise_key.is_some().then_some(self.pmf_negotiated);
        hw.drain_transmits().await?;
        let next = super::sc_mlo::deactivate_further_link(
            hw, &binding, &further, pairwise, &baid_tids, &group_ids,
        )
        .await?;
        hw.install_mld_link(next.clone())?;
        self.mld = Some(next);
        self.mld_links[index].active = None;
        self.emlsr
            .links_activated(self.mld_active_links(), now_ms());
        Ok(())
    }

    pub async fn handle_eapol(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
    ) -> Result<(), &'static str> {
        let (local, peer) = self.management_addresses();
        if ethernet.len() < 14 || ethernet[..6] != local || ethernet[6..12] != peer {
            return Ok(());
        }
        if self.mld.is_some() {
            self.mld_eapol
                .retain(|(epoch, _)| *epoch == self.receive_epoch);
            let mut hash = narf_crypto::sha256::Sha256::new();
            hash.update(ethernet);
            let proof = (self.receive_epoch, hash.finalize());
            let Some(at) = self.mld_eapol.iter().position(|entry| *entry == proof) else {
                return Ok(());
            };
            self.mld_eapol.remove(at);
        }
        let Some(security) = self.security.as_mut() else {
            return Ok(());
        };
        // Unauthenticated EAPOL must not close an established port or
        // poison replay state. A missing valid response times out during
        // initial association; an established connection simply drops it.
        let mut response = match security.process(&ethernet[14..]) {
            Ok(response) => response,
            Err(reason) => {
                #[cfg(feature = "kernel-test")]
                {
                    use core::fmt::Write;
                    let _ = writeln!(narf_console::Writer, "Sc rejected EAPOL: {reason}");
                }
                #[cfg(not(feature = "kernel-test"))]
                let _ = reason;
                return Ok(());
            }
        };
        // Each further link's MLO GTK/IGTK belongs to that link alone.
        let link_keys = response
            .keys
            .as_mut()
            .map(|keys| core::mem::take(&mut keys.links))
            .unwrap_or_default();
        let igtk_changed = response
            .keys
            .as_ref()
            .and_then(|keys| keys.igtk.as_ref())
            .is_some_and(|(material, id, _)| {
                self.mfp
                    .find_by_key_id(*id)
                    .is_none_or(|old| old.key != *material)
            });
        if let Some(keys) = &response.keys {
            let validated = (|| {
                if keys.group_id > 3
                    || keys
                        .igtk
                        .as_ref()
                        .is_some_and(|(_, id, pn)| !(4..=5).contains(id) || *pn >= 1 << 48)
                {
                    return Err("invalid MLD authenticated key identity/replay floor");
                }
                let candidates = [
                    keys.pairwise
                        .as_ref()
                        .filter(|key| self.pairwise_key.as_ref() != Some(*key)),
                    (self.group_keys[usize::from(keys.group_id)] != Some(keys.group))
                        .then_some(&keys.group),
                    keys.igtk
                        .as_ref()
                        .filter(|_| igtk_changed)
                        .map(|(material, _, _)| material),
                ];
                self.key_history.reserve(candidates)?;
                for link in &link_keys {
                    let valid = self
                        .mld_links
                        .iter()
                        .find(|valid| valid.link_id() == link.link_id)
                        .ok_or("MLD key delivery names an unknown link")?;
                    if link.group_id > 3
                        || link
                            .igtk
                            .as_ref()
                            .is_some_and(|(_, id, pn)| !(4..=5).contains(id) || *pn >= 1 << 48)
                    {
                        return Err("invalid MLD further-link key identity/replay floor");
                    }
                    let old = valid.keys.as_ref();
                    self.key_history.reserve([
                        old.is_none_or(|old| old.group != link.group)
                            .then_some(&link.group),
                        link.igtk
                            .as_ref()
                            .filter(|(new, _, _)| {
                                old.and_then(|old| old.igtk.as_ref())
                                    .is_none_or(|(old, _, _)| old != new)
                            })
                            .map(|(material, _, _)| material),
                        None,
                    ])?;
                }
                Ok(())
            })();
            if let Err(reason) = validated {
                self.authorized = false;
                hw.fail();
                return Err(reason);
            }
        }
        let changed = response.keys.as_ref().is_some_and(|keys| {
            keys.pairwise
                .as_ref()
                .is_some_and(|key| self.pairwise_key.as_ref() != Some(key))
                || self.group_keys[keys.group_id as usize] != Some(keys.group)
                || igtk_changed
        });
        let mld_pairwise_rekey = self.mld.is_some()
            && self.authorized
            && self.pairwise_key.is_some()
            && response
                .keys
                .as_ref()
                .is_some_and(|keys| keys.pairwise.is_some());
        if changed {
            self.receive_epoch = hw.close_receive_epoch()?;
            self.discard_reorder();
            self.actions.clear();
        }
        let mut reply = Vec::new();
        reply.extend_from_slice(&peer);
        reply.extend_from_slice(&local);
        reply.extend_from_slice(&[0x88, 0x8e]);
        reply.extend_from_slice(&response.bytes);
        if mld_pairwise_rekey {
            // The new KCK authenticates M4, but its outer DATA MPDU still
            // belongs to the old packet key. Do not retire that key before
            // the exact native TX receipt proves M4 terminal delivery.
            self.send_ethernet(hw, &reply, true).await?;
        }
        let mut pending_igtk = None;
        if let Some(keys) = response.keys {
            if let Some(pairwise) = keys.pairwise.as_ref() {
                if self.pairwise_key.as_ref() != Some(pairwise) {
                    hw.drain_transmits().await?;
                    if self.pairwise_key.is_some() {
                        remove_key(hw, self.pairwise_mask(), 0, false, self.pmf_negotiated).await?;
                    }
                    install_key(
                        hw,
                        self.pairwise_mask(),
                        0,
                        false,
                        self.pmf_negotiated,
                        pairwise,
                        0,
                    )
                    .await?;
                    if let Some(old) = &mut self.pairwise_key {
                        old.zeroize();
                    }
                    self.pairwise_key = Some(*pairwise);
                    self.replay.reset_pairwise();
                    for rx in &mut self.extra_rx {
                        rx.replay.reset_pairwise();
                    }
                    self.management_pn = 0;
                    self.discard_reorder();
                }
            }
            let id = keys.group_id as usize;
            // Authenticated group-message retransmissions may carry a
            // higher EAPOL replay counter with the SAME GTK. Reinstalling
            // it would reset firmware/host packet numbers (KRACK).
            if self.group_keys[id] != Some(keys.group) {
                // An association link a primary-link switch deactivated
                // keeps its new GTK for its restoration.
                if let Some(mask) = self.association_key_mask() {
                    if self.group_keys[id].is_some() {
                        remove_key(hw, mask, keys.group_id, true, self.pmf_negotiated).await?;
                    }
                    install_key(
                        hw,
                        mask,
                        keys.group_id,
                        true,
                        self.pmf_negotiated,
                        &keys.group,
                        keys.group_rx_pn,
                    )
                    .await?;
                }
                if let Some(old) = &mut self.group_keys[id] {
                    old.zeroize();
                }
                self.group_keys[id] = Some(keys.group);
                self.replay.group[id].fill(keys.group_rx_pn);
                self.replay.group_valid[id] = true;
                self.replay.reset_subframes();
                for rx in &mut self.extra_rx {
                    rx.replay.reset_subframes();
                }
                self.discard_reorder();
            }
            // New IGTKs are native keys too. Adopt the authenticated KDE
            // floor only after its receipt and the native ordered RX marker.
            // Identical material never reinstalls/reset its replay counters.
            if let Some((igtk, key_id, ipn)) = keys.igtk.as_ref().filter(|_| igtk_changed) {
                let (key_id, ipn) = (*key_id, *ipn);
                let material = Zeroizing::new(*igtk);
                if !(4..=5).contains(&key_id) {
                    return Err("invalid IGTK key index");
                }
                if let Some(mask) = self.association_key_mask() {
                    if self.mfp.find_by_key_id(key_id).is_some() {
                        remove_key(hw, mask, key_id as u8, true, true).await?;
                    }
                    install_key(hw, mask, key_id as u8, true, true, &material, ipn).await?;
                }
                pending_igtk = Some((material, key_id, ipn));
            }
        }
        if pending_igtk.is_some() {
            self.open_receive_epoch(hw).await?;
        }
        if let Some((material, key_id, ipn)) = pending_igtk {
            // This slot is about to be replaced by the previous active key.
            // The shared BIP store has plain arrays, so retire its old bytes
            // explicitly before rotating the two native station slots.
            if let Some(old) = &mut self.mfp.next {
                old.key.zeroize();
            }
            self.mfp
                .install_active(*material, key_id)
                .map_err(|_| "invalid IGTK key index")?;
            self.mfp.active.as_mut().unwrap().rx_pn = ipn;
            self.mfp_active = true;
            // Key adoption and controlled-port publication are separate
            // boundaries. Close capture again before held M4 TX so ordinary
            // packets copied while the port is closed can never acquire the
            // post-M4 epoch. The final marker below proves that boundary.
            self.receive_epoch = hw.close_receive_epoch()?;
        }
        for keys in link_keys {
            self.adopt_link_keys(hw, keys).await?;
        }
        // Initial M2/M4 are plaintext; later replies use the installed PTK.
        if !mld_pairwise_rekey {
            self.send_ethernet(hw, &reply, self.authorized).await?;
        }
        if changed {
            self.open_receive_epoch(hw).await?;
        }
        Ok(())
    }

    async fn open_receive_epoch(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        for packet in hw.synchronize_receive_epoch().await? {
            // Ordered peer-loss/PHY/PMF controls remain effective; only old
            // data/reorder notifications are discarded before the marker.
            let _ = self.receive_packet(&packet)?;
        }
        hw.commit_receive_epoch(self.receive_epoch)
    }

    /// Append a BIP-CMAC-128 MMIE to a group-addressed robust management
    /// frame body and stamp its MIC/IPN under the active IGTK (802.11w TX,
    /// §12.5.4). This is the transmit counterpart to the inbound MMIE
    /// verification in `receive_frame`. A station never emits group-addressed
    /// robust management frames, so this is exercised by tests and is the
    /// hook an AP/mesh-mode send path would call; `hdr_24` is the frame's
    /// 24-byte management header, `body` its in-progress body.
    pub fn protect_group_mgmt(
        &mut self,
        hdr_24: &[u8],
        body: &mut Vec<u8>,
    ) -> Result<u64, &'static str> {
        if !self.mfp_active {
            return Err("management-frame protection is not active");
        }
        let igtk = self.mfp.active.as_mut().ok_or("no active IGTK installed")?;
        narf_wireless::mfp::protect_outbound(igtk, hdr_24, body).map_err(|_| "BIP protect failed")
    }

    pub(in crate::iwlwifi) async fn p2p_management(
        &mut self,
        hw: &mut Hardware,
        request: &narf_wireless::MgmtTxRequest,
    ) -> Result<bool, &'static str> {
        let client = self
            .client
            .as_ref()
            .ok_or("P2P client management lacks actual completed role")?;
        client.current()?;
        if !self.authorized
            || !hw
                .p2p_client_native()
                .is_some_and(|current| alloc::sync::Arc::ptr_eq(&current, client))
        {
            return Err("P2P client management lacks its exact current native port");
        }
        let mut frame = client.plan.management(request)?;
        self.service_power(hw).await?;
        frame[22..24].copy_from_slice(&((self.sequence & 4095) << 4).to_le_bytes());
        self.sequence = self.sequence.wrapping_add(1);
        match hw
            .transmit(self.management_queue, &frame, 24, self.rate())
            .await
        {
            Ok(()) => Ok(true),
            Err(super::runtime::TX_FAILED) => Ok(false),
            Err(reason) => Err(reason),
        }
    }
    pub async fn disconnect(mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        self.authorized = false;
        hw.close_receive_epoch()?;
        // The teardown below names the association link's FWlink0/STA0/PHY0:
        // first return to that link alone.
        self.restore_association_only(hw).await?;
        for tid in 0..self.rx_ba.len() {
            self.stop_rx_ba(hw, tid as u8).await?;
        }
        hw.drain_transmits().await?;
        self.service_power(hw).await?;
        let mfp_active = self.mfp_active;
        let mut frame = self.management(0xa0, &3u16.to_le_bytes());
        if mfp_active {
            // 802.11w: the individually-addressed disassoc is a robust mgmt
            // frame — set the Protected bit so firmware CCMP-encrypts it
            // under the installed pairwise key before transmit.
            frame[1] |= 0x40;
        }
        let _ = hw
            .transmit(self.management_queue, &frame, 24, self.rate())
            .await;
        let mac = match &self.client {
            Some(client) => client.mac(2, None, client.desired())?,
            None => station_api::mac(2, self.local, None),
        };
        hw.command(3, 8, &mac).await?;
        hw.remove_tx(self.management_queue, 0, 15).await?;
        for (index, queue) in self.data_queues.iter().enumerate() {
            if let Some(queue) = queue {
                hw.remove_tx(*queue, 0, super::qos::TIDS[index]).await?;
            }
        }
        hw.command(3, 0xc, &[0; 4]).await?;
        hw.command(
            3,
            9,
            &station_api::link_channel(
                2,
                self.local,
                false,
                super::native_band::Channel {
                    band: self.beacon.band,
                    number: self.beacon.channel,
                },
                0,
                1,
            ),
        )
        .await?;
        // A second inactive update detaches phy_id after deactivation.
        hw.command(
            3,
            9,
            &station_api::link_channel(
                2,
                self.local,
                false,
                super::native_band::Channel {
                    band: self.beacon.band,
                    number: self.beacon.channel,
                },
                0,
                1,
            ),
        )
        .await?;
        hw.station_phy(
            &station_api::phy_channel(
                3,
                super::native_band::Channel {
                    band: self.beacon.band,
                    number: self.beacon.channel,
                },
            ),
            self.beacon.channel,
        )
        .await?;
        if self.client.is_some() {
            hw.restore_p2p_client_default().await?;
        }
        if self.mld.is_some() {
            // Restore the ordinary inactive default only after every
            // station/queue and PHY owner reached its terminal removal.
            hw.command(
                3,
                9,
                &station_api::link(3, self.local, false, self.beacon.channel, 0, 1),
            )
            .await?;
            hw.command(
                3,
                9,
                &station_api::link(1, self.local, false, self.beacon.channel, 0, 1),
            )
            .await?;
        }
        Ok(())
    }
}

/// Extract the opaque anti-clogging token from an AP's SAE Commit rejection
/// (status 76). H2E carries it in an Anti-Clogging Token Container element
/// (ID 255, ext 93); legacy SAE used a bare inline field. Returns the token
/// value to echo back on the retry.
fn extract_anti_clogging_token(body: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if body.len() >= 3 && body[0] == 0xff && body[2] == 93 {
        let len = body[1] as usize;
        if len >= 1 && body.len() >= 2 + len {
            return Some(body[3..2 + len].to_vec());
        }
        return None;
    }
    (!body.is_empty()).then(|| body.to_vec())
}

/// `sta_mask`: the pairwise key spans every active link STA; the
/// association link's group keys name only STA0 (`iwl_mld_get_key_sta_mask`).
async fn remove_key(
    hw: &mut Hardware,
    sta_mask: u32,
    id: u8,
    group: bool,
    pmf: bool,
) -> Result<(), &'static str> {
    super::sc_security::key_command(id, group, pmf, None, 0)?;
    let body = super::sc_security::key_command_for(sta_mask, id, group, pmf, None, 0)?;
    let receipt = hw.command(5, 0x18, &body[..]).await?;
    if !receipt.payload.is_empty() {
        return Err("unexpected native key-removal receipt");
    }
    Ok(())
}

async fn install_key(
    hw: &mut Hardware,
    sta_mask: u32,
    id: u8,
    group: bool,
    pmf: bool,
    key: &[u8; 16],
    rx_pn: u64,
) -> Result<(), &'static str> {
    if hw.version(5, 0x18).map(|v| v.0) != Some(1) {
        return Err("unsupported security key command");
    }
    super::sc_security::key_command(id, group, pmf, None, 0)?;
    let body = super::sc_security::key_command_for(sta_mask, id, group, pmf, Some(key), rx_pn)?;
    let receipt = hw.command(5, 0x18, &body[..]).await?;
    if !receipt.payload.is_empty() {
        return Err("unexpected native key-install receipt");
    }
    Ok(())
}

/// Firmware permission is refreshed once per scan/association operation.
pub(super) async fn regulatory_channels_in_domain(
    hw: &mut Hardware,
    domain: &narf_wireless::reg::RegulatoryDomain,
) -> Result<super::mld_regulatory::Mcc, &'static str> {
    let version = hw
        .version(1, 0xc8)
        .map(|v| v.1)
        .ok_or("missing regulatory response")?;
    if !(version == 8 || hw.is_mvm89() && matches!(version, 5 | 6)) {
        return Err("unsupported regulatory response");
    }
    let mut body = [0; 28];
    put16(&mut body, 0, u16::from_be_bytes(domain.country_code));
    body[2] = 2; // MCC_SOURCE_BIOS
    let response = hw.command(1, 0xc8, &body).await?;
    if version == 8 {
        super::mld_regulatory::Mcc::parse(&response.payload)
    } else {
        super::mld_regulatory::Mcc::parse_version(version, &response.payload)
    }
}

/// Host policy is intersected with firmware permission, with the lowest
/// matching power ceiling. NO_IR closes all host TX/association; probes also
/// reject DFS. Every intersecting restriction applies, including a narrower
/// restrictive rule overlapping an otherwise permissive covering rule.
pub(super) fn channel_power(
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: u8,
    firmware: &[u32],
    probe: bool,
) -> Option<i8> {
    let flags = *firmware.get(station_api::channel_index(channel)?)?;
    if flags & 5 != 5 || (probe && (flags & (1 << 3) == 0 || flags & (1 << 4) != 0)) {
        return None;
    }
    host_channel_power(domain, channel, probe)
}

/// Host-only preflight; it cannot replace the current NVM/MCC permission
/// checked by channel_power before any transmit-capable firmware transition.
pub(super) fn host_channel_power(
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: u8,
    probe: bool,
) -> Option<i8> {
    station_api::channel_index(channel)?;
    let frequency = if channel == 14 {
        2484
    } else if channel <= 13 {
        2407 + 5 * channel as u32
    } else {
        5000 + 5 * channel as u32
    };
    let mut power = None;
    let low = frequency.saturating_sub(10);
    let high = frequency + 10;
    let mut covering = false;
    for rule in &domain.rules {
        if rule.freq_end_mhz <= low || rule.freq_start_mhz >= high {
            continue;
        }
        if rule.freq_end_mhz <= rule.freq_start_mhz
            || rule.max_bandwidth_mhz < 20
            || rule.flags.contains(narf_wireless::reg::RegFlags::NO_IR)
            || probe && rule.flags.contains(narf_wireless::reg::RegFlags::DFS)
        {
            return None;
        }
        covering |= rule.freq_start_mhz <= low && rule.freq_end_mhz >= high;
        power = Some(power.map_or(rule.max_power_dbm, |old: i8| old.min(rule.max_power_dbm)));
    }
    covering.then_some(power).flatten()
}

/// `struct cfg80211_chan_def` of a link from its negotiated native PHY:
/// legacy mode is 20_NOHT, else the TLC width (20/40/80/160 MHz) around
/// the negotiated centre channel. No puncturing or 320 MHz is negotiated.
fn link_channel(
    band: super::native_band::Band,
    primary: u8,
    phy: &super::ht_vht::Negotiated,
) -> narf_wireless::LinkChannel {
    use super::native_band::Channel;
    let frequency_mhz = Channel {
        band,
        number: primary,
    }
    .frequency();
    let (width, center) = match phy.width {
        _ if phy.mode == 0 => (0, primary),
        0 => (1, primary),
        1 => (2, phy.center),
        2 => (3, phy.center),
        _ => (5, phy.center),
    };
    narf_wireless::LinkChannel {
        frequency_mhz,
        width,
        center_freq1_mhz: Channel {
            band,
            number: center,
        }
        .frequency(),
        center_freq2_mhz: 0,
    }
}

/// Every occupied 20 MHz subchannel and the full spectral span must be
/// allowed by both policies. A primary-channel permission is insufficient.
pub(super) fn channel_power_width(
    domain: &narf_wireless::reg::RegulatoryDomain,
    primary: u8,
    width: u8,
    center: u8,
    firmware: &[u32],
) -> Option<i8> {
    if width == 0 {
        return (primary == center)
            .then(|| channel_power(domain, primary, firmware, false))
            .flatten();
    }
    if width > 3 || primary == 14 || (width >= 2 && primary <= 14) {
        return None;
    }
    let offsets: &[i16] = if width == 1 {
        &[-2, 2]
    } else if width == 2 {
        &[-6, -2, 2, 6]
    } else {
        if ![50, 114, 163].contains(&center) {
            return None;
        }
        &[-14, -10, -6, -2, 2, 6, 10, 14]
    };
    let mut power = i8::MAX;
    let mut contains_primary = false;
    for offset in offsets {
        let channel = u8::try_from(i16::from(center) + offset).ok()?;
        if (channel <= 14) != (primary <= 14) || channel == 14 {
            return None;
        }
        contains_primary |= channel == primary;
        let flags = *firmware.get(station_api::channel_index(channel)?)?;
        if flags & (1 << (8 + width)) == 0 {
            return None;
        }
        power = power.min(channel_power(domain, channel, firmware, false)?);
    }
    if !contains_primary {
        return None;
    }
    let mhz = 20u32 << width;
    let frequency = if primary <= 14 { 2407 } else { 5000 } + 5 * u32::from(center);
    let mut span_power = None;
    let low = frequency - mhz / 2;
    let high = frequency + mhz / 2;
    let mut covering = false;
    for rule in &domain.rules {
        if rule.freq_end_mhz <= low || rule.freq_start_mhz >= high {
            continue;
        }
        if rule.freq_end_mhz <= rule.freq_start_mhz
            || rule.max_bandwidth_mhz < mhz
            || rule.flags.contains(narf_wireless::reg::RegFlags::NO_IR)
        {
            return None;
        }
        covering |= rule.freq_start_mhz <= low && rule.freq_end_mhz >= high;
        span_power =
            Some(span_power.map_or(rule.max_power_dbm, |old: i8| old.min(rule.max_power_dbm)));
    }
    covering.then_some(power.min(span_power?))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "connection_tests.rs"]
mod tests;

#[path = "connection_tx_amsdu.rs"]
pub(super) mod tx_amsdu;

/// Boot-time monotonic milliseconds for EMLSR timing.
fn now_ms() -> u64 {
    narf_time::wall::monotonic_ns() / 1_000_000
}
