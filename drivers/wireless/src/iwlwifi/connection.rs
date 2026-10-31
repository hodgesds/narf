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
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn open_model() -> Self {
        Self {
            beacon: Beacon {
                bssid: [4; 6],
                ssid: Vec::new(),
                channel: 1,
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
                widths: super::gen3_wire::Widths {
                    forty: true,
                    eighty: true,
                    one_sixty: true,
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
        mut local_phy: super::ht_vht::Local,
        roam_from: Option<[u8; 6]>,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Self, &'static str> {
        // Reserve before any native await. Neither old notifications nor
        // descriptors copied while this port is closed belong to the new key.
        let receive_epoch = hw.close_receive_epoch()?;
        hw.prepare_receive_queues().await?;
        let secure = !matches!(auth, AuthMethod::Open);
        let mut profile = super::sc_security::Profile::negotiate(&beacon, local, &auth, local_phy)?;
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
        let permissions = regulatory_channels_in_domain(hw, domain).await?;
        let original_local = local_phy;
        // Rebuild the shared offer with the native owner's current width
        // limit. A forbidden160 span retains a genuine HE/VHT80 fallback;
        // an unbounded shared160 offer cannot relabel that narrower program.
        if !permissions.widths.permits(3)
            || ![50, 114, 163].into_iter().any(|center| {
                local_phy.permits160(center)
                    && channel_power_width(domain, beacon.channel, 3, center, &permissions.channels)
                        .is_some()
            })
        {
            local_phy.width160_channels = 0;
        }
        if local_phy.he && (!permissions.he_allowed || !super::sc_he::native_supported(hw)) {
            local_phy.he = false;
        }
        if local_phy != original_local {
            profile = super::sc_security::Profile::negotiate(&beacon, local, &auth, local_phy)?;
        }
        let phy = super::ht_vht::Negotiated::parse_with_offer(
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
        )?;
        let he_offer = profile
            .offer
            .filter(|offer| qos.is_some() && super::sc_he::matches_native(offer, &phy));
        if he_offer.is_none() && profile.offer.is_some_and(|offer| offer.he().is_some()) {
            local_phy.he = false;
            profile = super::sc_security::Profile::negotiate(&beacon, local, &auth, local_phy)?;
        }
        let rates = super::rates::Rates::parse_for_profiles(
            &beacon.information_elements,
            beacon.channel,
            phy.mode,
            profile.sae.as_ref().is_some_and(|join| join.h2e()),
            he_offer.is_some(),
        )?;
        let max_power = channel_power_width(
            domain,
            beacon.channel,
            phy.width,
            phy.center,
            &permissions.channels,
        )
        .ok_or("channel transmission prohibited by host/firmware regulatory policy")?;
        let ap_power = super::mld_power::ap_limit_in_ies(
            &beacon.information_elements,
            beacon.capabilities,
            beacon.channel,
        )?;
        let max_power = ap_power.map_or(max_power, |limit| i16::from(max_power).min(limit) as i8);
        let qos = permissions.limit_qos(domain, beacon.channel, phy.width, phy.center, qos);
        let regulatory = super::mld_policy::Program::new(
            domain,
            permissions.clone(),
            beacon.channel,
            phy.width,
            phy.center,
            max_power,
            qos,
            hw.rf_policy_validity()?,
        )?;
        hw.ensure_platform_power().await?;
        let mut phy_command = station_api::phy(1, beacon.channel);
        phy.apply_phy(&mut phy_command, beacon.channel);
        hw.station_phy(&phy_command, beacon.channel).await?;
        // PHY binding is accepted only while the link stays inactive.
        // Combining the bind with activation causes firmware to ignore
        // phy_id, leaving the link detached from its channel context.
        let mut binding = station_api::link(
            2,
            local,
            false,
            beacon.channel,
            beacon.interval,
            beacon.dtim,
        );
        put32(&mut binding, 12, 0);
        hw.command(3, 9, &binding).await?;
        // Program host/AP power before any active link or autonomous TX.
        let power = station_api::tx_power(
            hw.version(1, 0x9f).ok_or("missing TX power command")?.0,
            max_power,
        )?;
        hw.command(1, 0x9f, &power).await?;
        let mut link =
            station_api::link(2, local, true, beacon.channel, beacon.interval, beacon.dtim);
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
        hw.command(3, 9, &link).await?;
        let mut peer = station_api::peer(beacon.bssid);
        phy.apply_peer(&mut peer, 0);
        put32(&mut peer, 36, u32::from(profile.pmf));
        hw.station_peer(&peer).await?;
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
            tx_amsdu: super::sc_tx_amsdu::Limits::default(),
            amsdu_memory: None,
            amsdu_memory_attempted: false,
            tlc_notification_version: hw.version(5, 0xf7).map(|v| v.1),
        };
        // Authenticate: open-system auth for Open/WPA2-PSK; the SAE
        // commit/confirm exchange for WPA3, which also yields the PMK.
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
            this.security = Some(
                security::Session::new(
                    akm,
                    pmk,
                    this.beacon.bssid,
                    local,
                    **snonce.as_ref().ok_or("missing secure association nonce")?,
                    this.beacon.rsn.clone().ok_or("AP has no RSN IE")?,
                )
                .with_pmf(profile.pmf)
                .with_station_rsn(profile.rsne.clone().ok_or("MLD station RSNE missing")?)
                .with_rsn_extensions(station_rsnxe, ap_rsnxe)?,
            );
        }
        let rsn = profile.rsne.clone();
        let rates = this.rates.elements();
        let params = mlme::AssocParamsRsn {
            base: mlme::AssocParams {
                sta_addr: local,
                ap_bssid: this.beacon.bssid,
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
        if let Some(he) = he_offer.as_ref().and_then(|offer| offer.he()) {
            let capability = he.local_capability();
            request.extend_from_slice(&[255, capability.len() as u8]);
            request.extend_from_slice(&capability);
        }
        this.sequence = this.sequence.wrapping_add(1);
        hw.transmit(management_queue, &request, 24, this.rate())
            .await?;
        let reply = this.wait_management(hw, response_subtype).await?;
        let response =
            mlme::AssocResponseFields::decode(&reply).ok_or("invalid association response")?;
        if !response.is_success() || !(1..=2007).contains(&response.aid) {
            return Err("AP rejected association");
        }
        profile.check_response(&reply[6..])?;
        if this.qos.is_some() {
            // Association response may refine contention parameters from
            // the beacon. Only use QoS if the AP confirms WMM support.
            this.qos = super::qos::Parameters::parse(&reply[6..])?;
        }
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
        }
        this.qos = permissions.limit_qos(
            domain,
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
        let final_power = channel_power_width(
            domain,
            this.beacon.channel,
            this.phy.width,
            this.phy.center,
            &permissions.channels,
        )
        .ok_or("association response selected a prohibited channel span")?;
        if final_power < max_power {
            let power = station_api::tx_power(
                hw.version(1, 0x9f).ok_or("missing TX power command")?.0,
                final_power,
            )?;
            hw.command(1, 0x9f, &power).await?;
        }
        // Recheck membership selectors after a response downgrades PHY.
        this.rates = super::rates::Rates::parse_for_profiles(
            &this.beacon.information_elements,
            this.beacon.channel,
            this.phy.mode,
            profile.sae.as_ref().is_some_and(|join| join.h2e()),
            this.he.is_some(),
        )?;
        let mut phy_command = station_api::phy(2, this.beacon.channel);
        this.phy.apply_phy(&mut phy_command, this.beacon.channel);
        hw.station_phy(&phy_command, this.beacon.channel).await?;
        {
            let mut link = station_api::link(
                2,
                local,
                true,
                this.beacon.channel,
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
            if let Some(he) = this.he {
                he.apply_link(&mut link);
            }
            hw.station_link(&mut link);
            hw.command(3, 9, &link).await?;
        }
        let mut peer = station_api::peer(this.beacon.bssid);
        this.phy.apply_peer(&mut peer, response.aid);
        if let Some(he) = this.he {
            he.apply_sta(&mut peer);
        }
        put32(&mut peer, 36, u32::from(this.pmf_negotiated));
        hw.station_peer(&peer).await?;
        let mut mac = station_api::mac(2, local, Some(response.aid));
        if let Some(he) = this.he {
            he.apply_mac(&mut mac);
        }
        hw.command(3, 8, &mac).await?;
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
        hw.station_tlc(&tlc).await?;
        // The response-refined native span/power is the handshake's owner;
        // a beacon received during M4 can update that same shared proof.
        this.regulatory = super::mld_policy::Program::new(
            domain,
            permissions,
            this.beacon.channel,
            this.phy.width,
            this.phy.center,
            final_power.min(max_power),
            this.qos,
            hw.rf_policy_validity()?,
        )?
        .with_he(this.he.is_some())?;
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

    fn management(&mut self, subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut frame =
            frame_api::management(subtype, self.local, self.beacon.bssid, self.sequence, body);
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
                if frame.len() < 24
                    || frame[4..10] != self.local
                    || frame[10..16] != self.beacon.bssid
                    || frame[16..22] != self.beacon.bssid
                {
                    continue;
                }
                if matches!(frame[0], 0xa0 | 0xc0) {
                    return Err("AP disconnected during association");
                }
                if frame[0] == subtype {
                    return mpdu
                        .body(24, 0)
                        .map(|body| body.to_vec())
                        .ok_or("invalid management body");
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
        let sae = if join.h2e() {
            SaeSession::new_h2e_bytes(&ssid, password, self.local, self.beacon.bssid)
        } else {
            SaeSession::new_hunt_and_peck(password, self.local, self.beacon.bssid)
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
            ap_bssid: &self.beacon.bssid,
            sta_mac: &self.local,
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
        hw.enqueue_transmit_assisted(queue, &frame, header, None, assist)?;
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
            || self.amsdu_memory_pending()
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
        let (ac, frame, header) = if let Some(qos) = &self.qos {
            let ac = requested_ac
                .map_or_else(|| qos.classify(ethernet), |ac| qos.admitted(ac))
                .ok_or("no admitted access category")?;
            (
                ac,
                frame_api::transmit_qos(
                    self.local,
                    self.beacon.bssid,
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
                frame_api::transmit(
                    self.local,
                    self.beacon.bssid,
                    self.sequence,
                    ethernet,
                    protected,
                ),
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
        if !self.admits_data_header(mpdu) {
            return Ok(None);
        }
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
                self.local,
                self.beacon.bssid,
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
                if mpdu.channel != self.beacon.channel {
                    return Ok(output);
                }
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
                        self.local,
                        self.beacon.bssid,
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
                if frame.len() >= 24
                    && frame[0] == 0xd0
                    && frame[1] & 0x87 == 0
                    && frame[22] & 15 == 0
                    && frame[4..10] == self.local
                    && frame[10..16] == self.beacon.bssid
                    && frame[16..22] == self.beacon.bssid
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
                                self.local,
                                self.beacon.bssid,
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

    async fn service_power(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        if !self.power_pending {
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
            return Ok(());
        }
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
        if frame.len() < 24
            || !self.phy.admits_wide_rx(self.local_phy, mpdu.rate_n_flags)
            || (mpdu.rate_n_flags >> 8) & 7 >= 4
                && self
                    .he
                    .is_none_or(|he| !he.admits_rx_rate(mpdu.rate_n_flags))
        {
            return false;
        }
        if frame[1] & 0x80 == 0 {
            return true;
        }
        frame[0] == 0x88
            && self.he.is_some_and(|he| he.negotiation.htc_he())
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
        if mpdu.channel != self.beacon.channel || !self.admits_data_header(mpdu) {
            return Ok(None);
        }
        if frame.len() >= 24
            && frame[10..16] == self.beacon.bssid
            && frame[16..22] == self.beacon.bssid
        {
            if frame[0] == 0x80 {
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
                    {
                        self.authorized = false;
                        return Err("AP changed PHY operation; reassociation required");
                    }
                }
                self.last_beacon = narf_time::now_cycles();
            }
            if matches!(frame[0], 0xa0 | 0xc0)
                && (frame[4..10] == self.local || frame[4..10] == [0xff; 6])
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
                        if narf_wireless::mfp::verify_inbound(&mut self.mfp, &frame[..24], body)
                            .is_err()
                        {
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
        let Some(ethernet) = frame_api::receive(
            mpdu,
            self.local,
            self.beacon.bssid,
            self.security.is_some(),
            self.replay_for(queue),
        ) else {
            return Ok(None);
        };
        Ok(Some(ethernet))
    }

    pub async fn handle_eapol(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
    ) -> Result<(), &'static str> {
        if ethernet.len() < 14
            || ethernet[..6] != self.local
            || ethernet[6..12] != self.beacon.bssid
        {
            return Ok(());
        }
        let Some(security) = self.security.as_mut() else {
            return Ok(());
        };
        // Unauthenticated EAPOL must not close an established port or
        // poison replay state. A missing valid response times out during
        // initial association; an established connection simply drops it.
        let response = match security.process(&ethernet[14..]) {
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
                self.key_history.reserve(candidates)
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
        if changed {
            self.receive_epoch = hw.close_receive_epoch()?;
            self.discard_reorder();
            self.actions.clear();
        }
        let mut pending_igtk = None;
        if let Some(keys) = response.keys {
            if let Some(pairwise) = keys.pairwise.as_ref() {
                if self.pairwise_key.as_ref() != Some(pairwise) {
                    hw.drain_transmits().await?;
                    if self.pairwise_key.is_some() {
                        remove_key(hw, 0, false, self.pmf_negotiated).await?;
                    }
                    install_key(hw, 0, false, self.pmf_negotiated, pairwise, 0).await?;
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
                if self.group_keys[id].is_some() {
                    remove_key(hw, keys.group_id, true, self.pmf_negotiated).await?;
                }
                install_key(
                    hw,
                    keys.group_id,
                    true,
                    self.pmf_negotiated,
                    &keys.group,
                    keys.group_rx_pn,
                )
                .await?;
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
                if self.mfp.find_by_key_id(key_id).is_some() {
                    remove_key(hw, key_id as u8, true, true).await?;
                }
                install_key(hw, key_id as u8, true, true, &material, ipn).await?;
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
        let mut reply = Vec::new();
        reply.extend_from_slice(&self.beacon.bssid);
        reply.extend_from_slice(&self.local);
        reply.extend_from_slice(&[0x88, 0x8e]);
        reply.extend_from_slice(&response.bytes);
        // M2/M4 remain unencrypted; subsequent group-key replies use PTK.
        self.send_ethernet(hw, &reply, self.authorized).await?;
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

    pub async fn disconnect(mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        self.authorized = false;
        hw.close_receive_epoch()?;
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
        hw.command(3, 8, &station_api::mac(2, self.local, None))
            .await?;
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
            &station_api::link(2, self.local, false, self.beacon.channel, 0, 1),
        )
        .await?;
        // A second inactive update detaches phy_id after deactivation.
        hw.command(
            3,
            9,
            &station_api::link(2, self.local, false, self.beacon.channel, 0, 1),
        )
        .await?;
        hw.station_phy(
            &station_api::phy(3, self.beacon.channel),
            self.beacon.channel,
        )
        .await?;
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

async fn remove_key(hw: &mut Hardware, id: u8, group: bool, pmf: bool) -> Result<(), &'static str> {
    let body = super::sc_security::key_command(id, group, pmf, None, 0)?;
    let receipt = hw.command(5, 0x18, &body[..]).await?;
    if !receipt.payload.is_empty() {
        return Err("unexpected native key-removal receipt");
    }
    Ok(())
}

async fn install_key(
    hw: &mut Hardware,
    id: u8,
    group: bool,
    pmf: bool,
    key: &[u8; 16],
    rx_pn: u64,
) -> Result<(), &'static str> {
    if hw.version(5, 0x18).map(|v| v.0) != Some(1) {
        return Err("unsupported security key command");
    }
    let body = super::sc_security::key_command(id, group, pmf, Some(key), rx_pn)?;
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
