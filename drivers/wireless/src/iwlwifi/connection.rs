//! Station association and controlled-port state for the MLD interface.

use super::{
    boot_context::{put16, put32, put64},
    frame_api, mlme,
    runtime::Hardware,
    scan_api, security, station_api,
};
use alloc::{collections::VecDeque, vec::Vec};
use zeroize::Zeroize;

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

pub struct Connection {
    pub beacon: Beacon,
    local: [u8; 6],
    management_queue: u16,
    data_queues: [Option<u16>; 4],
    qos: Option<super::qos::Parameters>,
    sequence: u16,
    security: Option<security::Session>,
    replay: frame_api::Replay,
    pub authorized: bool,
    pub last_beacon: u64,
    group_keys: [Option<[u8; 16]>; 4],
    pairwise_key: Option<[u8; 16]>,
    tx_antenna: u32,
    rates: super::rates::Rates,
    phy: super::ht_vht::Negotiated,
    local_phy: super::ht_vht::Local,
    rx_ba: [Option<super::aggregation::Window>; super::aggregation::MAX_TIDS],
    actions: VecDeque<Vec<u8>>,
    /// 802.11w IGTK store (BIP-CMAC-128), populated from message 3 on
    /// WPA3. `mfp_active` gates management-frame protection enforcement.
    mfp: narf_wireless::mfp::MfpKeyStore,
    mfp_active: bool,
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
    pub async fn associate(
        hw: &mut Hardware,
        local: [u8; 6],
        beacon: Beacon,
        auth: AuthMethod,
        tx_chains: u32,
        local_phy: super::ht_vht::Local,
        roam_from: Option<[u8; 6]>,
    ) -> Result<Self, &'static str> {
        let secure = !matches!(auth, AuthMethod::Open);
        let akm = match &auth {
            AuthMethod::Open => None,
            AuthMethod::Wpa2Psk(_) => Some(security::Akm::Wpa2Psk),
            AuthMethod::Wpa3Sae { .. } => Some(security::Akm::Wpa3Sae),
        };
        if secure {
            let rsn = narf_wireless::rsn::RsnIe::decode_body(
                beacon.rsn.as_ref().ok_or("AP has no RSN IE")?,
            )
            .ok_or("invalid AP RSN")?;
            use narf_wireless::rsn::*;
            let ccmp = Suite::standard(CIPHER_CCMP_128);
            let ciphers_ok = rsn.group_cipher == ccmp && rsn.pairwise_ciphers.contains(&ccmp);
            match akm {
                Some(security::Akm::Wpa3Sae) => {
                    // WPA3-Personal: AKM-SAE and mandatory management-frame
                    // protection (the AP must at least be MFP-capable).
                    if !ciphers_ok
                        || !rsn.akms.contains(&Suite::standard(AKM_SAE))
                        || rsn.rsn_capabilities & RSN_CAP_MFP_CAPABLE == 0
                    {
                        return Err("AP does not support WPA3-SAE/CCMP with MFP");
                    }
                }
                _ => {
                    // WPA2-PSK: AKM-PSK, CCMP, and the AP must not require MFP
                    // (this profile's WPA2 path does not protect mgmt frames).
                    if !ciphers_ok
                        || !rsn.akms.contains(&Suite::standard(AKM_PSK))
                        || rsn.rsn_capabilities & RSN_CAP_MFP_REQUIRED != 0
                    {
                        return Err("AP does not support WPA2-PSK/CCMP without required MFP");
                    }
                }
            }
        } else if beacon.privacy {
            return Err("secured AP requested as open");
        }
        let qos = super::qos::Parameters::parse(&beacon.information_elements)?;
        let domain = narf_wireless::reg::db::get_domain()
            .ok_or("wireless regulatory domain is not configured")?;
        let permissions = regulatory_channels(hw).await?;
        let phy = super::ht_vht::Negotiated::parse(
            local_phy,
            &beacon.information_elements,
            beacon.channel,
            qos.is_some(),
            |width, center| {
                channel_power_width(&domain, beacon.channel, width, center, &permissions).is_some()
            },
        )?;
        let rates = super::rates::Rates::parse_for_phy(
            &beacon.information_elements,
            beacon.channel,
            phy.mode,
        )?;
        let max_power =
            channel_power_width(&domain, beacon.channel, phy.width, phy.center, &permissions)
                .ok_or("channel transmission prohibited by host/firmware regulatory policy")?;
        let mut phy_command = station_api::phy(1, beacon.channel);
        phy.apply_phy(&mut phy_command, beacon.channel);
        hw.command(1, 8, &phy_command).await?;
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
        let power = station_api::tx_power(
            hw.version(1, 0x9f).ok_or("missing TX power command")?.0,
            max_power,
        )?;
        hw.command(1, 0x9f, &power).await?;
        let mut peer = station_api::peer(beacon.bssid);
        phy.apply_peer(&mut peer, 0);
        hw.command(3, 0xa, &peer).await?;
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
            authorized: false,
            last_beacon: narf_time::now_cycles(),
            group_keys: [None; 4],
            pairwise_key: None,
            tx_antenna: tx_chains & tx_chains.wrapping_neg(),
            rates,
            phy,
            local_phy,
            rx_ba: core::array::from_fn(|_| None),
            actions: VecDeque::new(),
            mfp: narf_wireless::mfp::MfpKeyStore::new(),
            mfp_active: false,
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
            AuthMethod::Wpa3Sae { password } => Some(this.sae_authenticate(hw, password).await?),
        };
        // With the PMK in hand, arm the 4-way handshake session.
        if let (Some(pmk), Some(akm)) = (pmk, akm) {
            let mut nonce = [0; 32];
            narf_crypto::fill_random_bytes(&mut nonce);
            this.security = Some(security::Session::new(
                akm,
                pmk,
                this.beacon.bssid,
                local,
                nonce,
                this.beacon.rsn.clone().ok_or("AP has no RSN IE")?,
            ));
        }
        let rsn = akm.map(|akm| match akm {
            security::Akm::Wpa2Psk => narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body(),
            security::Akm::Wpa3Sae => narf_wireless::rsn::RsnIe::wpa3_sae_ccmp().encode_body(),
        });
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
        if this.qos.is_some() {
            request.extend_from_slice(&super::qos::INFORMATION_IE);
        }
        request.extend_from_slice(&this.phy.association_ies(local_phy, this.beacon.channel));
        this.sequence = this.sequence.wrapping_add(1);
        hw.transmit(management_queue, &request, 24, this.rate())
            .await?;
        let reply = this.wait_management(hw, response_subtype).await?;
        let response =
            mlme::AssocResponseFields::decode(&reply).ok_or("invalid association response")?;
        if !response.is_success() || !(1..=2007).contains(&response.aid) {
            return Err("AP rejected association");
        }
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
        // The response can choose a different secondary channel while
        // narrowing bandwidth. Revalidate the resulting entire span.
        let final_power = channel_power_width(
            &domain,
            this.beacon.channel,
            this.phy.width,
            this.phy.center,
            &permissions,
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
        this.rates = super::rates::Rates::parse_for_phy(
            &this.beacon.information_elements,
            this.beacon.channel,
            this.phy.mode,
        )?;
        let mut phy_command = station_api::phy(2, this.beacon.channel);
        this.phy.apply_phy(&mut phy_command, this.beacon.channel);
        hw.command(1, 8, &phy_command).await?;
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
            hw.command(3, 9, &link).await?;
        }
        let mut peer = station_api::peer(this.beacon.bssid);
        this.phy.apply_peer(&mut peer, response.aid);
        hw.command(3, 0xa, &peer).await?;
        hw.command(3, 8, &station_api::mac(2, local, Some(response.aid)))
            .await?;
        let mut tlc = this.rates.tlc(
            hw.version(5, 0xf).ok_or("firmware has no TLC command")?.0,
            tx_chains,
        )?;
        if this.phy.mode != 0 {
            hw.enable_aggregation()?;
        }
        this.phy.apply_tlc(&mut tlc);
        hw.command(5, 0xf, &tlc).await?;
        if secure {
            let deadline = narf_time::Deadline::after_ms(8000);
            while !this.security.as_ref().unwrap().complete() {
                let activity = hw.activity();
                hw.poll()?;
                while let Some(packet) = hw.notifications.pop_front() {
                    if packet.header.group_id != 0 || packet.header.cmd != 0xc1 {
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
        this.authorized = true;
        Ok(this)
    }

    fn rate(&self) -> Option<u32> {
        Some(self.rates.management_rate(self.tx_antenna))
    }

    fn management(&mut self, subtype: u8, body: &[u8]) -> Vec<u8> {
        let frame =
            frame_api::management(subtype, self.local, self.beacon.bssid, self.sequence, body);
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
                if packet.header.group_id != 0 || packet.header.cmd != 0xc1 {
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

    /// Drive the WPA3-SAE (H2E) commit/confirm exchange over the
    /// management path and return the derived 32-byte PMK. Authentication
    /// frames use algorithm 3 (SAE); the SAE variable body carries the
    /// commit scalar/element and the confirm transcript MAC.
    async fn sae_authenticate(
        &mut self,
        hw: &mut Hardware,
        password: &[u8],
    ) -> Result<[u8; 32], &'static str> {
        use narf_wireless::sae::{SaeSession, SaeState, SAE_STATUS_HASH_TO_ELEMENT};
        // Own the SSID: its borrow must outlive the `&mut self` TX calls below
        // (SAE-PK verification at the end needs it again).
        let ssid = alloc::string::String::from_utf8(self.beacon.ssid.clone())
            .map_err(|_| "SSID is not valid UTF-8")?;
        let password =
            core::str::from_utf8(password).map_err(|_| "SAE password is not valid UTF-8")?;
        let mut sae = SaeSession::new(&ssid, password, self.local, self.beacon.bssid);

        // Commit (seq 1). H2E signals via status SAE_STATUS_HASH_TO_ELEMENT.
        // `build_commit` is called once: an anti-clogging retry must resend the
        // same scalar/element, adding only the AP-supplied token (§12.4.7.4).
        const SAE_STATUS_ANTI_CLOGGING: u16 = 76; // §9.4.1.9
        let commit = sae.build_commit();
        let mut token: Vec<u8> = Vec::new();
        let mut commit_reply = Vec::new();
        let mut accepted = false;
        // Initial commit plus up to two anti-clogging retries.
        for _ in 0..3 {
            // SAE Commit body: group(2) || scalar || element, plus the
            // Anti-Clogging Token Container element (ID 255, ext 93) on the
            // H2E retry (§9.4.2.199).
            let mut body = Vec::with_capacity(commit.len() + token.len() + 3);
            body.extend_from_slice(&commit);
            if !token.is_empty() {
                body.push(0xff);
                body.push((token.len() + 1) as u8);
                body.push(93);
                body.extend_from_slice(&token);
            }
            let frame = self.management(
                0xb0,
                &mlme::build_sae_auth_body(1, SAE_STATUS_HASH_TO_ELEMENT, &body),
            );
            hw.transmit(self.management_queue, &frame, 24, self.rate())
                .await?;
            commit_reply = self.wait_management(hw, 0xb0).await?;
            let header =
                mlme::AuthResponse::decode(&commit_reply).ok_or("invalid SAE commit response")?;
            if header.algorithm != mlme::auth_algorithm::SAE || header.seq != 1 {
                return Err("AP did not answer SAE commit");
            }
            match header.status {
                0 | SAE_STATUS_HASH_TO_ELEMENT => {
                    accepted = true;
                    break;
                }
                SAE_STATUS_ANTI_CLOGGING => {
                    token = extract_anti_clogging_token(commit_reply.get(6..).unwrap_or(&[]))
                        .ok_or("SAE anti-clogging token missing")?;
                }
                _ => return Err("AP rejected SAE commit"),
            }
        }
        if !accepted {
            return Err("SAE anti-clogging retries exhausted");
        }
        // The AP commit's fixed fields are group(2)+scalar(32)+element(64);
        // ignore any trailing H2E elements (rejected groups, token container).
        let commit_body = &commit_reply[6..];
        sae.on_commit(commit_body.get(..98).unwrap_or(commit_body))
            .map_err(|_| "SAE commit processing failed")?;

        // Confirm (seq 2, status 0).
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
        // WPA3 SAE-PK: the AP must prove possession of the public key whose
        // fingerprint the password encodes. Authenticate it before trusting
        // the PMK, and abort the association on failure (evil-twin defence).
        if sae.is_sae_pk() {
            self.verify_sae_pk(&sae, &ssid, password)?;
        }
        sae.pmk().copied().ok_or("SAE produced no PMK")
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
        if !self.authorized {
            return Err("controlled port closed");
        }
        let (queue, frame, header) = self.ethernet_frame(ethernet, self.security.is_some(), ac)?;
        hw.enqueue_transmit(queue, &frame, header, None)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(())
    }

    pub(super) async fn enqueue_wait_for_ac(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
        ac: usize,
    ) -> Result<(), &'static str> {
        if !self.authorized {
            return Err("controlled port closed");
        }
        let (queue, frame, header) =
            self.ethernet_frame(ethernet, self.security.is_some(), Some(ac))?;
        hw.wait_tx_space(queue).await?;
        hw.enqueue_transmit(queue, &frame, header, None)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(())
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
        let (queue, frame, header) = self.ethernet_frame(ethernet, protected, None)?;
        self.sequence = self.sequence.wrapping_add(1);
        hw.transmit(queue, &frame, header, None).await
    }

    pub async fn receive(
        &mut self,
        hw: &mut Hardware,
        mpdu: &scan_api::Mpdu<'_>,
    ) -> Result<Option<Vec<u8>>, &'static str> {
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
        let mut output = Vec::new();
        if packet.header.group_id != 0 {
            return Ok(output);
        }
        let now = narf_time::now_cycles();
        match packet.header.cmd {
            0xc1 => {
                let Some(mpdu) = scan_api::mpdu(&packet.payload) else {
                    return Ok(output);
                };
                let frame = mpdu.frame;
                if frame.len() >= 24
                    && frame[0] == 0xd0
                    && frame[1] & 0xc7 == 0
                    && frame[22] & 15 == 0
                    && frame[4..10] == self.local
                    && frame[10..16] == self.beacon.bssid
                    && frame[16..22] == self.beacon.bssid
                    && self.authorized
                    && self.phy.mode != 0
                {
                    if let Some(body) = mpdu.body(24, 0) {
                        if super::aggregation::action(body).is_some() && self.actions.len() < 16 {
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
                                &mut self.replay.clone(),
                            )
                            .is_none()
                        {
                            return Ok(output);
                        }
                        if let Some(window) =
                            self.rx_ba.iter_mut().flatten().find(|w| w.baid == baid)
                        {
                            let released = window.push(&packet.payload, now);
                            self.deliver_reordered(released, &mut output)?;
                        }
                        return Ok(output);
                    }
                }
                if let Some(frame) = self.receive_frame(&mpdu)? {
                    output.push(frame);
                }
            }
            0xc3 if packet.payload.len() == 4 => {
                let baid = packet.payload[0];
                let nssn = u16::from_le_bytes(packet.payload[2..4].try_into().unwrap());
                if let Some(window) = self.rx_ba.iter_mut().flatten().find(|w| w.baid == baid) {
                    let released = window.release(nssn, now);
                    self.deliver_reordered(released, &mut output)?;
                }
            }
            0xc2 if packet.payload.len() == 8 => {
                let sta_tid = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
                let info = u32::from_le_bytes(packet.payload[4..8].try_into().unwrap());
                if sta_tid & 0x1f0 == 0 {
                    if let Some(window) = self
                        .rx_ba
                        .get_mut((sta_tid & 15) as usize)
                        .and_then(Option::as_mut)
                    {
                        if window.baid == ((info >> 24) & 63) as u8 {
                            let released = window.release((info & 4095) as u16, now);
                            self.deliver_reordered(released, &mut output)?;
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
        packets: Vec<Vec<u8>>,
        output: &mut Vec<Vec<u8>>,
    ) -> Result<(), &'static str> {
        for packet in packets {
            if let Some(mpdu) = scan_api::mpdu(&packet) {
                if let Some(frame) = self.receive_frame(&mpdu)? {
                    output.push(frame);
                }
            }
        }
        Ok(())
    }

    pub fn reorder_tick(&mut self) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut output = Vec::new();
        let now = narf_time::now_cycles();
        for tid in 0..self.rx_ba.len() {
            if let Some(window) = &mut self.rx_ba[tid] {
                let packets = window.tick(now);
                self.deliver_reordered(packets, &mut output)?;
            }
        }
        Ok(output)
    }

    pub async fn service_aggregation(&mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        use super::aggregation::{self, Action};
        if !self.authorized {
            self.actions.clear();
            return Ok(());
        }
        while let Some(body) = self.actions.pop_front() {
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
                            let mut state = aggregation::Window::new(
                                0,
                                tid,
                                token,
                                ssn,
                                window,
                                timeout,
                                narf_time::now_cycles(),
                            )?;
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
                            state.baid = baid as u8;
                            self.rx_ba[tid as usize] = Some(state);
                            status = 0;
                        }
                    }
                    let response = aggregation::add_response(token, tid, window, timeout, status);
                    let frame = self.management(0xd0, &response);
                    hw.transmit(self.management_queue, &frame, 24, self.rate())
                        .await?;
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
            if self.rx_ba[tid]
                .as_ref()
                .is_some_and(|w| w.expired(narf_time::now_cycles()))
            {
                self.stop_rx_ba(hw, tid as u8).await?;
                let frame = self.management(0xd0, &aggregation::delete(tid as u8));
                hw.transmit(self.management_queue, &frame, 24, self.rate())
                    .await?;
            }
        }
        Ok(())
    }

    async fn stop_rx_ba(&mut self, hw: &mut Hardware, tid: u8) -> Result<(), &'static str> {
        if self.rx_ba[tid as usize].is_some() {
            hw.command(5, 0x16, &super::aggregation::remove(tid))
                .await?;
            // Preserve ordering across BAID reuse: discard packets captured
            // during removal before accepting a new session with that ID.
            hw.discard_key_transition_rx()?;
            self.rx_ba[tid as usize] = None;
        }
        Ok(())
    }

    fn discard_reorder(&mut self) {
        for window in self.rx_ba.iter_mut().flatten() {
            window.discard();
        }
    }

    pub fn receive_frame(
        &mut self,
        mpdu: &scan_api::Mpdu<'_>,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let frame = mpdu.frame;
        if frame.len() >= 24
            && frame[10..16] == self.beacon.bssid
            && frame[16..22] == self.beacon.bssid
        {
            if frame[0] == 0x80 {
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
                if self.mfp_active {
                    if frame[4] & 1 == 1 {
                        // Group-addressed robust mgmt frame: require a valid
                        // BIP MMIE signed by the AP's IGTK.
                        let Some(body) = mpdu.body(24, 0) else {
                            return Ok(None);
                        };
                        if narf_wireless::mfp::verify_inbound(&mut self.mfp, &frame[..24], body)
                            .is_err()
                        {
                            return Ok(None);
                        }
                    } else if frame[1] & 0x40 == 0 {
                        // Individually-addressed robust mgmt frame must be
                        // CCMP-protected (Protected bit set); drop the forgery.
                        return Ok(None);
                    }
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
            &mut self.replay,
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
        let Ok(response) = security.process(&ethernet[14..]) else {
            return Ok(());
        };
        if let Some(keys) = response.keys {
            if let Some(pairwise) = keys.pairwise.as_ref() {
                if self.pairwise_key.as_ref() != Some(pairwise) {
                    hw.drain_transmits().await?;
                    if self.pairwise_key.is_some() {
                        remove_key(hw, 0, false).await?;
                    }
                    install_key(hw, 0, false, pairwise, 0).await?;
                    hw.discard_key_transition_rx()?;
                    if let Some(old) = &mut self.pairwise_key {
                        old.zeroize();
                    }
                    self.pairwise_key = Some(*pairwise);
                    self.replay.reset_pairwise();
                    self.discard_reorder();
                }
            }
            let id = keys.group_id as usize;
            // Authenticated group-message retransmissions may carry a
            // higher EAPOL replay counter with the SAME GTK. Reinstalling
            // it would reset firmware/host packet numbers (KRACK).
            if self.group_keys[id] != Some(keys.group) {
                if self.group_keys[id].is_some() {
                    remove_key(hw, keys.group_id, true).await?;
                }
                install_key(hw, keys.group_id, true, &keys.group, keys.group_rx_pn).await?;
                hw.discard_key_transition_rx()?;
                if let Some(old) = &mut self.group_keys[id] {
                    old.zeroize();
                }
                self.group_keys[id] = Some(keys.group);
                self.replay.group[id].fill(keys.group_rx_pn);
                self.replay.group_valid[id] = true;
                self.replay.reset_subframes();
                self.discard_reorder();
            }
            // 802.11w: install the IGTK and arm management-frame protection.
            // The host verifies group-addressed robust mgmt frames (BIP) and
            // drops unprotected ones; per-frame BIP math lives in `mfp`.
            if let Some((igtk, key_id)) = keys.igtk {
                self.mfp
                    .install_active(igtk, key_id)
                    .map_err(|_| "invalid IGTK key index")?;
                self.mfp_active = true;
            }
        }
        let mut reply = Vec::new();
        reply.extend_from_slice(&self.beacon.bssid);
        reply.extend_from_slice(&self.local);
        reply.extend_from_slice(&[0x88, 0x8e]);
        reply.extend_from_slice(&response.bytes);
        // M2/M4 remain unencrypted; subsequent group-key replies use PTK.
        self.send_ethernet(hw, &reply, self.authorized).await?;
        Ok(())
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
        for tid in 0..self.rx_ba.len() {
            self.stop_rx_ba(hw, tid as u8).await?;
        }
        hw.drain_transmits().await?;
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
        hw.command(1, 8, &station_api::phy(3, self.beacon.channel))
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

async fn remove_key(hw: &mut Hardware, id: u8, group: bool) -> Result<(), &'static str> {
    let mut body = [0; 80];
    put32(&mut body, 0, 3); // REMOVE
    put32(&mut body, 4, 1); // station 0
    put32(&mut body, 8, id as u32);
    put32(&mut body, 12, 2 | if group { 0x48 } else { 0 });
    hw.command(5, 0x18, &body).await?;
    Ok(())
}

async fn install_key(
    hw: &mut Hardware,
    id: u8,
    group: bool,
    key: &[u8; 16],
    rx_pn: u64,
) -> Result<(), &'static str> {
    if hw.version(5, 0x18).map(|v| v.0) != Some(1) {
        return Err("unsupported security key command");
    }
    let mut body = zeroize::Zeroizing::new([0; 80]);
    put32(&mut body[..], 0, 1); // ADD
    put32(&mut body[..], 4, 1); // station 0 mask
    put32(&mut body[..], 8, id as u32);
    put32(&mut body[..], 12, 2 | if group { 0x48 } else { 0 });
    body[16..32].copy_from_slice(key);
    put64(&mut body[..], 64, rx_pn);
    hw.command(5, 0x18, &body[..]).await?;
    Ok(())
}

/// Firmware permission is refreshed once per scan/association operation.
pub(super) async fn regulatory_channels(hw: &mut Hardware) -> Result<Vec<u32>, &'static str> {
    let domain = narf_wireless::reg::db::get_domain()
        .ok_or("wireless regulatory domain is not configured")?;
    if hw.version(1, 0xc8).map(|v| v.1) != Some(8) {
        return Err("unsupported regulatory response");
    }
    let mut body = [0; 28];
    put16(&mut body, 0, u16::from_be_bytes(domain.country_code));
    body[2] = 2; // MCC_SOURCE_BIOS
    let response = hw.command(1, 0xc8, &body).await?;
    if response.payload.len() < 24 {
        return Err("invalid MCC response");
    }
    if u32::from_le_bytes(response.payload[..4].try_into().unwrap()) > 1 {
        return Err("firmware rejected regulatory update");
    }
    let count = u32::from_le_bytes(response.payload[20..24].try_into().unwrap()) as usize;
    if count > 115 || response.payload.len() != 24 + count * 4 {
        return Err("invalid MCC channel count");
    }
    Ok(response.payload[24..]
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect())
}

/// Host policy is intersected with firmware permission, with the lowest
/// matching power ceiling. Probes never initiate radiation on DFS channels.
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
    let frequency = if channel == 14 {
        2484
    } else if channel <= 13 {
        2407 + 5 * channel as u32
    } else {
        5000 + 5 * channel as u32
    };
    let mut power = None;
    for rule in &domain.rules {
        if rule.freq_start_mhz <= frequency.saturating_sub(10)
            && rule.freq_end_mhz >= frequency + 10
            && rule.max_bandwidth_mhz >= 20
        {
            if probe && rule.flags.contains(narf_wireless::reg::RegFlags::DFS) {
                return None;
            }
            power = Some(power.map_or(rule.max_power_dbm, |old: i8| old.min(rule.max_power_dbm)));
        }
    }
    power
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
    if width > 2 || primary == 14 || (width == 2 && primary <= 14) {
        return None;
    }
    let offsets: &[i16] = if width == 1 {
        &[-2, 2]
    } else {
        &[-6, -2, 2, 6]
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
    for rule in &domain.rules {
        if rule.freq_start_mhz <= frequency - mhz / 2
            && rule.freq_end_mhz >= frequency + mhz / 2
            && rule.max_bandwidth_mhz >= mhz
        {
            span_power =
                Some(span_power.map_or(rule.max_power_dbm, |old: i8| old.min(rule.max_power_dbm)));
        }
    }
    Some(power.min(span_power?))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "connection_tests.rs"]
mod tests;
