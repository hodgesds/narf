//! Station association and controlled-port state for the MLD interface.

use super::{
    boot_context::{put16, put32, put64},
    frame_api, mlme,
    runtime::Hardware,
    scan_api, security, station_api,
};
use alloc::vec::Vec;
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

impl Connection {
    pub async fn associate(
        hw: &mut Hardware,
        local: [u8; 6],
        beacon: Beacon,
        psk: Option<[u8; 32]>,
        tx_chains: u32,
    ) -> Result<Self, &'static str> {
        let secure = psk.is_some();
        if secure {
            let rsn = narf_wireless::rsn::RsnIe::decode_body(
                beacon.rsn.as_ref().ok_or("AP has no RSN IE")?,
            )
            .ok_or("invalid AP RSN")?;
            use narf_wireless::rsn::*;
            let ccmp = Suite::standard(CIPHER_CCMP_128);
            let psk = Suite::standard(AKM_PSK);
            if rsn.group_cipher != ccmp
                || !rsn.pairwise_ciphers.contains(&ccmp)
                || !rsn.akms.contains(&psk)
                || rsn.rsn_capabilities & RSN_CAP_MFP_REQUIRED != 0
            {
                return Err("AP does not support WPA2-PSK/CCMP without required MFP");
            }
        } else if beacon.privacy {
            return Err("secured AP requested as open");
        }
        let rates = super::rates::Rates::parse(&beacon.information_elements, beacon.channel)?;
        let qos = super::qos::Parameters::parse(&beacon.information_elements)?;
        let max_power = authorize_channel(hw, beacon.channel).await?;
        hw.command(1, 8, &station_api::phy(1, beacon.channel))
            .await?;
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
        hw.command(3, 9, &link).await?;
        let power = station_api::tx_power(
            hw.version(1, 0x9f).ok_or("missing TX power command")?.0,
            max_power,
        )?;
        hw.command(1, 0x9f, &power).await?;
        hw.command(3, 0xa, &station_api::peer(beacon.bssid)).await?;
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
        let mut nonce = [0; 32];
        let security = psk.map(|psk| {
            narf_crypto::fill_random_bytes(&mut nonce);
            security::Session::new(psk, beacon.bssid, local, nonce, beacon.rsn.clone().unwrap())
        });
        let mut this = Self {
            beacon,
            local,
            management_queue,
            data_queues,
            qos,
            sequence: 0,
            security,
            replay: frame_api::Replay::default(),
            authorized: false,
            last_beacon: narf_time::now_cycles(),
            group_keys: [None; 4],
            pairwise_key: None,
            tx_antenna: tx_chains & tx_chains.wrapping_neg(),
            rates,
        };
        let auth = this.management(0xb0, &mlme::build_open_auth_body());
        hw.transmit(management_queue, &auth, 24, this.rate())
            .await?;
        let auth = this.wait_management(hw, 0xb0).await?;
        if !mlme::AuthResponse::decode(&auth).is_some_and(|reply| reply.is_success()) {
            return Err("AP rejected authentication");
        }
        let rsn = if secure {
            Some(narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body())
        } else {
            None
        };
        let rates = this.rates.elements();
        let mut request = mlme::build_assoc_request_rsn(&mlme::AssocParamsRsn {
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
        });
        if this.qos.is_some() {
            request.extend_from_slice(&super::qos::INFORMATION_IE);
        }
        this.sequence = this.sequence.wrapping_add(1);
        hw.transmit(management_queue, &request, 24, this.rate())
            .await?;
        let reply = this.wait_management(hw, 0x10).await?;
        let response =
            mlme::AssocResponseFields::decode(&reply).ok_or("invalid association response")?;
        if !response.is_success() || !(1..=2007).contains(&response.aid) {
            return Err("AP rejected association");
        }
        if this.qos.is_some() {
            // Association response may refine contention parameters from
            // the beacon. Only use QoS if the AP confirms WMM support.
            this.qos = super::qos::Parameters::parse(&reply[6..])?;
            if let Some(qos) = &this.qos {
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
                qos.apply(&mut link);
                hw.command(3, 9, &link).await?;
            }
        }
        hw.command(3, 8, &station_api::mac(2, local, Some(response.aid)))
            .await?;
        hw.command(
            5,
            0xf,
            &this.rates.tlc(
                hw.version(5, 0xf).ok_or("firmware has no TLC command")?.0,
                tx_chains,
            )?,
        )
        .await?;
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
                self.last_beacon = narf_time::now_cycles();
            }
            if matches!(frame[0], 0xa0 | 0xc0)
                && (frame[4..10] == self.local || frame[4..10] == [0xff; 6])
            {
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

    pub async fn disconnect(mut self, hw: &mut Hardware) -> Result<(), &'static str> {
        self.authorized = false;
        let frame = self.management(0xa0, &3u16.to_le_bytes());
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

async fn authorize_channel(hw: &mut Hardware, channel: u8) -> Result<i8, &'static str> {
    let domain = narf_wireless::reg::db::get_domain()
        .ok_or("wireless regulatory domain is not configured")?;
    let firmware = regulatory_channels(hw).await?;
    channel_power(&domain, channel, &firmware, false)
        .ok_or("channel transmission prohibited by host/firmware regulatory policy")
}
