//! Station association and controlled-port state for the MLD interface.

use super::{
    boot_context::{put16, put32, put64},
    frame_api, mlme,
    runtime::Hardware,
    scan_api, security, station_api,
};
use alloc::{vec, vec::Vec};
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
    pub information_elements: Vec<u8>,
}

pub struct Connection {
    pub beacon: Beacon,
    local: [u8; 6],
    management_queue: u16,
    data_queue: u16,
    sequence: u16,
    security: Option<security::Session>,
    replay: frame_api::Replay,
    pub authorized: bool,
    pub last_beacon: u64,
    group_keys: [Option<[u8; 16]>; 4],
    tx_antenna: u32,
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
        hw.command(
            3,
            9,
            &station_api::link(2, local, true, beacon.channel, beacon.interval, beacon.dtim),
        )
        .await?;
        let power = station_api::tx_power(
            hw.version(1, 0x9f).ok_or("missing TX power command")?.0,
            max_power,
        )?;
        hw.command(1, 0x9f, &power).await?;
        hw.command(3, 0xa, &station_api::peer(beacon.bssid)).await?;
        let management_queue = hw.allocate_tx(0, 15).await?;
        let data_queue = hw.allocate_tx(0, 0).await?;
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
            data_queue,
            sequence: 0,
            security,
            replay: frame_api::Replay::default(),
            authorized: false,
            last_beacon: narf_time::now_cycles(),
            group_keys: [None; 4],
            tx_antenna: tx_chains & tx_chains.wrapping_neg(),
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
        let rates = if this.beacon.channel <= 14 {
            vec![0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36]
        } else {
            vec![0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]
        };
        let request = mlme::build_assoc_request_rsn(&mlme::AssocParamsRsn {
            base: mlme::AssocParams {
                sta_addr: local,
                ap_bssid: this.beacon.bssid,
                ssid: this.beacon.ssid.clone(),
                supported_rates: rates,
                capability_info: 0x0401 | if secure { 0x10 } else { 0 },
                listen_interval: 10,
                seq_num: this.sequence,
            },
            rsn_ie_body: rsn,
            ext_rates: if this.beacon.channel <= 14 {
                vec![48, 72, 96, 108]
            } else {
                Vec::new()
            },
        });
        this.sequence = this.sequence.wrapping_add(1);
        hw.transmit(management_queue, &request, 24, this.rate())
            .await?;
        let reply = this.wait_management(hw, 0x10).await?;
        let response =
            mlme::AssocResponseFields::decode(&reply).ok_or("invalid association response")?;
        if !response.is_success() || !(1..=2007).contains(&response.aid) {
            return Err("AP rejected association");
        }
        hw.command(3, 8, &station_api::mac(2, local, Some(response.aid)))
            .await?;
        if secure {
            let deadline = narf_time::Deadline::after_ms(8000);
            while !this.security.as_ref().unwrap().complete() {
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
                delay().await;
            }
        }
        this.authorized = true;
        Ok(this)
    }

    fn rate(&self) -> u32 {
        (self.tx_antenna << 14) | if self.beacon.channel <= 14 { 0 } else { 0x100 }
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
            delay().await;
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
        let frame = frame_api::transmit(
            self.local,
            self.beacon.bssid,
            self.sequence,
            ethernet,
            self.security.is_some(),
        )
        .ok_or("invalid Ethernet frame")?;
        hw.enqueue_transmit(self.data_queue, &frame, 24, self.rate())?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(())
    }

    async fn send_ethernet(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
        protected: bool,
    ) -> Result<(), &'static str> {
        let frame = frame_api::transmit(
            self.local,
            self.beacon.bssid,
            self.sequence,
            ethernet,
            protected,
        )
        .ok_or("invalid Ethernet frame")?;
        self.sequence = self.sequence.wrapping_add(1);
        hw.transmit(self.data_queue, &frame, 24, self.rate()).await
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
                install_key(hw, 0, false, pairwise, 0).await?;
            }
            let id = keys.group_id as usize;
            // Authenticated group-message retransmissions may carry a
            // higher EAPOL replay counter with the SAME GTK. Reinstalling
            // it would reset firmware/host packet numbers (KRACK).
            if self.group_keys[id] != Some(keys.group) {
                install_key(hw, keys.group_id, true, &keys.group, keys.group_rx_pn).await?;
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
        hw.remove_tx(self.data_queue, 0, 0).await?;
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

async fn delay() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
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
    put32(&mut body[..], 12, 2 | if group { 0x40 } else { 0 });
    body[16..32].copy_from_slice(key);
    put64(&mut body[..], 64, rx_pn);
    hw.command(5, 0x18, &body[..]).await?;
    Ok(())
}

async fn authorize_channel(hw: &mut Hardware, channel: u8) -> Result<i8, &'static str> {
    let domain = narf_wireless::reg::db::get_domain()
        .ok_or("wireless regulatory domain is not configured")?;
    let frequency = if channel == 14 {
        2484
    } else if channel <= 13 {
        2407 + 5 * channel as u32
    } else {
        5000 + 5 * channel as u32
    };
    let max_power = domain
        .rules
        .iter()
        .filter(|rule| {
            rule.freq_start_mhz <= frequency.saturating_sub(10)
                && rule.freq_end_mhz >= frequency + 10
                && rule.max_bandwidth_mhz >= 20
        })
        .map(|rule| rule.max_power_dbm)
        .min()
        .ok_or("channel prohibited by regulatory domain")?;
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
    // Same channel order as NVM. The firmware must allow 20MHz
    // activity in addition to the host's domain grant.
    let index = station_api::channel_index(channel).ok_or("unknown channel")?;
    if index >= count {
        return Err("channel absent from MCC response");
    }
    let flags = u32::from_le_bytes(
        response.payload[24 + index * 4..28 + index * 4]
            .try_into()
            .unwrap(),
    );
    if flags & 5 != 5 {
        return Err("firmware prohibited channel transmission");
    }
    Ok(max_power)
}
