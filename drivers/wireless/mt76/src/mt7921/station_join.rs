//! MT76 live station join and disassociate dispatch.
//! Channel/power authorization, MLME open authentication/association
//! request/response loops, and peer record installation.
use super::{
    scan::rx_frame, station::Command, Backend, Error, ScanBss, Session, Stage, State, TIMEOUT_MS,
};
use crate::mt7921::{
    association::{disconnect_record, JoinPlan, Security},
    cmd, packet_tx,
};
use alloc::{vec, vec::Vec};
use narf_wireless::eapol::{HmacPrimitive, KeyFrame, Supplicant};

struct HmacSha1;
impl HmacPrimitive for HmacSha1 {
    fn out_len(&self) -> usize {
        20
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
    }
}

fn compute_mic(kck: &[u8], eapol_bytes_zero_mic: &[u8]) -> [u8; 16] {
    let full = narf_crypto::pbkdf2_sha1::hmac_sha1(kck, eapol_bytes_zero_mic);
    let mut mic = [0u8; 16];
    mic.copy_from_slice(&full[..16]);
    mic
}

pub(crate) fn extract_eapol(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() >= 18 && frame[12..14] == [0x88, 0x8e] {
        return Some(&frame[14..]);
    }
    for snap_offset in [24, 26] {
        if frame.len() >= snap_offset + 8 + 4
            && frame[snap_offset..snap_offset + 6] == [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]
            && frame[snap_offset + 6..snap_offset + 8] == [0x88, 0x8e]
        {
            return Some(&frame[snap_offset + 8..]);
        }
    }
    None
}

pub(crate) fn wrap_eapol_frame(own: [u8; 6], peer: [u8; 6], eapol: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + 8 + eapol.len());
    frame.extend_from_slice(&[0x08, 0x01]); // 802.11 Data to-DS
    frame.extend_from_slice(&[0x00, 0x00]); // duration
    frame.extend_from_slice(&peer); // Addr1: BSSID
    frame.extend_from_slice(&own); // Addr2: SA
    frame.extend_from_slice(&peer); // Addr3: DA
    frame.extend_from_slice(&[0x00, 0x00]); // seq ctrl
    frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]); // LLC/SNAP EAPOL
    frame.extend_from_slice(eapol);
    frame
}

/// Convert an incoming 802.11 Data frame with LLC/SNAP or raw 802.3 frame
/// into an 802.3 Ethernet frame.
pub fn to_ethernet(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() >= 32 && (frame[0] == 0x08 || frame[0] == 0x88) && (frame[1] & 0x03 == 0x02) {
        let da = &frame[4..10];
        let sa = &frame[16..22];
        let qos = frame[0] == 0x88;
        let snap_offset = if qos { 26 } else { 24 };
        if frame.len() >= snap_offset + 8
            && frame[snap_offset..snap_offset + 6] == [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]
        {
            let ethertype = &frame[snap_offset + 6..snap_offset + 8];
            let payload = &frame[snap_offset + 8..];
            let mut eth = Vec::with_capacity(14 + payload.len());
            eth.extend_from_slice(da);
            eth.extend_from_slice(sa);
            eth.extend_from_slice(ethertype);
            eth.extend_from_slice(payload);
            return Some(eth);
        }
    }
    if frame.len() >= 14 {
        return Some(frame.to_vec());
    }
    None
}

impl<B: Backend> Session<B> {
    pub(super) async fn send_management(
        &mut self,
        frame: &[u8],
        wcid: u16,
    ) -> Result<packet_tx::Completion, Error> {
        self.backend.check()?;
        self.backend.submit_management(frame, wcid)?;
        let completion = self
            .wait(TIMEOUT_MS, |backend| backend.management_complete())
            .await?;
        if completion.status != 0 {
            return Err(Error::Rejected(completion.status));
        }
        Ok(completion)
    }

    pub(super) async fn send_ethernet(
        &mut self,
        frame: &[u8],
    ) -> Result<packet_tx::Completion, Error> {
        self.backend.check()?;
        self.backend.submit_data(frame)?;
        let completion = self
            .wait(TIMEOUT_MS, |backend| backend.management_complete())
            .await?;
        if completion.status != 0 {
            return Err(Error::Rejected(completion.status));
        }
        Ok(completion)
    }

    pub(super) async fn associate_station(
        &mut self,
        bss: &ScanBss,
        ssid: &[u8],
        security: Security,
    ) -> Result<u16, Error> {
        let (info, setup) = match self.state {
            State::RadioReady(info) => (info, true),
            State::ScanReady(info) => (info, false),
            State::Associated { .. } => return Err(Error::Busy),
            _ => return Err(Error::Busy),
        };
        if info.capabilities.phy.bands & 1 == 0 {
            return Err(Error::InvalidIdentity);
        }
        let own = info.capabilities.mac;
        let mut plan = JoinPlan::prepare(bss, own, ssid, security).map_err(|e| match e {
            crate::mt7921::association::Error::InvalidBss => Error::Bounds,
            crate::mt7921::association::Error::UnsupportedRates => Error::UnsupportedFirmware,
            crate::mt7921::association::Error::UnsupportedSecurity => Error::Bounds,
            crate::mt7921::association::Error::Busy => Error::Busy,
            _ => Error::Bounds,
        })?;

        let result = async {
            if setup {
                self.stage(Stage::ScanSetup);
                self.scan_setup(info).await?;
            }
            self.stage(Stage::ChannelSwitch);
            // 1. Authorize transmission on the target channel in channel domain (NO_IR = 0):
            let mut domain = vec![0u8; 12 + 8];
            domain[..2].copy_from_slice(b"00");
            domain[4..7].fill(1); // 20 MHz
            domain[8] = 1; // 1 channel
            domain[12..14].copy_from_slice(&(u16::from(bss.channel)).to_le_bytes());
            domain[16..20].copy_from_slice(&0u32.to_le_bytes()); // NO_IR=0 (transmission authorized)
            self.notify(
                Command::Ce {
                    id: 0x0f,
                    query: false,
                },
                &domain,
            )
            .await?;

            // 2. Switch channel:
            let mut switch = [0u8; cmd::CHANNEL_SWITCH_SIZE];
            cmd::encode_channel_switch(
                bss.channel,
                bss.channel,
                cmd::CH_BW_20,
                info.capabilities.phy.spatial_streams.min(2),
                info.capabilities.phy.spatial_streams.min(2),
                cmd::CH_BAND_24G,
                &mut switch,
            )
            .ok_or(Error::Bounds)?;
            self.exchange(
                Command::Extended {
                    id: crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH,
                    query: false,
                },
                &switch,
            )
            .await?;

            // 3. Send Authentication Request:
            self.stage(Stage::Authenticate);
            let auth_req = plan.start_authentication().map_err(|_| Error::Busy)?;
            self.send_management(auth_req, 1).await?;

            // 4. Wait for Authentication Response:
            let assoc_req = self
                .wait(3_000, |backend| {
                    for _ in 0..16 {
                        let Some(packet) = backend.receive_data()? else {
                            break;
                        };
                        if let Some(frame) = rx_frame(&packet) {
                            if let Some(assoc) = plan
                                .authentication_response(frame)
                                .map_err(|_| Error::MalformedEvent)?
                            {
                                return Ok(Some(assoc.to_vec()));
                            }
                        }
                    }
                    Ok(None)
                })
                .await?;

            // 5. Send Association Request:
            self.stage(Stage::Associate);
            self.send_management(&assoc_req, 1).await?;

            // 6. Wait for Association Response:
            let aid = self
                .wait(3_000, |backend| {
                    for _ in 0..16 {
                        let Some(packet) = backend.receive_data()? else {
                            break;
                        };
                        if let Some(frame) = rx_frame(&packet) {
                            if let Some(aid) = plan
                                .association_response(frame)
                                .map_err(|_| Error::MalformedEvent)?
                            {
                                return Ok(Some(aid));
                            }
                        }
                    }
                    Ok(None)
                })
                .await?;

            // 7. Update STA_REC / perform WPA2 4-way handshake:
            match security {
                Security::Open => {
                    self.stage(Stage::StaRecord);
                    let sta_rec = plan
                        .peer_record(aid, true)
                        .map_err(|_| Error::MalformedEvent)?;
                    self.exchange(
                        Command::Extended {
                            id: crate::mt7921::txrx::MCU_EXT_CMD_STA_REC_UPDATE,
                            query: false,
                        },
                        &sta_rec,
                    )
                    .await?;
                }
                Security::Wpa2Psk { psk } => {
                    self.stage(Stage::EapolHandshake);
                    let mut snonce = [0u8; 32];
                    narf_crypto::fill_random_bytes(&mut snonce);
                    let mut supplicant = Supplicant::new(bss.bssid, own, snonce);

                    // Wait for M1 from AP:
                    let m2_frame = self
                        .wait(3_000, |backend| {
                            for _ in 0..16 {
                                let Some(packet) = backend.receive_data()? else {
                                    break;
                                };
                                let payload = rx_frame(&packet).unwrap_or(&packet);
                                if let Some(eapol_bytes) = extract_eapol(payload) {
                                    if eapol_bytes.len() >= 4 {
                                        if let Some(m1) = KeyFrame::decode(&eapol_bytes[4..], 16) {
                                            if let Ok(Some(mut m2)) =
                                                supplicant.handle(&HmacSha1, &psk, 16, &m1)
                                            {
                                                if let Some(rsn) = plan.rsn_body() {
                                                    m2.key_data = rsn;
                                                }
                                                let mut m2_bytes = m2.into_eapol();
                                                let kck = &supplicant.ptk.as_ref().unwrap().kck;
                                                let mic = compute_mic(kck, &m2_bytes);
                                                m2_bytes[81..97].copy_from_slice(&mic);
                                                return Ok(Some(wrap_eapol_frame(
                                                    own, bss.bssid, &m2_bytes,
                                                )));
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(None)
                        })
                        .await?;

                    self.send_management(&m2_frame, 1).await?;

                    // Wait for M3 from AP:
                    let m4_frame = self
                        .wait(3_000, |backend| {
                            for _ in 0..16 {
                                let Some(packet) = backend.receive_data()? else {
                                    break;
                                };
                                let payload = rx_frame(&packet).unwrap_or(&packet);
                                if let Some(eapol_bytes) = extract_eapol(payload) {
                                    if eapol_bytes.len() >= 97 {
                                        let mut zeroed = eapol_bytes.to_vec();
                                        zeroed[81..97].fill(0);
                                        let kck = supplicant.ptk.as_ref().unwrap().kck.clone();
                                        let expected_mic = compute_mic(&kck, &zeroed);
                                        if eapol_bytes[81..97] != expected_mic[..] {
                                            return Err(Error::MalformedEvent);
                                        }
                                        if let Some(m3) = KeyFrame::decode(&eapol_bytes[4..], 16) {
                                            if let Ok(Some(m4)) =
                                                supplicant.handle(&HmacSha1, &psk, 16, &m3)
                                            {
                                                let mut m4_bytes = m4.into_eapol();
                                                let mic = compute_mic(&kck, &m4_bytes);
                                                m4_bytes[81..97].copy_from_slice(&mic);
                                                return Ok(Some(wrap_eapol_frame(
                                                    own, bss.bssid, &m4_bytes,
                                                )));
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(None)
                        })
                        .await?;

                    self.send_management(&m4_frame, 1).await?;

                    // Commit secure station record with WTBL CCMP-128 key
                    self.stage(Stage::StaRecord);
                    let tk = &supplicant.ptk.as_ref().unwrap().tk;
                    let sta_rec = plan
                        .secure_peer_record(aid, tk)
                        .map_err(|_| Error::MalformedEvent)?;
                    self.exchange(
                        Command::Extended {
                            id: crate::mt7921::txrx::MCU_EXT_CMD_STA_REC_UPDATE,
                            query: false,
                        },
                        &sta_rec,
                    )
                    .await?;
                }
            }

            Ok(aid)
        }
        .await;

        match result {
            Ok(aid) => {
                self.state = State::Associated {
                    info,
                    peer: bss.bssid,
                    channel: bss.channel,
                    aid,
                };
                Ok(aid)
            }
            Err(error) => {
                plan.cancel();
                let stage = match self.state {
                    State::Running(stage) => stage,
                    _ => Stage::Associate,
                };
                self.state = State::Failed { stage, error };
                Err(error)
            }
        }
    }

    pub(super) async fn disassociate_station(&mut self) -> Result<(), Error> {
        let (info, peer) = match self.state {
            State::Associated { info, peer, .. } => (info, peer),
            _ => return Ok(()),
        };
        self.stage(Stage::StaRecord);
        // Deauth frame: 24-byte mgmt header + reason code 3 (Deauth leaving ESS)
        let mut deauth = vec![0u8; 26];
        deauth[0] = 0xc0; // subtype 12 = Deauth
        deauth[4..10].copy_from_slice(&peer);
        deauth[10..16].copy_from_slice(&info.capabilities.mac);
        deauth[16..22].copy_from_slice(&peer);
        deauth[24..26].copy_from_slice(&3u16.to_le_bytes()); // Reason 3: Leaving ESS
        let _ = self.send_management(&deauth, 1).await;

        let disconnect = disconnect_record(peer);
        let _ = self
            .exchange(
                Command::Extended {
                    id: crate::mt7921::txrx::MCU_EXT_CMD_STA_REC_UPDATE,
                    query: false,
                },
                &disconnect,
            )
            .await;

        self.state = State::RadioReady(info);
        Ok(())
    }
}
