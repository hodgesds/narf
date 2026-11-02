//! Original native AP ToDS/FromDS facts and separate SME/data publication.
//! Firmware owns packet crypto and TX PN; host replay changes follow exact
//! physical station/band/capture, integrity, payload and port admission.
use super::*;
pub(in crate::iwlwifi) enum Event {
    Management {
        frame: Vec<u8>,
        rssi: i8,
    },
    Control {
        peer: [u8; 6],
        ethertype: u16,
        pdu: Vec<u8>,
        unencrypted: bool,
    },
}
pub(in crate::iwlwifi) struct Received {
    pub data: Option<Vec<u8>>,
    pub event: Option<Event>,
    pub probe: Option<Vec<u8>>,
}
impl Received {
    fn empty() -> Self {
        Self {
            data: None,
            event: None,
            probe: None,
        }
    }
}
impl Session {
    pub fn receive(
        &mut self,
        packet: &super::super::runtime::Packet,
        hw: &Hardware,
    ) -> Result<Received, &'static str> {
        self.current()?;
        let mut out = Received::empty();
        if packet.header.group_id != 0
            || packet.header.cmd != 0xc1
            || packet.receive_epoch != Some(self.epoch)
            || packet.receive_queue >= hw.receive_queue_count()
        {
            return Ok(out);
        }
        let Some(mpdu) = hw.ap_mpdu(&packet.payload) else {
            return Ok(out);
        };
        if hw.band_in_rx_supported() && mpdu.raw_band != self.plan.channel.band as u8
            || super::super::native_band::Channel::received(
                mpdu.channel,
                mpdu.raw_band,
                hw.band_in_rx_supported(),
            ) != Some(self.plan.channel)
            || hw.uses_mld_station_protocol() && mpdu.raw_fw_link != 0
        {
            return Ok(out);
        }
        let f = mpdu.frame;
        if f.len() < 24 || f[0] & 3 != 0 || f[1] & 0x84 != 0 || f[22] & 15 != 0 {
            return Ok(out);
        }
        if f[0] & 12 == 0 {
            if packet.receive_queue != 0
                || f[1] & 3 != 0
                || f[10] & 1 != 0
                || f[10..16] == [0; 6]
                || f[10..16] == self.own
                || f[4..10] != self.own && f[4..10] != [0xff; 6]
                || f[16..22] != self.own && !(f[0] == 0x40 && f[16..22] == [0xff; 6])
            {
                return Ok(out);
            }
            let peer = self.peers.iter().position(|p| f[10..16] == p.config.mac);
            if let Some(i) = peer {
                if mpdu.status & 4 != 0 && ((mpdu.status >> 24) & 31) != u32::from(self.peers[i].id)
                {
                    return Ok(out);
                }
            }
            let protected = f[1] & 0x40 != 0;
            let mut delivered = f[..24].to_vec();
            if protected {
                let Some(i) = peer else {
                    return Ok(out);
                };
                let peer = &mut self.peers[i];
                if peer.key.is_none()
                    || !peer.config.mfp.unwrap_or(false)
                    || mpdu.status & 0x7c0 != 0x240
                {
                    return Ok(out);
                }
                let Some(iv) = f.get(24..32) else {
                    return Ok(out);
                };
                let Ok((pn, id)) = narf_wireless::ccmp::decode_ccmp_header(iv.try_into().unwrap())
                else {
                    return Ok(out);
                };
                if id != 0 || pn <= peer.management_pn {
                    return Ok(out);
                }
                let Some(body) = mpdu.body(24, 8) else {
                    return Ok(out);
                };
                if body.len() < 2 || !robust(f[0], body) {
                    return Ok(out);
                }
                delivered.extend_from_slice(body);
                peer.management_pn = pn;
            } else {
                let Some(body) = mpdu.body(24, 0) else {
                    return Ok(out);
                };
                if peer.is_some_and(|i| {
                    self.peers[i].key.is_some() && self.peers[i].config.mfp.unwrap_or(false)
                }) && robust(f[0], body)
                {
                    return Ok(out);
                }
                delivered.extend_from_slice(body);
            }
            if matches!(f[0], 0xa0 | 0xc0) {
                if let Some(i) = peer {
                    if self.peers[i].authorized {
                        self.data_epoch.advance()?;
                    }
                    self.peers[i].authorized = false;
                    self.peers[i].config.authorized = Some(false);
                }
            }
            if f[0] == 0x40 {
                if let Some(template) = &self.plan.config.probe_resp {
                    let Ok(wanted) = super::super::ap_wire::elements_iter(&delivered[24..]) else {
                        return Ok(out);
                    };
                    let ssids: Vec<_> = wanted.iter().filter(|(id, _)| *id == 0).collect();
                    if ssids.len() == 1
                        && (ssids[0].1 == self.plan.config.ssid
                            || ssids[0].1.is_empty() && self.plan.config.hidden_ssid == 0
                            || self.plan.go.is_some_and(|go| {
                                ssids[0].1 == b"DIRECT-" && go.discovery_request(&delivered[24..])
                            }))
                    {
                        let mut reply = template.clone();
                        reply[4..10].copy_from_slice(&f[10..16]);
                        out.probe = Some(reply);
                    }
                }
            }
            out.event = Some(Event::Management {
                frame: delivered,
                rssi: mpdu.rssi,
            });
            return Ok(out);
        }
        if !matches!(f[0], 8 | 0x88)
            || f[1] & 3 != 1
            || f[4..10] != self.own
            || mpdu.amsdu
            || (mpdu.rate_n_flags >> 8) & 7 > 1
            || mpdu.status & 4 == 0
        {
            return Ok(out);
        }
        let Some(index) = self.peers.iter().position(|p| p.config.mac == f[10..16]) else {
            return Ok(out);
        };
        let peer = &self.peers[index];
        if (mpdu.status >> 24) & 31 != u32::from(peer.id) {
            return Ok(out);
        }
        let (header, tid) = if f[0] == 0x88 {
            if f.len() < 26 || !peer.config.wme.unwrap_or(false) || f[24] & 0xf8 != 0 || f[25] != 0
            {
                return Ok(out);
            }
            (26, usize::from(f[24] & 7))
        } else {
            (24, 16)
        };
        let encrypted = f[1] & 0x40 != 0;
        let mut pn = None;
        let body = if encrypted {
            if peer.key.is_none() || mpdu.status & 0x7c0 != 0x240 {
                return Ok(out);
            }
            let Some(iv) = f.get(header..header + 8) else {
                return Ok(out);
            };
            let Ok((number, key_id)) =
                narf_wireless::ccmp::decode_ccmp_header(iv.try_into().unwrap())
            else {
                return Ok(out);
            };
            if key_id != 0 || number <= peer.pn[tid] {
                return Ok(out);
            }
            pn = Some(number);
            mpdu.body(header, 8)
        } else {
            mpdu.body(header, 0)
        };
        let Some(body) =
            body.filter(|b| b.len() >= 8 && b.len() <= 1508 && b[..6] == [0xaa, 0xaa, 3, 0, 0, 0])
        else {
            return Ok(out);
        };
        let ethertype = u16::from_be_bytes(body[6..8].try_into().unwrap());
        if ethertype < 0x600 {
            return Ok(out);
        }
        let configured = ethertype == self.settings.control_port.ethertype;
        if !configured
            && ethertype == narf_wireless::ETH_P_PREAUTH
            && (!peer.authorized || self.plan.secure() && !encrypted)
        {
            return Ok(out);
        }
        let control = configured
            || ethertype == narf_wireless::ETH_P_PREAUTH && !self.settings.control_port.no_preauth;
        if control {
            if !self.settings.control_port.enabled || !self.settings.control_port.over_nl80211 {
                return Ok(out);
            }
            out.event = Some(Event::Control {
                peer: peer.config.mac,
                ethertype,
                pdu: body[8..].to_vec(),
                unencrypted: !encrypted,
            });
        } else {
            if !peer.authorized || self.plan.secure() && !encrypted {
                return Ok(out);
            }
            let mut ethernet = Vec::new();
            ethernet.extend_from_slice(&f[16..22]);
            ethernet.extend_from_slice(&peer.config.mac);
            ethernet.extend_from_slice(&body[6..]);
            out.data = Some(ethernet);
        }
        if let Some(pn) = pn {
            self.peers[index].pn[tid] = pn;
        }
        Ok(out)
    }
    pub fn try_enqueue(
        &mut self,
        hw: &mut Hardware,
        ethernet: &[u8],
        category: usize,
        assist: u32,
    ) -> Result<bool, &'static str> {
        self.current()?;
        if !(14..=1514).contains(&ethernet.len())
            || ethernet[6] & 1 != 0
            || ethernet[6..12] == [0; 6]
        {
            return Ok(true); // Discard an unpublishable ordinary-ring frame.
        }
        let ethertype = u16::from_be_bytes(ethernet[12..14].try_into().unwrap());
        if ethertype < 0x600 || ethertype == narf_wireless::ETH_P_PAE {
            return Ok(true); // Only the separately admitted SME port can send it.
        }
        let multicast = ethernet[0] & 1 != 0;
        let (queue, encrypt, tid) = if multicast {
            if !self.peers.iter().any(|p| p.authorized) {
                return Ok(true);
            }
            if self.plan.secure() && !self.default_installed(false) {
                return Ok(false);
            }
            (self.mcast, self.plan.secure(), None)
        } else {
            let Some(peer) = self.peers.iter().find(|p| p.config.mac == ethernet[..6]) else {
                return Ok(true);
            };
            if !peer.authorized || self.plan.secure() && peer.key.is_none() {
                return Ok(true);
            }
            let ac = if peer.config.wme.unwrap_or(false) {
                category.min(3)
            } else {
                1
            };
            (
                peer.queues[ac],
                self.plan.secure(),
                peer.config
                    .wme
                    .unwrap_or(false)
                    .then_some(super::super::qos::TIDS[ac]),
            )
        };
        if !hw.transmit_space(queue)? {
            return Ok(false);
        }
        let host_group = multicast && encrypt && self.plan.go.is_some();
        let completed = if host_group {
            let mut plain = ethernet.to_vec();
            super::super::csum::complete_prepared(&mut plain, assist)?;
            Some(plain)
        } else {
            None
        };
        let ethernet = completed.as_deref().unwrap_or(ethernet);
        let (mut frame, header) =
            ap_wire::ethernet_qos_from_ap(self.own, self.sequence, ethernet, encrypt, tid)
                .ok_or("AP native Ethernet frame invalid")?;
        let rate = multicast.then(|| {
            self.plan
                .rates
                .management_rate(self.chains & self.chains.wrapping_neg())
        });
        if host_group {
            self.protect_go_group(&mut frame, header)?;
        }
        hw.enqueue_transmit_ap(
            queue,
            &frame,
            header,
            rate,
            encrypt && !host_group,
            if host_group { 0 } else { assist },
        )?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(true)
    }
    pub async fn management(
        &mut self,
        hw: &mut Hardware,
        r: &narf_wireless::MgmtTxRequest,
    ) -> Result<bool, &'static str> {
        self.current()?;
        let f = &r.frame;
        if !(24..=2048).contains(&f.len())
            || !matches!(f[0], 0x10 | 0x30 | 0x50 | 0xb0 | 0xa0 | 0xc0 | 0xd0)
            || f[1] & 0xc7 != 0
            || f[4..10] == [0; 6]
            || f[10..16] != self.own
            || f[16..22] != self.own
            || f[22] & 15 != 0
            || r.frequency_mhz != 0 && r.frequency_mhz != self.plan.channel.frequency()
            || r.duration != 0
        {
            return Err("AP management FRAME differs from current native BSS");
        }
        let peer = self.peers.iter().find(|p| p.config.mac == f[4..10]);
        let group = f[4] & 1 != 0;
        let protected = robust(f[0], &f[24..])
            && if group {
                self.default_installed(true)
            } else {
                peer.is_some_and(|p| p.config.mfp.unwrap_or(false) && p.key.is_some())
            };
        if robust(f[0], &f[24..]) && self.plan.pmf_required() && !protected {
            return Err("AP robust management lacks current native PTK/IGTK");
        }
        let queue = if group {
            self.bcast
        } else {
            peer.map_or(self.bcast, |p| p.management)
        };
        let mut frame = f.clone();
        if protected && !group {
            frame[1] |= 0x40;
        }
        super::super::boot_context::put16(&mut frame, 22, (self.sequence & 4095) << 4);
        self.sequence = self.sequence.wrapping_add(1);
        let mut rates = self.plan.rates;
        if r.no_cck {
            rates.supported &= !15;
            rates.basic &= !15;
            if rates.supported == 0 {
                return Err("AP NO_CCK has no actual OFDM rate");
            }
            if rates.basic == 0 {
                rates.basic = rates.supported;
            }
        }
        let software_bip = protected && group && (self.plan.go.is_some() || hw.ap_software_bip());
        if software_bip {
            self.protect_host_bip(&mut frame)?;
        }
        let rate = Some(rates.management_rate(self.chains & self.chains.wrapping_neg()));
        match hw
            .transmit_ap(queue, &frame, 24, rate, protected && !software_bip)
            .await
        {
            Ok(()) => Ok(!group),
            Err(super::super::runtime::TX_FAILED) => Ok(false),
            Err(e) => Err(e),
        }
    }
    pub fn try_probe(&mut self, hw: &mut Hardware, bytes: &[u8]) -> Result<bool, &'static str> {
        self.current()?;
        if !hw.transmit_space(self.bcast)? {
            return Ok(false);
        }
        let mut frame = bytes.to_vec();
        if frame.len() < 36
            || frame[0] != 0x50
            || frame[10..16] != self.own
            || frame[16..22] != self.own
        {
            return Err("AP private probe response lost original physical identity");
        }
        super::super::boot_context::put16(&mut frame, 22, (self.sequence & 4095) << 4);
        let rate = self
            .plan
            .rates
            .management_rate(self.chains & self.chains.wrapping_neg());
        hw.enqueue_transmit_ap(self.bcast, &frame, 24, Some(rate), false, 0)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(true)
    }
}
pub(super) fn robust(subtype: u8, body: &[u8]) -> bool {
    matches!(subtype, 0xa0 | 0xc0)
        || subtype == 0xd0
            && body
                .first()
                .is_some_and(|category| !matches!(category, 4 | 7 | 11 | 15 | 20 | 21 | 22 | 127))
}
