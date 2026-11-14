//! Legacy AP data uses exact peer WCIDs and software CCMP over unmodified
//! native 802.11 bytes. Binding/capture and per-peer port checks are distinct.
use super::super::{ap_crypto::Target, ap_packet, ap_rx};
use super::*;

impl<B: Backend> Session<B> {
    pub(in crate::mt7921::firmware_transport) fn ap_receive_current(
        &self,
        epoch: u64,
    ) -> Result<bool, Error> {
        let Some(owner) = self.ap_owner.as_ref() else {
            self.backend.check()?;
            return Ok(false);
        };
        self.owner_ap_receive_current(owner, &self.state, epoch)
    }
    fn ap_data_failure(&mut self, error: Error) -> Error {
        self.close_ap_capture(self.receive_epoch);
        if let Some(owner) = self.ap_owner.as_mut() {
            owner.activated = false;
        }
        self.state = State::Failed {
            stage: Stage::ApPeer,
            error,
        };
        error
    }
    pub(in crate::mt7921::firmware_transport) fn step_ap_network(
        &mut self,
        tx: Option<&[u8]>,
    ) -> Result<super::super::PacketStep, Error> {
        if self.p2p_rf_busy() {
            return Err(Error::Busy);
        }
        if !self
            .ap_receive_current(self.receive_epoch)
            .map_err(|e| self.ap_data_failure(e))?
        {
            return Err(Error::Busy);
        }
        if let Err(error) = self.settle_go_credit() {
            return Err(self.ap_data_failure(error));
        }
        // A GO measures its timeout from its own oldest entry; a home
        // station entry ahead of it is credited to the home link.
        let oldest = if self.go_role() {
            self.data_pending.oldest_go()
        } else {
            self.data_pending.front().copied()
        };
        if let Some(started) = oldest {
            match self.backend.management_complete() {
                Ok(Some(completion)) => match self.retire_ap_completion(completion) {
                    Some(completion) if completion.status != 0 => {
                        return Err(self.ap_data_failure(Error::Rejected(completion.status)));
                    }
                    _ => (),
                },
                Ok(None)
                    if self.backend.now_ns().saturating_sub(started)
                        >= super::super::TIMEOUT_MS * 1_000_000 =>
                {
                    return Err(self.ap_data_failure(Error::Timeout));
                }
                Ok(None) => (),
                Err(error) => return Err(self.ap_data_failure(error)),
            }
        }
        let mut transmitted = false;
        let idle = if self.go_role() {
            self.data_pending.go_owned() == 0
                && self.data_pending.len() < crate::mt7921::packet_tx::PIPELINE
        } else {
            self.data_pending.is_empty()
        };
        if idle {
            if let Some(frame) = tx {
                match self.ap_transmit(frame) {
                    Ok(()) => transmitted = true,
                    Err(Error::Busy) => (),
                    Err(error) => return Err(self.ap_data_failure(error)),
                }
            }
        }
        let mut received = alloc::vec::Vec::new();
        for _ in 0..16 {
            let captured = match self.next_ap_copy() {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => return Err(self.ap_data_failure(e)),
            };
            if !captured.port_open
                || !self
                    .ap_owner
                    .as_ref()
                    .is_some_and(|owner| self.ap_epoch_admits(owner, captured.epoch))
            {
                continue;
            }
            if !self
                .ap_receive_current(captured.epoch)
                .map_err(|e| self.ap_data_failure(e))?
            {
                break;
            }
            if let Some(frame) = self.ap_receive(&captured.bytes) {
                received.push(frame);
            }
        }
        self.ap_receive_current(self.receive_epoch)
            .map_err(|e| self.ap_data_failure(e))?;
        Ok(super::super::PacketStep {
            transmitted,
            received,
            link: None,
            receive_epoch: self.receive_epoch,
        })
    }
    fn ap_transmit(&mut self, ethernet: &[u8]) -> Result<(), Error> {
        if !self.ap_receive_current(self.receive_epoch)? {
            return Err(Error::Busy);
        }
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        let own = owner.plan.own;
        let vif = owner.plan.vif;
        let secure = owner.plan.config.privacy;
        let (header, body) = ap_packet::ethernet(own, ethernet, secure)?;
        // EAPOL belongs to explicit control-port authority, even after the
        // peer is authorized. It never enters the ordinary data rings.
        let ethertype = u16::from_be_bytes([ethernet[12], ethernet[13]]);
        let preauth_on_netdev = owner
            .start_settings
            .as_ref()
            .is_some_and(|s| s.control_port.no_preauth);
        if ethertype == 0x888e || ethertype == 0x88c7 && !preauth_on_netdev {
            return Err(Error::Bounds);
        }
        let destination: [u8; 6] = ethernet[..6].try_into().unwrap();
        let (wcid, target) = if destination[0] & 1 != 0 {
            if !owner.peers.any_authorized() {
                return Err(Error::Busy);
            }
            (
                vif.bmc(),
                if secure {
                    Some(Target::Group(owner.default_group.ok_or(Error::Busy)?))
                } else {
                    None
                },
            )
        } else {
            let peer = owner
                .peers
                .get(destination)
                .filter(|p| p.associated && p.authorized)
                .ok_or(Error::Busy)?;
            (
                peer.wcid,
                if secure {
                    Some(Target::Pairwise(destination))
                } else {
                    None
                },
            )
        };
        let rate = owner.plan.rate;
        let mut wire = header.clone();
        match target {
            Some(target) => wire.extend_from_slice(
                &self
                    .ap_keys
                    .protect(own, target, &header, &body)
                    .map_err(|_| Error::Bounds)?,
            ),
            None => wire.extend_from_slice(&body),
        }
        if !self.ap_receive_current(self.receive_epoch)? {
            return Err(Error::Busy);
        }
        self.backend.submit_ap_frame(vif, &wire, wcid, rate)?;
        self.push_ap_pending();
        Ok(())
    }
    pub(in crate::mt7921::firmware_transport) fn pop_ap_event(
        &mut self,
    ) -> Result<Option<ApRxEvent>, Error> {
        if !self.ap_receive_current(self.receive_epoch)? {
            return Ok(None);
        }
        while let Some(event) = self
            .ap_owner
            .as_mut()
            .ok_or(Error::Busy)?
            .events
            .pop_front()
        {
            if self
                .ap_owner
                .as_ref()
                .is_some_and(|owner| self.ap_epoch_admits(owner, event.epoch))
            {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }
    fn queue_ap_event(&mut self, event: ApEvent) {
        if let Some(owner) = self.ap_owner.as_mut() {
            // Radio input is untrusted and cannot allocate an unbounded
            // notification backlog. Overflow drops this event, never grants
            // host data or changes native packet ownership.
            if owner.events.len() < 64 {
                owner.events.push_back(ApRxEvent {
                    epoch: self.receive_epoch,
                    event,
                });
            }
        }
    }
    fn ap_receive(&mut self, packet: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        let owner = self.ap_owner.as_ref()?;
        let raw = ap_rx::decode(packet, owner.info.capabilities.phy.spatial_streams)?;
        let wire = raw.frame;
        if raw.channel != owner.plan.channel
            || raw.band
                != if owner.plan.five_ghz {
                    crate::mt7921::channel::Band::Ghz5
                } else {
                    crate::mt7921::channel::Band::Ghz2
                }
            || raw.fragment
            || wire.len() < 24
            || wire[22] & 15 != 0
            || wire[0] & 3 != 0
        {
            return None;
        }
        let own = owner.plan.own;
        if wire[0] & 15 == 0 {
            let subtype = wire[0] >> 4;
            let minimum = match subtype {
                0 => 28,
                2 => 34,
                4 => 24,
                10 | 12 => 26,
                11 => 30,
                13 => 25,
                _ => return None,
            };
            if wire.len() < minimum
                || wire[1] & 0xc7 != 0
                || wire[10..16] == [0; 6]
                || wire[10] & 1 != 0
                || wire[10..16] == own
                || !(wire[4..10] == own || wire[4..10] == [0xff; 6])
                || !(wire[16..22] == own || subtype == 4 && wire[16..22] == [0xff; 6])
            {
                return None;
            }
            let frequency_mhz = owner.plan.config.frequency_mhz;
            self.queue_ap_event(ApEvent::Management {
                frequency_mhz,
                signal_dbm: raw.signal_dbm,
                frame: wire.to_vec(),
            });
            return None;
        }
        if raw.tid != 0
            || wire.len() <= 24
            || wire[0] != 8
            || wire[1] & 0x87 != 1
            || wire[4..10] != own
        {
            return None;
        }
        let mac: [u8; 6] = wire[10..16].try_into().ok()?;
        let peer = owner.peers.get(mac)?;
        if !peer.associated || raw.wcid != u16::from(peer.wcid) {
            return None;
        }
        let authorized = peer.authorized;
        let secure = owner.plan.config.privacy;
        let protected = wire[1] & 0x40 != 0;
        let body = if protected {
            self.ap_keys
                .unprotect(own, mac, &wire[..24], &wire[24..])
                .ok()?
        } else {
            wire[24..].to_vec()
        };
        let ethernet = ap_packet::to_ethernet(own, mac, &wire[..24], &body)?;
        let ethertype = u16::from_be_bytes([ethernet[12], ethernet[13]]);
        let preauth_on_netdev = self
            .ap_owner
            .as_ref()?
            .start_settings
            .as_ref()
            .is_some_and(|s| s.control_port.no_preauth);
        if ethertype == 0x888e || ethertype == 0x88c7 && !preauth_on_netdev {
            // Unencrypted handshake traffic is explicitly marked and has no
            // ordinary data/peer authorization. The userspace authenticator
            // owns its EAPOL MIC/replay state. Protected control still needs
            // the actual current peer PTK and native software replay proof.
            self.queue_ap_event(ApEvent::Control {
                peer: mac,
                ethertype,
                pdu: ethernet[14..].to_vec(),
                unencrypted: !protected,
            });
            return None;
        }
        if !authorized || protected != secure {
            return None;
        }
        Some(ethernet)
    }
}
