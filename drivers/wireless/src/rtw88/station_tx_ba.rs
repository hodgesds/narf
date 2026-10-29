// SPDX-License-Identifier: GPL-2.0-or-later
//! Same retained station's source BA/SSN/FIFO and native batch continuation.
use super::*;
impl State {
    pub(in crate::rtw88) fn rts_threshold(&self) -> Option<u32> {
        self.protection
            .as_ref()
            .filter(|_| self.data_profile.rates & (1 << 8) != 0)
            .map(|g| g.threshold())
    }
    pub(in crate::rtw88) fn set_rts_threshold(
        &mut self,
        io: &mut impl Io,
        value: u32,
    ) -> Result<(), Error> {
        let admission = self.admission.clone();
        let result = admission
            .run(|| {
                io.station_allowed()?;
                Ok((|| {
                    let g = self.protection.as_ref().ok_or(Error::Profile)?;
                    if !self.ready() || !io.packet_ready() {
                        return Err(Error::Busy);
                    }
                    let c21 = self.ht.as_ref().ok_or(Error::State)?.rx_ba_identity().2 == 0xc821;
                    if !super::super::tx_ba::fifo_empty(io, c21)? {
                        return Err(Error::Busy);
                    }
                    io.station_profile_readback()?;
                    g.set(value, self.data_profile.rates)?;
                    Ok(())
                })())
            })
            .map_err(Error::Native)
            .and_then(|r| r);
        if result.as_ref().is_err_and(|e| {
            !matches!(
                e,
                Error::Busy
                    | Error::Profile
                    | Error::Native(firmware_transport::Error::Unsupported)
            )
        }) {
            self.fail(io);
        }
        result
    }
    fn next_qos(&self) -> Result<u16, Error> {
        if !self.receive_open() {
            return Err(Error::State);
        }
        match &self.security {
            Some(s) => s.next_qos_sequence(0).map_err(Error::Security),
            None => Ok(self.qos_sequence),
        }
    }
    pub(super) fn service_tx_ba(
        &mut self,
        io: &mut impl Io,
        now: u64,
        idle: bool,
    ) -> Result<(), Error> {
        let grant = self.tx_ba_grant.clone();
        if grant.is_none() && self.data_drain.is_none() {
            return Ok(());
        }
        let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        let c21 = self.ht.as_ref().ok_or(Error::State)?.rx_ba_identity().2 == 0xc821;
        if grant.is_some() {
            self.tx_ba.tick(now, self.own, ap);
        }
        // Single RTS DATA has the same actual CCX plus MAC drain contract as
        // a T burst. A pending native control/data slot is never quiet.
        let quiet = self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.data_pending.is_empty()
            && super::super::tx_ba::fifo_empty(io, c21)?;
        if let Some(start) = self.data_drain {
            if quiet {
                self.data_drain = None;
                if self.receive_open() && self.tx_ba.active().is_some() {
                    let ssn = self.next_qos()?;
                    self.tx_ba.queue_bar(self.own, ap, ssn, now)?;
                }
            } else if now.saturating_sub(start) >= 1000 {
                return Err(Error::Timeout);
            }
        }
        let Some(g) = grant else {
            return Ok(());
        };
        if self.pending.is_some() || !quiet || self.data_drain.is_some() {
            return Ok(());
        }
        if self.tx_ba.active().is_none() && self.tx_config.is_some() {
            io.packet_aggregation(None)?;
            self.tx_config = None;
        }
        if !self.receive_open() || !idle {
            return Ok(());
        }
        g.check()?;
        super::super::tx_ba::readback(io)?;
        let ssn = self.next_qos()?;
        if self.tx_ba.can_begin() && self.security.as_ref().is_none_or(|s| !s.handshake_active()) {
            self.tx_ba.begin(self.own, ap, ssn, g.window(), now)?;
        } else if self.tx_ba.idle(now, self.own, ap, ssn)? {
            let negotiated = self
                .plan
                .as_ref()
                .and_then(JoinPlan::negotiated_phy)
                .ok_or(Error::Profile)?;
            let density = negotiated.ht().peer_mpdu_density();
            let window = self.tx_ba.active().ok_or(Error::State)?;
            let (bytes, airtime) = g.limits();
            let cfg = super::super::packet_format::Aggregation {
                density,
                count: g.count().min(usize::from(window)) as u8,
                bytes,
                airtime,
            };
            io.packet_aggregation(Some(cfg))?;
            self.tx_config = Some(cfg);
        }
        Ok(())
    }
    pub(in crate::rtw88) fn batch_capacity(&self) -> usize {
        if !self.ready() {
            return 0;
        }
        self.tx_config
            .filter(|_| self.tx_ba.active().is_some())
            .map_or(1, |c| usize::from(c.count))
    }
    pub(in crate::rtw88) fn batch_active(&self) -> bool {
        self.tx_config.is_some() && self.tx_ba.active().is_some()
    }
    /// Produce exact headers/PNs only after reserving native batch capacity.
    /// A failed publication consumes those values and terminally closes; no
    /// protected header or immutable ciphertext is rewritten for a retry.
    pub(in crate::rtw88) fn send_batch(
        &mut self,
        io: &mut impl Io,
        frames: &[&[u8]],
    ) -> Result<usize, Error> {
        let admission = self.admission.clone();
        let result = admission
            .run(|| Ok(self.send_batch_inner(io, frames)))
            .map_err(Error::Native)
            .and_then(|r| r);
        if result.as_ref().is_err_and(|e| {
            !matches!(
                e,
                Error::Busy | Error::Profile | Error::Transport(packet::Error::Busy)
            )
        }) {
            self.fail(io);
        }
        result
    }
    pub(super) fn send_batch_inner(
        &mut self,
        io: &mut impl Io,
        frames: &[&[u8]],
    ) -> Result<usize, Error> {
        self.coding_live(io)?;
        io.station_allowed()?;
        let cfg = self.tx_config.ok_or(Error::State)?;
        if !self.ready() || self.tx_ba.active().is_none() || !io.packet_ready() {
            return Err(Error::Busy);
        }
        let c21 = self.ht.as_ref().ok_or(Error::State)?.rx_ba_identity().2 == 0xc821;
        if !super::super::tx_ba::fifo_empty(io, c21)? {
            return Err(Error::Busy);
        }
        let mut native = Vec::new();
        native
            .try_reserve_exact(frames.len().min(usize::from(cfg.count)))
            .map_err(|_| Error::State)?;
        let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        for ethernet in frames.iter().take(usize::from(cfg.count)) {
            if !admitted(ethernet, self.own) {
                return Err(Error::Profile);
            }
            // Budget the real resulting QoS/CCMP/FCS size before consuming
            // sequence/PN. Existing Ethernet admission bounds this length.
            let length = ethernet.len() + 20 + if self.security.is_some() { 16 } else { 0 };
            let mut sizes = [0; 4];
            for (i, b) in native.iter().enumerate() {
                sizes[i] = Vec::len(b);
            }
            sizes[native.len()] = length;
            if !cfg.admits_lengths(self.data_profile, sizes[..=native.len()].iter().copied()) {
                break;
            }
            let expected = self.next_qos()?;
            let bytes = if let Some(s) = &mut self.security {
                s.transmit_ethernet_qos(ethernet, 0)?
            } else {
                let mut b = vec![0x88, 1, 0, 0];
                b.extend_from_slice(&ap);
                b.extend_from_slice(&self.own);
                b.extend_from_slice(&ethernet[..6]);
                b.extend_from_slice(&(expected << 4).to_le_bytes());
                b.extend_from_slice(&[0, 0, 0xaa, 0xaa, 3, 0, 0, 0]);
                b.extend_from_slice(&ethernet[12..]);
                self.qos_sequence = (expected + 1) & 4095;
                b
            };
            if bytes.len() != length || u16::from_le_bytes([bytes[22], bytes[23]]) >> 4 != expected
            {
                return Err(Error::State);
            }
            native.push(bytes);
        }
        if native.is_empty() {
            return Err(Error::Profile);
        }
        let ids = io.packet_submit_batch(&native)?;
        if ids.len() != native.len() {
            return Err(Error::State);
        }
        let now = self.now()?;
        for (id, bytes) in ids.into_iter().zip(native) {
            self.data_pending.push_back(Pending {
                id,
                bytes,
                kind: Kind::Data,
            });
        }
        self.data_drain = Some(now);
        self.tx_ba.note_tx(now);
        Ok(self.data_pending.len())
    }
}
