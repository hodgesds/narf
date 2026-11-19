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
    pub(in crate::rtw88) async fn set_rts_threshold(
        &mut self,
        io: &mut impl Io,
        value: u32,
    ) -> Result<(), Error> {
        let admission = self.admission.clone();
        let result = crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
            io.station_allowed()?;
            Ok(async {
                let g = self.protection.as_ref().ok_or(Error::Profile)?;
                if !self.ready() || !io.packet_ready() {
                    return Err(Error::Busy);
                }
                let c21 = self.ht.as_ref().ok_or(Error::State)?.rx_ba_identity().2 == 0xc821;
                if !self.tx_fifo_empty(io, c21).await? {
                    return Err(Error::Busy);
                }
                io.station_profile_readback().await?;
                g.set(value, self.data_profile.rates)?;
                Ok(())
            }
            .await)
        })
        .await
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
    pub(super) fn data_tid(&self, frame: &[u8]) -> u8 {
        let acm = self
            .wmm
            .map_or([false; 4], |p| p.ac.map(|a| a.admission_control));
        super::super::qos::tid_for(frame, acm, self.data_profile)
    }
    fn next_qos(&self, tid: u8) -> Result<u16, Error> {
        if !self.receive_open() || tid >= 8 {
            return Err(Error::State);
        }
        match &self.security {
            Some(s) => s.next_qos_sequence(tid).map_err(Error::Security),
            None => Ok(self.qos_sequence[usize::from(tid)]),
        }
    }
    async fn tx_fifo_empty(
        &self,
        io: &mut impl Io,
        c21: bool,
    ) -> Result<bool, firmware_transport::Error> {
        super::super::tx_ba::fifo_empty_tids(
            io,
            c21,
            self.tx_ba_grant.as_ref().map_or(1, |g| g.tids()),
        )
        .await
    }
    fn aggregate_config(&self, tid: u8) -> Result<super::super::packet_format::Aggregation, Error> {
        let g = self.tx_ba_grant.as_ref().ok_or(Error::State)?;
        let window = self.tx_ba.active(tid).ok_or(Error::State)?;
        let phy = self
            .plan
            .as_ref()
            .and_then(JoinPlan::negotiated_phy)
            .ok_or(Error::Profile)?;
        let (bytes, airtime) = g.limits();
        Ok(super::super::packet_format::Aggregation {
            density: phy.ht().peer_mpdu_density(),
            count: g.count().min(usize::from(window)) as u8,
            bytes,
            airtime,
        })
    }
    pub(super) async fn service_tx_ba(
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
        let quiet = self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.data_pending.is_empty()
            && self.tx_fifo_empty(io, c21).await?;
        if let Some((start, tid)) = self.data_drain {
            if quiet {
                self.data_drain = None;
                if let Some(tid) =
                    tid.filter(|&tid| self.receive_open() && self.tx_ba.active(tid).is_some())
                {
                    let ssn = self.next_qos(tid)?;
                    self.tx_ba.queue_bar(tid, self.own, ap, ssn, now)?;
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
        if !self.tx_ba.any_active() && self.tx_config.is_some() {
            io.packet_aggregation(None)?;
            self.tx_config = None;
        }
        if !self.receive_open() || !idle {
            return Ok(());
        }
        g.check()?;
        super::super::tx_ba::readback(io).await?;
        for tid in 0..6 {
            if g.tids() & (1 << tid) == 0 {
                continue;
            }
            let ssn = self.next_qos(tid)?;
            if self.tx_ba.idle(tid, now, self.own, ap, ssn)? {
                let cfg = self.aggregate_config(tid)?;
                io.packet_aggregation(Some(cfg))?;
                self.tx_config = Some(cfg);
            }
        }
        if self.security.as_ref().is_none_or(|s| !s.handshake_active()) {
            for tid in 0..6 {
                if g.tids() & (1 << tid) != 0 && self.tx_ba.can_begin(tid) {
                    let ssn = self.next_qos(tid)?;
                    self.tx_ba.begin(tid, self.own, ap, ssn, g.window(), now)?;
                    break;
                }
            }
        }
        Ok(())
    }
    pub(in crate::rtw88) fn batch_capacity(&self) -> usize {
        if !self.ready() {
            return 0;
        }
        // An aggregation prefix (up to four A-MPDU subframes of A-MSDUs);
        // the interface never hands more than 16 frames.
        if self.amsdu_ready() {
            return 16;
        }
        self.tx_ba_grant
            .as_ref()
            .filter(|_| self.tx_ba.any_active())
            .map_or(1, |g| g.count())
    }
    pub(in crate::rtw88) fn batch_active(&self) -> bool {
        self.tx_config.is_some() && self.tx_ba.any_active() || self.amsdu_ready()
    }
    /// Produce exact headers/PNs only after reserving native batch capacity.
    /// A failed publication consumes those values and terminally closes; no
    /// protected header or immutable ciphertext is rewritten for a retry.
    pub(in crate::rtw88) async fn send_batch(
        &mut self,
        io: &mut impl Io,
        frames: &[&[u8]],
    ) -> Result<usize, Error> {
        let admission = self.admission.clone();
        let result = crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
            Ok(self.send_batch_inner(io, frames).await)
        })
        .await
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
    pub(super) async fn send_batch_inner(
        &mut self,
        io: &mut impl Io,
        frames: &[&[u8]],
    ) -> Result<usize, Error> {
        self.coding_live(io)?;
        self.qos_live(io)?;
        self.fallback_live(io)?;
        self.txrx_1ss_live(io)?;
        io.station_allowed()?;
        let first = *frames.first().ok_or(Error::Profile)?;
        if !admitted(first, self.own) {
            return Err(Error::Profile);
        }
        let tid = self.data_tid(first);
        if self.tx_ba.active(tid).is_none() {
            // 5GHz: one A-MSDU MPDU of the same-TID admitted prefix.
            if let Some(count) = self.send_amsdu_inner(io, frames, tid)? {
                return Ok(count);
            }
            // Consume only the original FIFO head. A different TID/VO/EAPOL
            // cannot be relabelled into an already active TID0 agreement.
            self.send_inner(io, first).await?;
            return Ok(1);
        }
        let cfg = self.aggregate_config(tid)?;
        if !self.ready() || !io.packet_ready() {
            return Err(Error::Busy);
        }
        let c21 = self.ht.as_ref().ok_or(Error::State)?.rx_ba_identity().2 == 0xc821;
        if !self.tx_fifo_empty(io, c21).await? {
            return Err(Error::Busy);
        }
        io.packet_aggregation(Some(cfg))?;
        self.tx_config = Some(cfg);
        // Each A-MPDU subframe is one MSDU or (5GHz, peer-permitted) one
        // A-MSDU of the next same-TID prefix. Every byte/airtime bound is
        // checked before consuming any producer sequence or packet-key PN.
        let mut selected: Vec<(usize, usize, usize)> = Vec::new();
        selected
            .try_reserve_exact(usize::from(cfg.count))
            .map_err(|_| Error::State)?;
        let mut sizes = [0; 4];
        let mut at = 0;
        while at < frames.len() && selected.len() < usize::from(cfg.count) {
            let ethernet = frames[at];
            if !admitted(ethernet, self.own) {
                return Err(Error::Profile);
            }
            if self.data_tid(ethernet) != tid {
                break;
            }
            let slot = selected.len();
            let fits = |length: usize| {
                let mut s = sizes;
                s[slot] = length;
                cfg.admits_lengths(self.data_profile, s[..=slot].iter().copied())
            };
            let (count, length) = self.amsdu_prefix(&frames[at..], tid, fits).unwrap_or((
                1,
                ethernet.len() + 20 + if self.security.is_some() { 16 } else { 0 },
            ));
            sizes[slot] = length;
            if !cfg.admits_lengths(self.data_profile, sizes[..=slot].iter().copied()) {
                break;
            }
            selected.push((at, count, length));
            at += count;
        }
        if selected.is_empty() {
            return Err(Error::Profile);
        }
        let mut native = Vec::new();
        native
            .try_reserve_exact(selected.len())
            .map_err(|_| Error::State)?;
        let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        for (start, count, length) in selected {
            let expected = self.next_qos(tid)?;
            let bytes = if count > 1 {
                let b = self.amsdu_mpdu(&frames[start..start + count], tid, expected)?;
                if self.security.is_none() {
                    self.qos_sequence[usize::from(tid)] = (expected + 1) & 4095;
                }
                b
            } else if let Some(s) = &mut self.security {
                s.transmit_ethernet_qos(frames[start], tid)?
            } else {
                let ethernet = frames[start];
                let mut b = vec![0x88, 1, 0, 0];
                b.extend_from_slice(&ap);
                b.extend_from_slice(&self.own);
                b.extend_from_slice(&ethernet[..6]);
                b.extend_from_slice(&(expected << 4).to_le_bytes());
                b.extend_from_slice(&[tid, 0, 0xaa, 0xaa, 3, 0, 0, 0]);
                b.extend_from_slice(&ethernet[12..]);
                self.qos_sequence[usize::from(tid)] = (expected + 1) & 4095;
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
        self.data_drain = Some((now, Some(tid)));
        self.tx_ba.note_tx(tid, now);
        Ok(at)
    }
}
