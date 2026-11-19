// SPDX-License-Identifier: GPL-2.0-or-later
//! TX-only ordered aggregation under the actual station's admission lock.
use super::*;

impl State {
    pub(super) fn send_amsdu_inner(
        &mut self,
        io: &mut impl Io,
        frames: &[&[u8]],
    ) -> Result<Option<usize>, Error> {
        if frames.len() < 2
            || !self.ready()
            || !self.ht
            || !self.ampdu
            || self.wmm.is_none()
            || !self.rx_idle
            || !io.station_amsdu_allowed()?
        {
            return Ok(None);
        }
        let phy = self
            .plan
            .as_ref()
            .and_then(JoinPlan::negotiated_phy)
            .ok_or(Error::State)?;
        let limit = narf_wireless::amsdu::Limit::from_ht_capability(phy.ht().peer_capability());
        let maximum = limit
            .bytes()
            .min(super::super::tx_amsdu::MAX_BODY)
            .min(self.amsdu_rc.unwrap_or(super::super::tx_amsdu::MAX_BODY));
        let tid = self.tid(frames[0]);
        if !self.originator.amsdu_allowed(tid) {
            return Ok(None);
        }
        if self.originator.holding(tid) {
            return Err(Error::Busy);
        }
        let agg = self
            .originator
            .aggregating(tid)
            .map(|buf| super::super::packet_format::Agg {
                num: (buf - 1) as u8,
                density: self.density,
            });
        // Peer receive-direction permission, independent of our unchanged RX
        // advertisement. HE's explicit nested permission is mandatory too.
        if agg.is_some()
            && phy
                .he()
                .is_some_and(|he| he.peer_capability().mac_capability()[4] & 0x40 == 0)
        {
            return Ok(None);
        }
        let mut count = 0;
        let mut body = Vec::new();
        for (index, frame) in frames
            .iter()
            .take(super::super::tx_amsdu::PREFIX)
            .enumerate()
        {
            if !admitted(frame, self.own) || self.tid(frame) != tid {
                break;
            }
            let Ok(encoded) = narf_wireless::amsdu::encode(&frames[..=index], self.own, limit)
            else {
                break;
            };
            if encoded.len() > maximum {
                break;
            }
            count = index + 1;
            body = encoded;
        }
        if count < 2 {
            return Ok(None);
        }
        // No sequence/PN is consumed until the whole exact prefix, current
        // native program, peer/port and actual queue credit have been checked.
        if !self.transmit_room(Kind::Data, agg)
            || agg.is_some() && !io.packet_ready_aggregate()
            || agg.is_none() && !io.packet_ready()
        {
            return Err(Error::Busy);
        }
        let bytes = if let Some(security) = self.security.as_mut() {
            security.transmit_amsdu_qos(&frames[..count], tid, limit)?
        } else {
            let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
            let mut bytes = vec![0x88, 1, 0, 0];
            bytes.extend_from_slice(&peer);
            bytes.extend_from_slice(&self.own);
            bytes.extend_from_slice(&peer);
            bytes.extend_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
            bytes.extend_from_slice(&[0x80 | tid, 0]);
            bytes.extend_from_slice(&body);
            bytes
        };
        self.transmit_with(io, bytes, Kind::Data, true, agg)?;
        if agg.is_none() {
            self.originator.want(tid, self.last_now);
        }
        Ok(Some(count))
    }
}
