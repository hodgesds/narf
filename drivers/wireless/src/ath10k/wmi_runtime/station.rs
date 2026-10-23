// SPDX-License-Identifier: GPL-2.0-or-later
//! One-shot owned station hardware preparation. No association/key/link state.
use super::*;
use crate::ath10k::regulatory::Permission;

#[derive(Debug)]
pub(super) struct Peer {
    permission: Permission,
    bssid: [u8; 6],
    ids: [u64; 32],
}
impl Peer {
    fn mapped(&self) -> Option<u16> {
        self.ids
            .iter()
            .enumerate()
            .find_map(|(i, b)| (*b != 0).then(|| (i * 64 + b.trailing_zeros() as usize) as u16))
    }
    fn record(&mut self, b: &[u8]) -> Result<bool, Error> {
        match b.first() {
            Some(3) => {
                if b.len() != 12 {
                    return Err(Error::Malformed);
                }
                let id = u16::from_le_bytes([b[2], b[3]]);
                if id >= 2048 {
                    return Err(Error::Malformed);
                }
                if b[1] != 0 || b[4..10] != self.bssid {
                    if self.ids[usize::from(id) / 64] & (1u64 << (id % 64)) != 0 {
                        return Err(Error::Malformed);
                    }
                    return Ok(false);
                }
                self.ids[usize::from(id) / 64] |= 1u64 << (id % 64);
                Ok(true)
            }
            Some(4) => {
                if b.len() != 4 {
                    return Err(Error::Malformed);
                }
                let id = u16::from_le_bytes([b[2], b[3]]);
                if id >= 2048 {
                    return Err(Error::Malformed);
                }
                let word = &mut self.ids[usize::from(id) / 64];
                let bit = 1u64 << (id % 64);
                let matched = *word & bit != 0;
                *word &= !bit;
                Ok(matched)
            }
            _ => Ok(false),
        }
    }
}
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub fn prepared_peer(&self) -> Option<PeerPrepared> {
        if self.failed {
            return None;
        }
        let peer = self.peer.as_ref()?;
        Some(PeerPrepared {
            bssid: peer.bssid,
            frequency: peer.permission.frequency,
            peer_id: peer.mapped()?,
            maximum_power_dbm: peer.permission.half_dbm / 2,
        })
    }
    /// The native bridge supplies only the installed authenticated host
    /// policy. Select the exact BSS captured by a completed passive scan.
    pub async fn prepare_station(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        bssid: [u8; 6],
        frequency: u16,
    ) -> Result<PeerPrepared, Error> {
        if self.failed || self.ready.is_none() || self.peer.is_some() {
            return Err(Error::Failed);
        }
        let bss = self
            .scan_cache
            .iter()
            .find(|b| b.bssid == bssid && b.frequency == frequency)
            .ok_or(Error::Unsupported)?;
        let mut dtim = 1;
        let mut seen = false;
        let mut ies = bss.information_elements.as_slice();
        while !ies.is_empty() {
            let h = ies.get(..2).ok_or(Error::Malformed)?;
            let n = usize::from(h[1]);
            let body = ies.get(2..2 + n).ok_or(Error::Malformed)?;
            if h[0] == 5 {
                if seen || body.len() < 4 || body[1] == 0 || body[0] >= body[1] {
                    return Err(Error::Malformed);
                }
                seen = true;
                dtim = body[1];
            }
            ies = &ies[2 + n..];
        }
        let permission = Permission::from_domain(
            self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?,
            domain,
            frequency,
        )?;
        let rd = self.wire.domain(permission)?;
        let power = self.wire.power(permission)?;
        let start = self
            .wire
            .start_station(permission, bss.beacon_interval, dtim)?;
        let create = self.wire.peer(bssid)?;
        self.peer = Some(Peer {
            permission,
            bssid,
            ids: [0; 32],
        });
        // Even an unsent/ambiguous START cannot be retried under this owner.
        // The nested native mission transport retains all published DMA.
        self.failed = true;
        for command in [&rd, &power, &start] {
            self.htt
                .wmi
                .htc
                .send_wmi(command)
                .await
                .map_err(htt::Error::from)?;
        }
        let deadline = narf_time::Deadline::after_ms(5_000);
        let mut started = false;
        for _ in 0..65_536 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = self.htt.poll().await?;
            match event {
                htt::Event::Wmi(bytes)
                    if wire::word(&bytes, 0)? & 0xffffff == self.wire.start_response_id() =>
                {
                    if self.wire.start_response(&bytes[4..])?.is_some() {
                        started = true;
                        break;
                    }
                }
                htt::Event::Idle => narf_scheduler::yield_now().await,
                other => self.queue(other)?,
            }
        }
        if !started {
            return Err(Error::Timeout);
        }
        self.htt
            .wmi
            .htc
            .send_wmi(&create)
            .await
            .map_err(htt::Error::from)?;
        let deadline = narf_time::Deadline::after_ms(5_000);
        for _ in 0..65_536 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = self.station_progress().await?;
            match event {
                htt::Event::Idle => {
                    if let Some(id) = self.peer.as_ref().and_then(Peer::mapped) {
                        self.failed = false;
                        return Ok(PeerPrepared {
                            bssid,
                            frequency,
                            peer_id: id,
                            maximum_power_dbm: permission.half_dbm / 2,
                        });
                    }
                    narf_scheduler::yield_now().await;
                }
                other => self.queue(other)?,
            }
        }
        Err(Error::Timeout)
    }
    async fn station_progress(&mut self) -> Result<htt::Event, Error> {
        let event = self.htt.poll().await?;
        if let htt::Event::Message(bytes) = &event {
            if self.peer.as_mut().ok_or(Error::Failed)?.record(bytes)? {
                return Ok(htt::Event::Idle);
            }
        }
        Ok(event)
    }
    /// The future station worker must drive this same retained event path.
    /// No peer-map event authenticates an association or opens a data port.
    pub async fn poll_station(&mut self) -> Result<htt::Event, Error> {
        if self.failed || self.peer.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        let event = self.station_progress().await?;
        self.failed = false;
        Ok(event)
    }
}
