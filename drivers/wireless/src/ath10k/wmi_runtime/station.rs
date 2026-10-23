// SPDX-License-Identifier: GPL-2.0-or-later
//! One-shot owned station hardware preparation. No association/key/link state.
use super::*;
use crate::ath10k::regulatory::Permission;

#[derive(Debug)]
pub(super) struct Peer {
    permission: Permission,
    bssid: [u8; 6],
    ids: [u64; 32],
    exchange_stage: u8,
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
            exchange_stage: 0,
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
            // Continuous ready events must not monopolize the retained owner.
            narf_scheduler::yield_now().await;
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
            // Continuous ready events must not monopolize the retained owner.
            narf_scheduler::yield_now().await;
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
    /// Initial MLME frames are bound to the prepared BSS and current host
    /// policy. No data/PMF/offchannel frame is accepted by this transport stage.
    pub async fn transmit_management(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frame: &[u8],
    ) -> Result<ManagementReceipt, Error> {
        if self.failed || self.prepared_peer().is_none() {
            return Err(Error::Failed);
        }
        let peer = self.peer.as_ref().ok_or(Error::Failed)?;
        let permission = Permission::from_domain(
            self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?,
            domain,
            peer.permission.frequency,
        )?;
        if permission != peer.permission {
            return Err(Error::Unsupported);
        }
        management::validate(frame, self.ready.ok_or(Error::Failed)?.mac, peer.bssid)?;
        if frame[0] == 0 {
            let bss = self
                .scan_cache
                .iter()
                .find(|b| b.bssid == peer.bssid && b.frequency == permission.frequency)
                .ok_or(Error::Failed)?;
            let mut ies = &frame[28..];
            while !ies.is_empty() {
                let n = usize::from(ies[1]);
                if ies[0] == 0 && ies[2..2 + n] != bss.ssid {
                    return Err(Error::Unsupported);
                }
                ies = &ies[2 + n..];
            }
        }
        let path = management::path(
            self.wire.dialect,
            self.features,
            self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?,
        )?;
        self.failed = true;
        let receipt = match path {
            management::Path::Htt => {
                let id = self
                    .htt
                    .transmit(
                        htt::tx::Parameters {
                            kind: htt::tx::Kind::Management,
                            vdev: 0,
                            tid: 17,
                            hardware_crypto: false,
                        },
                        frame,
                    )
                    .await?;
                ManagementReceipt {
                    token: ManagementToken::Htt(id),
                    terminal_expected: true,
                }
            }
            management::Path::Inline(command) => {
                let command = management::inline(command, frame)?;
                self.htt
                    .wmi
                    .htc
                    .send_wmi(&command)
                    .await
                    .map_err(htt::Error::from)?;
                ManagementReceipt {
                    token: ManagementToken::Inline,
                    terminal_expected: false,
                }
            }
            management::Path::Reference => {
                let (id, address) = self.htt.wmi.htc.transport.prepare_wmi_management(frame)?;
                let command = management::reference(id, address, frame)?;
                self.htt
                    .wmi
                    .htc
                    .send_wmi(&command)
                    .await
                    .map_err(htt::Error::from)?;
                ManagementReceipt {
                    token: ManagementToken::Wmi(id),
                    terminal_expected: true,
                }
            }
        };
        self.failed = false;
        Ok(receipt)
    }
    /// Own the first Open-System Authentication and Association responses.
    /// This advances no WMI association/key state and grants no data port.
    /// Each exchange is one-shot: cancellation or malformed/error completion
    /// closes this radio until an owned reset reconstructs it.
    pub async fn exchange_initial_management(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frame: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.failed || self.prepared_peer().is_none() {
            return Err(Error::Failed);
        }
        let peer = self.peer.as_ref().ok_or(Error::Failed)?;
        let expected = match (peer.exchange_stage, frame.first().copied()) {
            (0, Some(0xb0)) => 0xb0,
            (1, Some(0)) => 0x10,
            _ => return Err(Error::Unsupported),
        };
        let bssid = peer.bssid;
        let frequency = peer.permission.frequency;
        let own = self.ready.ok_or(Error::Failed)?.mac;
        self.transmit_management(domain, frame).await?;
        self.failed = true;
        let deadline = narf_time::Deadline::after_ms(3000);
        for _ in 0..65_536 {
            // Native CE/HTC polling may stay immediately ready under a
            // management RX flood. Every iteration must yield with this
            // same failed/retained owner, including discarded responses.
            narf_scheduler::yield_now().await;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = self.station_progress().await?;
            if self.peer.as_ref().and_then(Peer::mapped).is_none() {
                return Err(Error::Failed);
            }
            match event {
                htt::Event::Wmi(bytes)
                    if wire::word(&bytes, 0)? & 0xffffff == self.wire.management_event =>
                {
                    let rx = self.wire.management(&bytes[4..], self.features)?;
                    let f = &rx.frame;
                    if rx.status & !0x40 != 0
                        || wire::channel_to_frequency(rx.channel) != Some(frequency)
                        || f.len() < 30
                        || f[0] != expected
                        || u16::from_le_bytes([f[0], f[1]]) & 0xc700 != 0
                        || f[22] & 15 != 0
                        || f[4..10] != own
                        || f[10..16] != bssid
                        || f[16..22] != bssid
                    {
                        continue;
                    }
                    let status = if expected == 0xb0 {
                        if f[24..28] != [0, 0, 2, 0] {
                            continue;
                        }
                        u16::from_le_bytes([f[28], f[29]])
                    } else {
                        u16::from_le_bytes([f[26], f[27]])
                    };
                    if status != 0 {
                        return Err(Error::Firmware(u32::from(status)));
                    }
                    self.peer.as_mut().ok_or(Error::Failed)?.exchange_stage += 1;
                    self.failed = false;
                    return Ok(rx.frame);
                }
                htt::Event::Idle => {}
                other => self.queue(other)?,
            }
        }
        Err(Error::Timeout)
    }
    pub fn take_management_completion(&mut self) -> Option<ManagementCompletion> {
        self.management_done.pop_front()
    }
    async fn station_progress(&mut self) -> Result<htt::Event, Error> {
        let event = self.htt.poll().await?;
        if let htt::Event::Wmi(bytes) = &event {
            if self.wire.dialect == Dialect::Tlv {
                if let Some(reports) = management::completions(bytes)? {
                    if self.management_done.len() + reports.len() > 128 {
                        return Err(Error::Exhausted);
                    }
                    self.management_done
                        .try_reserve(reports.len())
                        .map_err(|_| Error::NoMemory)?;
                    let mut ids = Vec::new();
                    ids.try_reserve_exact(reports.len())
                        .map_err(|_| Error::NoMemory)?;
                    ids.extend(reports.iter().map(|r| r.id));
                    self.htt.wmi.htc.transport.complete_wmi_management(&ids)?;
                    self.management_done.extend(reports);
                    return Ok(htt::Event::Idle);
                }
            }
        }
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
