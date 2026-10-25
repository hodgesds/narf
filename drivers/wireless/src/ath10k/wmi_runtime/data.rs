// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RAW-mode station packets. Firmware receipts, RSNA and packet keys
//! have separate ownership; an associated peer alone never admits Ethernet.
use super::*;
use crate::ath10k::regulatory::Permission;
use narf_wireless::station_security::{RawFrame, Rx, Security};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub bssid: [u8; 6],
    pub frequency: u16,
    pub protected: bool,
}
#[derive(Debug)]
struct Native(Vec<u8>);
impl RawFrame for Native {
    fn bytes(&self) -> &[u8] {
        &self.0
    }
    fn unmodified(&self) -> bool {
        true
    }
}
#[derive(Debug)]
struct Pending {
    id: u16,
    reply: bool,
    length: usize,
    deadline: narf_time::Deadline,
}
#[derive(Debug)]
pub(super) struct State {
    security: Option<Security>,
    pending: Option<Pending>,
    incoming: VecDeque<Native>,
    received: VecDeque<Vec<u8>>,
    sequence: u16,
    failed: bool,
    authorized: bool,
    last_peer: narf_time::Deadline,
}
impl State {
    pub(super) fn fail(&mut self) {
        self.failed = true;
        self.incoming.clear();
        self.received.clear();
        if let Some(security) = &mut self.security {
            security.fail();
        }
        // A failed/cancelled HTT operation retains its payload/fragment owner.
        // Do not release or pretend to complete the outstanding native ID.
    }
    fn open(&self) -> bool {
        !self.failed && self.authorized
    }
}
fn security_error(_: narf_wireless::station_security::Error) -> Error {
    Error::Malformed
}
fn element(ies: &[u8], wanted: u8) -> Result<Option<&[u8]>, Error> {
    let mut rest = ies;
    let mut found = None;
    while !rest.is_empty() {
        let head = rest.get(..2).ok_or(Error::Malformed)?;
        let length = usize::from(head[1]);
        let body = rest.get(2..2 + length).ok_or(Error::Malformed)?;
        if head[0] == wanted {
            if found.is_some() {
                return Err(Error::Malformed);
            }
            found = Some(body);
        }
        rest = &rest[2 + length..];
    }
    Ok(found)
}
fn ethernet(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < 32
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || frame[4..10] != own && frame[4] & 1 == 0
        || frame[16..22] == [0; 6]
        || frame[16] & 1 != 0
    {
        return None;
    }
    let header = if frame[0] == 0x88 { 26 } else { 24 };
    if header == 26 && frame.get(24).is_none_or(|qos| qos & 0x80 != 0) {
        return None;
    }
    let snap = frame.get(header..header + 8)?;
    let protocol = u16::from_be_bytes([snap[6], snap[7]]);
    if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0]
        || protocol < 0x600
        || matches!(protocol, 0x888e | 0x80f3 | 0x8137)
        || frame.len() - header + 6 > 1514
    {
        return None;
    }
    let mut out = frame[4..10].to_vec();
    out.extend_from_slice(&frame[16..22]);
    out.extend_from_slice(&frame[header + 6..]);
    Some(out)
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub fn has_station_data(&self) -> bool {
        self.data.is_some()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn expire_data_for_test(&mut self) {
        if let Some(data) = &mut self.data {
            data.last_peer = narf_time::Deadline::after_ms(0);
        }
    }
    pub fn data_supported(&self) -> bool {
        self.htt.data_profile()
    }
    pub fn station_publishable(&self) -> Result<[u8; 6], Error> {
        if !self.data_supported() {
            return Err(Error::Unsupported);
        }
        if self.failed || self.peer.is_some() || self.data.is_some() {
            return Err(Error::Failed);
        }
        Ok(self.ready.ok_or(Error::Failed)?.mac)
    }
    pub fn fail_station_data(&mut self) {
        self.failed = true;
        if let Some(data) = &mut self.data {
            data.fail();
        }
    }
    pub fn station_link(&self) -> Option<Link> {
        if !self.data.as_ref()?.open() {
            return None;
        }
        let associated = self.associated_station()?;
        Some(Link {
            bssid: associated.bssid,
            frequency: associated.frequency,
            protected: associated.protected,
        })
    }
    pub(in crate::ath10k) fn check_data_policy(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        let peer = self.peer.as_ref().ok_or(Error::Failed)?;
        let permission = Permission::from_domain(
            self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?,
            domain,
            peer.permission.frequency,
        )?;
        if permission != peer.permission {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    /// Start the packet owner only after native association. Software CCMP is
    /// selected at WMI INIT, never retrofitted onto a native-WiFi/decapped RX
    /// image. PFC requires a separate host queue/fetch owner and stays gated.
    pub async fn start_station_data(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        pmk: Option<&[u8; 32]>,
    ) -> Result<Link, Error> {
        self.start_data_with_nonce(domain, pmk, || {
            let mut nonce = [0; 32];
            narf_crypto::try_fill_random_bytes(&mut nonce)
                .ok()
                .map(|()| nonce)
        })
        .await
    }
    pub(in crate::ath10k) async fn start_data_with_nonce(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        pmk: Option<&[u8; 32]>,
        mut nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Link, Error> {
        let associated = self.associated_station().ok_or(Error::Failed)?;
        if self.data.is_some() || !self.htt.data_profile() {
            return Err(Error::Unsupported);
        }
        if associated.protected != pmk.is_some() {
            return Err(Error::Unsupported);
        }
        self.check_data_policy(domain)?;
        let own = self.ready.ok_or(Error::Failed)?.mac;
        let cached = self
            .scan_cache
            .iter()
            .find(|b| b.bssid == associated.bssid && b.frequency == associated.frequency)
            .ok_or(Error::Failed)?;
        let security = match pmk {
            Some(pmk) => Some(
                Security::new(
                    own,
                    associated.bssid,
                    pmk,
                    &narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body(),
                    element(&cached.information_elements, 48)?.ok_or(Error::Unsupported)?,
                    element(&cached.information_elements, 244)?,
                    2,
                )
                .map_err(security_error)?,
            ),
            None => None,
        };
        self.failed = true;
        let mut incoming = VecDeque::new();
        // An AP may send M1 before PEER_ASSOC/UP's receive drain ends. Retain
        // only exact descriptor-bound, unprotected unicast EAPOL for the new
        // supplicant. Association-era IP can never become authorized later.
        let peer = self.peer.as_ref().ok_or(Error::Failed)?;
        for event in core::mem::take(&mut self.pending) {
            let frames = match event {
                htt::Event::Rx(batch) if security.is_some() && peer.owns(batch.peer) => batch
                    .frames
                    .into_iter()
                    .map(|(status, frame)| (status, batch.peer, batch.tid, frame))
                    .collect::<Vec<_>>(),
                htt::Event::InOrder(i, frames)
                    if security.is_some()
                        && peer.owns(i.peer)
                        && i.vdev == 0
                        && !i.offload
                        && !i.fragment =>
                {
                    frames
                        .into_iter()
                        .map(|frame| (1, i.peer, i.tid, frame))
                        .collect()
                }
                htt::Event::Rx(_) | htt::Event::InOrder(_, _) => Vec::new(),
                other => {
                    self.pending.push_back(other);
                    Vec::new()
                }
            };
            for (status, id, tid, frame) in frames {
                if let Some(frame) = raw_frame(frame, status, id, tid, own, associated.bssid)? {
                    let bytes = &frame.0;
                    let at = if bytes[0] == 0x88 { 26 } else { 24 };
                    if bytes[1] & 0x40 == 0
                        && bytes[4..10] == own
                        && bytes[16..22] == associated.bssid
                        && bytes.get(at..at + 8) == Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e])
                    {
                        if incoming.len() == 64 {
                            return Err(Error::Exhausted);
                        }
                        incoming.push_back(frame);
                    }
                }
            }
        }
        while self.htt.take_tx_receipt().is_some() {}
        self.data = Some(State {
            security,
            pending: None,
            incoming,
            received: VecDeque::new(),
            sequence: 2,
            failed: false,
            authorized: !associated.protected,
            last_peer: narf_time::Deadline::after_ms(5000),
        });
        self.failed = true;
        let deadline = narf_time::Deadline::after_ms(5000);
        for _ in 0..65536 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let idle = self.data_step(&mut nonce).await?;
            if idle && self.data.as_ref().is_some_and(State::open) {
                self.failed = false;
                return self.station_link().ok_or(Error::Failed);
            }
            narf_scheduler::yield_now().await;
        }
        Err(Error::Timeout)
    }
    /// Publish one Ethernet packet to native HTT. The returned ID describes
    /// publication, not delivery; no second packet/reply overwrites that slot.
    pub async fn transmit_ethernet(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        bytes: &[u8],
    ) -> Result<u16, Error> {
        let frame = self.ethernet_frame(domain, bytes)?;
        self.failed = true;
        let id = self.send_data(&frame, false).await?;
        self.failed = false;
        Ok(id)
    }
    fn ethernet_frame(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let link = self.station_link().ok_or(Error::Failed)?;
        self.check_data_policy(domain)?;
        let own = self.ready.ok_or(Error::Failed)?.mac;
        let data = self.data.as_mut().ok_or(Error::Failed)?;
        if data.pending.is_some() || data.security.as_ref().is_some_and(|s| !s.port_open()) {
            return Err(Error::Htt(htt::Error::Busy));
        }
        let frame = if let Some(security) = &mut data.security {
            security.transmit_ethernet(bytes).map_err(security_error)?
        } else {
            if !(14..=1514).contains(&bytes.len())
                || bytes[6..12] != own
                || bytes[..6] == [0; 6]
                || u16::from_be_bytes([bytes[12], bytes[13]]) < 0x600
                || matches!(
                    u16::from_be_bytes([bytes[12], bytes[13]]),
                    0x888e | 0x80f3 | 0x8137
                )
            {
                return Err(Error::Unsupported);
            }
            let mut frame = alloc::vec![8, 1, 0, 0];
            frame.extend_from_slice(&link.bssid);
            frame.extend_from_slice(&own);
            frame.extend_from_slice(&bytes[..6]);
            frame.extend_from_slice(&(data.sequence << 4).to_le_bytes());
            data.sequence = (data.sequence + 1) & 4095;
            frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            frame.extend_from_slice(&bytes[12..]);
            frame
        };
        Ok(frame)
    }
    pub fn begin_ethernet(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        bytes: &[u8],
    ) -> Result<u16, Error> {
        if self.station_link().is_none() {
            return Err(Error::Failed);
        }
        if !self.htt.source_ready()? {
            return Err(Error::Htt(htt::Error::Busy));
        }
        let frame = self.ethernet_frame(domain, bytes)?;
        self.failed = true;
        let id = self.htt.begin_transmit(
            htt::tx::Parameters {
                kind: htt::tx::Kind::Raw,
                vdev: 0,
                tid: 16,
                hardware_crypto: false,
            },
            &frame,
        )?;
        self.data.as_mut().ok_or(Error::Failed)?.pending = Some(Pending {
            id,
            reply: false,
            length: frame.len(),
            deadline: narf_time::Deadline::after_ms(3000),
        });
        self.failed = false;
        Ok(id)
    }
    pub fn poll_ethernet_now(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.failed || self.associated_station().is_none() || self.data.is_none() {
            return Err(Error::Failed);
        }
        self.check_data_policy(domain)?;
        self.failed = true;
        for _ in 0..64 {
            self.data_check()?;
            let event = match self.pending.pop_front() {
                Some(e) => e,
                None => {
                    let event = self.htt.poll_now()?;
                    self.station_event(event)?
                }
            };
            let (idle, reply) = self.data_event(event, &mut || {
                let mut nonce = [0; 32];
                narf_crypto::try_fill_random_bytes(&mut nonce)
                    .ok()
                    .map(|()| nonce)
            })?;
            if let Some(reply) = reply {
                if self.htt.source_ready()? {
                    let id = self.htt.begin_transmit(
                        htt::tx::Parameters {
                            kind: htt::tx::Kind::Raw,
                            vdev: 0,
                            tid: 16,
                            hardware_crypto: false,
                        },
                        &reply,
                    )?;
                    self.data.as_mut().ok_or(Error::Failed)?.pending = Some(Pending {
                        id,
                        reply: true,
                        length: reply.len(),
                        deadline: narf_time::Deadline::after_ms(3000),
                    });
                }
            }
            if idle {
                let frames = self
                    .data
                    .as_mut()
                    .ok_or(Error::Failed)?
                    .received
                    .drain(..)
                    .collect();
                self.failed = false;
                return Ok(frames);
            }
        }
        // Bounded synchronous work preserves buffered RX until a later empty
        // receive poll fences same-batch UNMAP/deauthentication before delivery.
        self.failed = false;
        Ok(Vec::new())
    }
    async fn send_data(&mut self, frame: &[u8], reply: bool) -> Result<u16, Error> {
        let id = self
            .htt
            .transmit(
                htt::tx::Parameters {
                    kind: htt::tx::Kind::Raw,
                    vdev: 0,
                    tid: 16,
                    hardware_crypto: false,
                },
                frame,
            )
            .await?;
        self.data.as_mut().ok_or(Error::Failed)?.pending = Some(Pending {
            id,
            reply,
            length: frame.len(),
            deadline: narf_time::Deadline::after_ms(3000),
        });
        Ok(id)
    }
    /// Consume the same retained HTC/HTT owner used for join/teardown. Receive
    /// quiescence and a still-owned peer precede exposing any Ethernet batch.
    pub async fn poll_ethernet(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.failed || self.associated_station().is_none() || self.data.is_none() {
            return Err(Error::Failed);
        }
        self.check_data_policy(domain)?;
        self.failed = true;
        for _ in 0..256 {
            let idle = self
                .data_step(&mut || {
                    let mut nonce = [0; 32];
                    narf_crypto::try_fill_random_bytes(&mut nonce)
                        .ok()
                        .map(|()| nonce)
                })
                .await?;
            if idle {
                let data = self.data.as_mut().ok_or(Error::Failed)?;
                let frames = data.received.drain(..).collect();
                self.failed = false;
                return Ok(frames);
            }
            narf_scheduler::yield_now().await;
        }
        Err(Error::Exhausted)
    }
    async fn data_step(
        &mut self,
        nonce: &mut impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<bool, Error> {
        self.data_check()?;
        let event = match self.pending.pop_front() {
            Some(e) => e,
            None => self.station_progress().await?,
        };
        let (idle, reply) = self.data_event(event, nonce)?;
        if let Some(reply) = reply {
            self.send_data(&reply, true).await?;
        }
        Ok(idle)
    }
    fn data_check(&self) -> Result<(), Error> {
        if self.peer.as_ref().and_then(|p| p.associated).is_none()
            || self.peer.as_ref().and_then(station::Peer::mapped).is_none()
        {
            return Err(Error::Failed);
        }
        if self
            .data
            .as_ref()
            .and_then(|d| d.pending.as_ref())
            .is_some_and(|p| p.deadline.expired())
        {
            return Err(Error::Timeout);
        }
        if self.data.as_ref().is_some_and(|d| d.last_peer.expired()) {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    fn data_event(
        &mut self,
        event: htt::Event,
        nonce: &mut impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<(bool, Option<Vec<u8>>), Error> {
        let idle = matches!(event, htt::Event::Idle);
        let peer = self.peer.as_ref().ok_or(Error::Failed)?;
        if peer.associated.is_none() || peer.mapped().is_none() {
            return Err(Error::Failed);
        }
        let own = self.ready.ok_or(Error::Failed)?.mac;
        let bssid = peer.bssid;
        let data = self.data.as_mut().ok_or(Error::Failed)?;
        match event {
            htt::Event::Rx(batch) => {
                if peer.owns(batch.peer) {
                    for (status, frame) in batch.frames {
                        if let Some(frame) =
                            raw_frame(frame, status, batch.peer, batch.tid, own, bssid)?
                        {
                            if data.incoming.len() == 64 {
                                return Err(Error::Exhausted);
                            }
                            data.incoming.push_back(frame);
                        }
                    }
                }
            }
            htt::Event::InOrder(indication, frames) => {
                if !indication.offload
                    && !indication.fragment
                    && indication.vdev == 0
                    && peer.owns(indication.peer)
                {
                    for frame in frames {
                        if let Some(frame) =
                            raw_frame(frame, 1, indication.peer, indication.tid, own, bssid)?
                        {
                            if data.incoming.len() == 64 {
                                return Err(Error::Exhausted);
                            }
                            data.incoming.push_back(frame);
                        }
                    }
                }
            }
            htt::Event::Wmi(bytes)
                if wire::word(&bytes, 0)? & 0xffffff == self.wire.management_event =>
            {
                let management = self.wire.management(&bytes[4..], self.features)?;
                let f = &management.frame;
                if let Some(beacon) = super::beacon(&management, &[peer.permission.frequency])? {
                    if beacon.bssid == bssid
                        && self
                            .scan_cache
                            .iter()
                            .any(|b| b.bssid == bssid && b.ssid == beacon.ssid)
                    {
                        data.last_peer = narf_time::Deadline::after_ms(5000);
                    }
                }
                if management.status & !0x40 == 0
                    && wire::channel_to_frequency(management.channel)
                        == Some(peer.permission.frequency)
                    && f.len() >= 26
                    && matches!(f[0], 0xa0 | 0xc0)
                    && f[1] & 0xc7 == 0
                    && f[22] & 15 == 0
                    && (f[4..10] == own || f[4..10] == [0xff; 6])
                    && f[10..16] == bssid
                    && f[16..22] == bssid
                {
                    return Err(Error::Failed);
                }
            }
            htt::Event::Message(bytes) if !matches!(bytes.first(), Some(3 | 4)) => {
                // BA, fragment and PFC events require separate ownership. This
                // profile never advertises HT/VHT or accepts a PFC image.
                if matches!(
                    bytes.first(),
                    Some(2 | 5 | 6 | 0xb | 0xc | 0xd | 0x16 | 0x17 | 0x18)
                ) {
                    return Err(Error::Unsupported);
                }
            }
            _ => {}
        }
        while let Some(receipt) = self.htt.take_tx_receipt() {
            if data.pending.as_ref().is_some_and(|p| p.id == receipt.id) {
                let pending = data.pending.take().ok_or(Error::Failed)?;
                if receipt.status != 0 {
                    return Err(Error::Firmware(u32::from(receipt.status)));
                }
                if pending.reply {
                    data.security
                        .as_mut()
                        .ok_or(Error::Failed)?
                        .reply_delivered(pending.length)
                        .map_err(security_error)?;
                    if data.security.as_ref().is_some_and(Security::port_open) {
                        data.authorized = true;
                    }
                }
            }
        }
        while data.pending.as_ref().is_none_or(|pending| !pending.reply)
            && data
                .security
                .as_ref()
                .and_then(Security::pending_frame)
                .is_none()
        {
            let Some(frame) = data.incoming.pop_front() else {
                break;
            };
            let normalized = if let Some(security) = &mut data.security {
                match security
                    .receive_with_nonce(&frame, &mut *nonce)
                    .map_err(security_error)?
                {
                    Rx::Ignored => None,
                    Rx::Data(frame) => {
                        data.last_peer = narf_time::Deadline::after_ms(5000);
                        Some(frame)
                    }
                    Rx::ReplyReady => {
                        data.last_peer = narf_time::Deadline::after_ms(5000);
                        break;
                    }
                }
            } else {
                Some(frame.0)
            };
            if let Some(frame) = normalized.and_then(|f| ethernet(&f, own, bssid)) {
                data.last_peer = narf_time::Deadline::after_ms(5000);
                if data.received.len() == 64 {
                    return Err(Error::Exhausted);
                }
                data.received.push_back(frame);
            }
        }
        let reply = if data.pending.is_none() {
            data.security
                .as_ref()
                .and_then(Security::pending_frame)
                .map(wire::owned)
                .transpose()?
        } else {
            None
        };
        Ok((idle, reply))
    }
}

/// Linux htt_rx.c::ath10k_htt_rx_h_undecap_raw strips only FCS for software
/// crypto. Admit a single, complete, original native MPDU and bind both the
/// indication and descriptor to an owned sparse peer/TID before shared RSNA.
fn raw_frame(
    mut msdu: htt::rx::Msdu,
    status: u8,
    peer: u16,
    tid: u8,
    own: [u8; 6],
    bssid: [u8; 6],
) -> Result<Option<Native>, Error> {
    if msdu.offload.is_some() || !matches!(status, 1 | 6 | 10) {
        return Ok(None);
    }
    let descriptor = &msdu.descriptor;
    let word = |at: usize| u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
    let attention = word(4);
    let errors = (1 << 3)
        | (1 << 4)
        | (1 << 7)
        | (1 << 8)
        | (1 << 9)
        | (1 << 13)
        | (1 << 16)
        | (1 << 17)
        | (1 << 27)
        | (1 << 28)
        | (1 << 30);
    let start = word(12);
    if attention & (1 << 31) == 0
        || attention & errors != 0
        || attention & 3 != 3
        || word(28) & 0x300 != 0
        || word(56) & 0xc000 != 0xc000
        || word(104) >> 24 != 4
        || (word(24) & 0x3fff) as usize != msdu.payload.len()
        || start & 0x7ff != u32::from(peer)
        || start & 0x1800 != 0x800
        || word(20) >> 28 != u32::from(if tid == 16 { 0 } else { tid })
        || !(28..=4096).contains(&msdu.payload.len())
    {
        return Ok(None);
    }
    // A no-key RAW profile may report DECRYPT_ERR; it must never hand already
    // decrypted ciphertext to software CCMP. NONE or an actual failed CCMP
    // decrypt preserves the wire MPDU. The software MIC remains authoritative.
    let encrypted = msdu.payload[1] & 0x40 != 0;
    let enctype = start >> 28;
    if status == 10 && !encrypted
        || encrypted && !(enctype == 7 || enctype == 6 && attention & (1 << 29) != 0)
        || !encrypted && enctype != 7
    {
        return Ok(None);
    }
    msdu.payload.truncate(msdu.payload.len() - 4); // native RAW carries FCS
    let frame = &msdu.payload;
    if frame.len() < 24
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0x87 != 2
        || u32::from(u16::from_le_bytes([frame[22], frame[23]]) >> 4) != (start >> 16) & 0xfff
        || frame[22] & 15 != 0
        || frame[10..16] != bssid
        || frame[4..10] != own && frame[4] & 1 == 0
        || frame[16..22] == [0; 6]
        || frame[16] & 1 != 0
    {
        return Ok(None);
    }
    let qos = frame[0] == 0x88;
    if qos && (frame.len() < 26 || frame[24] & 0x80 != 0 || frame[24] & 15 != tid)
        || !qos && tid != 16
    {
        return Ok(None);
    }
    if status == 6 {
        let at = if qos { 26 } else { 24 };
        if encrypted || frame.get(at..at + 8) != Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]) {
            return Ok(None);
        }
    }
    Ok(Some(Native(msdu.payload)))
}
