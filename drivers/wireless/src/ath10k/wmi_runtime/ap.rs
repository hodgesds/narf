// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained AP vdev, distinct from station/ROC and firmware packet credit.
//! Native completion and exact original source/copy guards stay independent.
use super::{ap_key, ap_wire, htt, management, wire, Error};
use crate::ath10k::regulatory::Permission;
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_wireless::{ap_control::ApEmissionAuthority, StationConfig};

/// Original signed database snapshot, not a later equal-value replacement.
/// Both providers are fixed kernel database owners; no callback runs in Radio.
#[derive(Clone)]
pub(in crate::ath10k) struct Policy {
    original: Arc<narf_wireless::reg::RegulatoryDomain>,
    #[cfg(any(test, feature = "kernel-test"))]
    database: Option<Arc<narf_wireless::reg::db::Database>>,
}
impl core::fmt::Debug for Policy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApPolicy")
            .field("country", &self.original.country_code)
            .finish()
    }
}
impl Policy {
    pub fn installed() -> Result<Self, Error> {
        Ok(Self {
            original: narf_wireless::reg::db::snapshot().ok_or(Error::Unsupported)?,
            #[cfg(any(test, feature = "kernel-test"))]
            database: None,
        })
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn scoped(database: Arc<narf_wireless::reg::db::Database>) -> Result<Self, Error> {
        Ok(Self {
            original: database.snapshot().ok_or(Error::Unsupported)?,
            database: Some(database),
        })
    }
    pub fn domain(&self) -> &narf_wireless::reg::RegulatoryDomain {
        &self.original
    }
    pub fn current(&self) -> bool {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(database) = &self.database {
            return database
                .snapshot()
                .is_some_and(|now| Arc::ptr_eq(&now, &self.original));
        }
        narf_wireless::reg::db::snapshot().is_some_and(|now| Arc::ptr_eq(&now, &self.original))
    }
}
#[derive(Clone, Debug)]
pub(in crate::ath10k) struct Capture {
    policy: Policy,
    epoch: Arc<AtomicU64>,
    original: u64,
    pub permission: Permission,
    emission: ApEmissionAuthority,
    data: Option<(Arc<AtomicU64>, u64)>,
    crypto: Option<(Arc<AtomicU64>, u64)>,
    guards: Vec<ApEmissionAuthority>,
    own: (Arc<AtomicU64>, u64),
    target: Option<PeerFence>,
}
impl Capture {
    pub(super) fn with_peer(mut self, target: PeerFence) -> Self {
        self.target = Some(target);
        self
    }
    /// A serialized control retains the original AP/source/key guards, while
    /// native peer loss is rechecked against its target before commit. Packet
    /// copy key/DATA epochs are not a grant for this distinct command waiter.
    pub(super) fn for_control_wait(mut self) -> Self {
        self.crypto = None;
        self.data = None;
        self
    }
    /// Fixed after all arbitrary event/source callbacks; no fresh lookup can
    /// recapture a retired native prefix or DATA denial generation.
    pub fn current(&self, domain: &narf_wireless::reg::RegulatoryDomain) -> Result<(), Error> {
        if !self.policy.current()
            || self.original == u64::MAX
            || self.epoch.load(Ordering::Acquire) != self.original
            || !self.emission.current()
            || self.data.as_ref().is_some_and(|(epoch, original)| {
                *original == u64::MAX || epoch.load(Ordering::Acquire) != *original
            })
            || self.crypto.as_ref().is_some_and(|(epoch, original)| {
                *original == u64::MAX || epoch.load(Ordering::Acquire) != *original
            })
            || self.guards.iter().any(|guard| !guard.current())
            || self.own.0.load(Ordering::Acquire) != self.own.1
            || self.own.1 == u64::MAX
            || self.target.as_ref().is_some_and(|target| !target.current())
        {
            return Err(Error::Failed);
        }
        self.permission.check(domain)
    }
}
#[derive(Debug)]
pub(super) struct Record {
    pub mac: [u8; 6],
    pub ids: [u64; 32],
    pub expected: bool,
    pub delete_ack: bool,
    pub deleting: bool,
    pub epoch: Arc<AtomicU64>,
}
impl Record {
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            ids: [0; 32],
            expected: false,
            delete_ack: false,
            deleting: false,
            epoch: Arc::new(AtomicU64::new(1)),
        }
    }
    pub fn mapped(&self) -> bool {
        self.ids.iter().any(|word| *word != 0)
    }
    pub fn owns(&self, id: u16) -> bool {
        id < 2048 && self.ids[usize::from(id) / 64] & (1 << (id % 64)) != 0
    }
}
pub(super) struct Peer {
    pub record: Record,
    pub config: StationConfig,
    pub associated: bool,
    pub authorized: bool,
    pub key: Option<ap_key::Key>,
    pub source: ApEmissionAuthority,
    pub key_source: Option<ApEmissionAuthority>,
    pub authorization: Option<ApEmissionAuthority>,
    pub denial: Arc<AtomicU64>,
}
#[derive(Clone, Debug)]
pub(super) struct PeerFence {
    source: ApEmissionAuthority,
    native: Arc<AtomicU64>,
    native_generation: u64,
    denial: Arc<AtomicU64>,
    denial_generation: u64,
}
impl PeerFence {
    pub fn capture(peer: &Peer) -> Self {
        Self {
            source: peer.source.clone(),
            native: peer.record.epoch.clone(),
            native_generation: peer.record.epoch.load(Ordering::Acquire),
            denial: peer.denial.clone(),
            denial_generation: peer.denial.load(Ordering::Acquire),
        }
    }
    pub fn current(&self) -> bool {
        self.source.current()
            && self.native_generation != u64::MAX
            && self.denial_generation != u64::MAX
            && self.native.load(Ordering::Acquire) == self.native_generation
            && self.denial.load(Ordering::Acquire) == self.denial_generation
    }
}
pub(super) struct Group {
    pub key: ap_key::Key,
    pub source: ApEmissionAuthority,
}
#[derive(Debug, Default)]
pub(super) struct Staging {
    pub keys: Vec<(narf_wireless::OwnedKey, ApEmissionAuthority)>,
    pub default: Option<(u8, ApEmissionAuthority)>,
}
impl Staging {
    pub fn current(&self) -> bool {
        self.keys.iter().all(|(_, source)| source.current())
            && self
                .default
                .as_ref()
                .is_none_or(|(_, source)| source.current())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Vdev {
    Original,
    DeleteSent,
    Absent,
    CreateSent,
    Created,
    StartSent,
    Started,
    Up,
    StopSent,
    Stopped,
    Retired,
}
#[derive(Clone, Copy)]
pub(super) enum Publication {
    Vdev(Vdev),
    CreatePeer([u8; 6]),
    DeletePeer([u8; 6]),
}
#[derive(Debug)]
pub(in crate::ath10k) enum Event {
    Management(Vec<u8>),
    Control {
        peer: [u8; 6],
        ethertype: u16,
        pdu: Vec<u8>,
        unencrypted: bool,
    },
    Data(Vec<u8>),
}
#[derive(Debug)]
pub(in crate::ath10k) struct Received {
    pub event: Event,
    pub capture: Capture,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Token {
    Htt(u16),
    Wmi(u32),
}
#[derive(Debug)]
pub(super) struct Pending {
    pub token: Token,
    pub deadline: narf_time::Deadline,
    pub status: Option<bool>,
    /// DATA is accounted independently from a control's terminal ACK.
    pub control: bool,
}
pub(in crate::ath10k) struct Session {
    pub(super) policy: Policy,
    pub(super) plan: ap_wire::Plan,
    pub(super) permission: Permission,
    pub(super) start: ApEmissionAuthority,
    pub(super) epoch: Arc<AtomicU64>,
    pub(super) data_epoch: Arc<AtomicU64>,
    pub(super) key_epoch: Arc<AtomicU64>,
    pub(super) vdev: Vdev,
    /// A GO's firmware-reported NoA (`WMI_TLV_P2P_NOA_EVENTID` for this
    /// vdev, `p2p.c::ath10k_p2p_noa_update_by_vdev_id`), appended to the
    /// Probe Responses it transmits (`ath10k_tx_h_add_p2p_noa_ie`).
    pub(super) noa: super::p2p::NoaOwner,
    pub(super) own: Record,
    pub(super) peers: Vec<Peer>,
    pub(super) groups: Vec<Group>,
    pub(super) default_group: Option<u8>,
    pub(super) default_source: Option<ApEmissionAuthority>,
    pub(super) template_source: Option<ApEmissionAuthority>,
    pub(super) sequence: u16,
    pub(super) echo: u32,
    pub(super) echo_seen: u32,
    pub(super) beacon_ok: bool,
    pub(super) vdev_deleted: bool,
    pub(super) native_stopped: bool,
    pub(super) busy: bool,
    pub(super) failed: bool,
    pub(super) pending: Vec<Pending>,
    pub(super) received: VecDeque<Received>,
}
impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kAp")
            .field("vdev", &self.vdev)
            .field("peers", &self.peers.len())
            .field("busy", &self.busy)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
impl Session {
    pub(super) fn new(
        policy: Policy,
        plan: ap_wire::Plan,
        permission: Permission,
        start: ApEmissionAuthority,
        own: [u8; 6],
    ) -> Self {
        Self {
            policy,
            plan,
            permission,
            start,
            epoch: Arc::new(AtomicU64::new(1)),
            data_epoch: Arc::new(AtomicU64::new(1)),
            key_epoch: Arc::new(AtomicU64::new(1)),
            vdev: Vdev::Original,
            noa: super::p2p::NoaOwner::default(),
            own: Record::new(own),
            peers: Vec::new(),
            groups: Vec::new(),
            default_group: None,
            default_source: None,
            template_source: None,
            sequence: 0,
            echo: 0,
            echo_seen: 0,
            beacon_ok: false,
            vdev_deleted: false,
            native_stopped: false,
            busy: true,
            failed: false,
            pending: Vec::new(),
            received: VecDeque::new(),
        }
    }
    pub fn current(&self, domain: &narf_wireless::reg::RegulatoryDomain) -> Result<(), Error> {
        if self.failed
            || !self.policy.current()
            || !self.start.current()
            || self.epoch.load(Ordering::Acquire) == u64::MAX
            || self.key_epoch.load(Ordering::Acquire) == u64::MAX
            || self.data_epoch.load(Ordering::Acquire) == u64::MAX
            || self.own.epoch.load(Ordering::Acquire) == u64::MAX
            || self.vdev == Vdev::Up && !self.own.mapped()
            || self.groups.iter().any(|group| !group.source.current())
            || self
                .template_source
                .as_ref()
                .is_some_and(|source| !source.current())
            || self
                .default_source
                .as_ref()
                .is_some_and(|source| !source.current())
            || self.peers.iter().any(|peer| {
                !peer.source.current()
                    || peer.record.epoch.load(Ordering::Acquire) == u64::MAX
                    || peer.denial.load(Ordering::Acquire) == u64::MAX
                    || peer
                        .key_source
                        .as_ref()
                        .is_some_and(|source| !source.current())
                    || peer
                        .authorization
                        .as_ref()
                        .is_some_and(|source| !source.current())
            })
        {
            return Err(Error::Failed);
        }
        self.permission.check(domain)
    }
    pub fn advance(epoch: &AtomicU64) -> Result<(), Error> {
        match epoch.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            (value < u64::MAX - 1).then(|| value + 1)
        }) {
            Ok(_) => Ok(()),
            Err(_) => {
                epoch.store(u64::MAX, Ordering::Release);
                Err(Error::Exhausted)
            }
        }
    }
    /// Terminal cleanup can consume real receipts after copy epochs already
    /// closed. An already-dead counter needs no new generation and grants none.
    pub fn invalidate(epoch: &AtomicU64) -> Result<(), Error> {
        if epoch.load(Ordering::Acquire) == u64::MAX {
            Ok(())
        } else {
            Self::advance(epoch)
        }
    }
    pub fn retire(&mut self) {
        self.failed = true;
        self.epoch.store(u64::MAX, Ordering::Release);
        self.data_epoch.store(u64::MAX, Ordering::Release);
        self.key_epoch.store(u64::MAX, Ordering::Release);
        for peer in &mut self.peers {
            peer.authorized = false;
        }
        self.received.clear();
    }
    pub fn capture(&self, data: bool, crypto: bool) -> Result<Capture, Error> {
        let mut guards = Vec::new();
        guards
            .try_reserve_exact(
                self.peers.len() * 3
                    + self.groups.len()
                    + usize::from(self.default_source.is_some())
                    + usize::from(self.template_source.is_some()),
            )
            .map_err(|_| Error::NoMemory)?;
        guards.extend(self.template_source.iter().cloned());
        if crypto {
            guards.extend(self.default_source.iter().cloned());
            guards.extend(self.groups.iter().map(|group| group.source.clone()));
            for peer in &self.peers {
                guards.push(peer.source.clone());
                guards.extend(peer.key_source.iter().cloned());
                guards.extend(peer.authorization.iter().cloned());
            }
        }
        Ok(Capture {
            policy: self.policy.clone(),
            epoch: self.epoch.clone(),
            original: self.epoch.load(Ordering::Acquire),
            data: data.then(|| {
                (
                    self.data_epoch.clone(),
                    self.data_epoch.load(Ordering::Acquire),
                )
            }),
            crypto: crypto.then(|| {
                (
                    self.key_epoch.clone(),
                    self.key_epoch.load(Ordering::Acquire),
                )
            }),
            permission: self.permission.clone(),
            target: None,
            emission: self.start.clone(),
            guards,
            own: (
                self.own.epoch.clone(),
                self.own.epoch.load(Ordering::Acquire),
            ),
        })
    }
    pub fn push(&mut self, event: Event, data: bool) -> Result<(), Error> {
        if self.failed {
            return Ok(());
        }
        if self.received.len() == 64 {
            return Err(Error::Exhausted);
        }
        self.received.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let mut capture = self.capture(data, !matches!(&event, Event::Management(_)))?;
        let mac = match &event {
            Event::Management(frame) => {
                Some(<[u8; 6]>::try_from(&frame[10..16]).map_err(|_| Error::Malformed)?)
            }
            Event::Control { peer, .. } => Some(*peer),
            Event::Data(_) => None,
        };
        if let Some(peer) =
            mac.and_then(|mac| self.peers.iter().find(|peer| peer.record.mac == mac))
        {
            // Capture after this frame's own denial transition. Genuine loss
            // management delivers now, but cannot survive delete/re-add or a
            // later authorization generation of the same MAC.
            capture = capture.with_peer(PeerFence::capture(peer));
        }
        self.received.push_back(Received { event, capture });
        Ok(())
    }
    /// Native MAP supplies only physical peer ownership. It never associates
    /// or authorizes a client, installs a key or revives a removed ID.
    pub fn peer_event(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match bytes.first() {
            Some(3) => {
                if bytes.len() != 12 || bytes[1] != 0 {
                    return Err(Error::Malformed);
                }
                let id = u16::from_le_bytes([bytes[2], bytes[3]]);
                if id >= 2048 {
                    return Err(Error::Malformed);
                }
                let mac: [u8; 6] = bytes[4..10].try_into().unwrap();
                for record in
                    core::iter::once(&self.own).chain(self.peers.iter().map(|peer| &peer.record))
                {
                    if record.owns(id) && record.mac != mac {
                        return Err(Error::Malformed);
                    }
                }
                let record = if mac == self.own.mac {
                    Some(&mut self.own)
                } else {
                    self.peers
                        .iter_mut()
                        .find(|peer| peer.record.mac == mac)
                        .map(|peer| &mut peer.record)
                };
                if let Some(record) = record {
                    if !record.expected {
                        return Err(Error::Failed);
                    }
                    record.ids[usize::from(id) / 64] |= 1 << (id % 64);
                }
            }
            Some(4) => {
                if bytes.len() != 4 {
                    return Err(Error::Malformed);
                }
                let id = u16::from_le_bytes([bytes[2], bytes[3]]);
                if id >= 2048 {
                    return Err(Error::Malformed);
                }
                let word = usize::from(id) / 64;
                let bit = 1 << (id % 64);
                if self.own.owns(id) {
                    self.own.ids[word] &= !bit;
                    Self::invalidate(&self.own.epoch)?;
                    if !self.own.mapped() && self.vdev == Vdev::Up {
                        self.retire();
                    }
                }
                for peer in &mut self.peers {
                    if peer.record.owns(id) {
                        peer.record.ids[word] &= !bit;
                        Self::invalidate(&peer.record.epoch)?;
                        Self::invalidate(&peer.denial)?;
                        Self::invalidate(&self.data_epoch)?;
                        Self::invalidate(&self.key_epoch)?;
                        if !peer.record.mapped() {
                            peer.authorized = false;
                            peer.associated = false;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub fn wmi_event(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let id = wire::word(bytes, 0)? & 0xffffff;
        match id {
            0x1d001 => {
                let body = wire::tag(&bytes[4..], 54)?;
                if body.len() != 4 {
                    return Err(Error::Malformed);
                }
                self.echo_seen = wire::word(body, 0)?;
            }
            0x7004 if self.vdev == Vdev::Up && !self.failed => {
                let body = wire::tag(&bytes[4..], 222)?;
                if body.len() != 8 || wire::word(body, 0)? != u32::from(self.plan.vdev) {
                    return Err(Error::Malformed);
                }
                let status = wire::word(body, 4)?;
                if status != 0 {
                    return Err(Error::Firmware(status));
                }
                self.beacon_ok = true;
            }
            // Delete response carries no consumed identity in Linux. One
            // outstanding AP-vdev teardown plus drained native prefix
            // supplies correlation; no guessed body/status is decoded.
            0x5006 if self.vdev == Vdev::DeleteSent => self.vdev_deleted = true,
            // `wmi-tlv.c::ath10k_wmi_tlv_event_p2p_noa` ->
            // `ath10k_p2p_noa_update_by_vdev_id`: only a GO vdev's own
            // report replaces its NoA; another vdev's is not ours.
            0xd002 if self.plan.role == super::p2p::Role::P2pGo => {
                let (vdev, noa) = super::p2p::Noa::tlv_event(&bytes[4..])?;
                self.noa.update(
                    super::p2p::Vdev::new(self.plan.vdev, self.plan.role),
                    vdev,
                    &noa,
                )?;
            }
            0x5002 if self.vdev == Vdev::StopSent => {
                let body = wire::tag(&bytes[4..], 41)?;
                if body.len() != 4 || wire::word(body, 0)? != u32::from(self.plan.vdev) {
                    return Err(Error::Malformed);
                }
                self.native_stopped = true;
            }
            0x6007 => {
                let body = wire::tag(&bytes[4..], 451)?;
                if body.len() != 12 {
                    return Err(Error::Malformed);
                }
                // Another vdev's (P2P_DEVICE/offchannel) peer is not ours.
                if wire::word(body, 0)? != u32::from(self.plan.vdev) {
                    return Ok(());
                }
                let mac = &body[4..10];
                if mac == self.own.mac && self.own.deleting {
                    self.own.delete_ack = true;
                }
                if let Some(peer) = self
                    .peers
                    .iter_mut()
                    .find(|peer| peer.record.mac == mac && peer.record.deleting)
                {
                    peer.record.delete_ack = true;
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub(super) fn terminal(&mut self, token: Token, ack: bool) -> Result<(), Error> {
        let pending = self
            .pending
            .iter_mut()
            .find(|pending| pending.token == token)
            .ok_or(Error::Malformed)?;
        if pending.status.replace(ack).is_some() {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub fn management_completions(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<Vec<management::Completion>>, Error> {
        let reports = management::completions(bytes)?;
        if let Some(reports) = &reports {
            for report in reports {
                self.terminal(Token::Wmi(report.id), report.status == 0)?;
            }
        }
        Ok(reports)
    }
    pub fn htt_completions(
        &mut self,
        htt: &mut htt::Runtime<impl super::Hif + super::HostMemory + super::HttMemory>,
    ) -> Result<(), Error> {
        while let Some(receipt) = htt.take_tx_receipt() {
            self.terminal(Token::Htt(receipt.id), receipt.status == 0)?;
        }
        self.pending
            .retain(|pending| pending.control || pending.status.is_none());
        if self
            .pending
            .iter()
            .any(|pending| pending.status.is_none() && pending.deadline.expired())
        {
            return Err(Error::Timeout);
        }
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.retire();
    }
}
