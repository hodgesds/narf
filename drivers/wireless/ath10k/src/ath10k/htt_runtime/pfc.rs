// SPDX-License-Identifier: GPL-2.0-or-later
//! 10.4 peer-flow-control ownership. Linux7.2 htt.h, htt_rx.c and htt_tx.c.
//!
//! A host queue entry owns a prepared native MSDU ID, not an air receipt.
//! FETCH_RESP/CONFIRM never release that ID. Only a terminal HTT TX event for
//! an actually published ID can return its payload to the physical DMA pool.
use super::Error;
use alloc::{collections::VecDeque, vec::Vec};

pub(super) const PEERS: usize = 528;
pub(super) const TIDS: usize = 8;
pub(super) const STATE_BYTES: usize = PEERS * TIDS + PEERS.div_ceil(32) * TIDS * 4 + 4;
const MAX_RECORDS: usize = PEERS * TIDS;
// Actual CE4 source commands retain256 bytes including the8-byte HTC
// header: FETCH_RESP12 +29*8 +HTC8 =252, whereas30 needs260. Never begin
// a partial fetch that this native transport cannot acknowledge completely.
pub(super) const MAX_FETCH_RECORDS: usize = 29;
const MAX_FETCHES: usize = 32;

fn word(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn dword(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Key {
    pub peer: u16,
    pub tid: u8,
}
impl Key {
    fn decode(info: u16) -> Result<Self, Error> {
        let key = Self {
            peer: info & 0xfff,
            tid: (info >> 12) as u8,
        };
        if usize::from(key.peer) >= PEERS || usize::from(key.tid) >= TIDS {
            return Err(Error::Malformed);
        }
        Ok(key)
    }
    fn info(self) -> u16 {
        self.peer | (u16::from(self.tid) << 12)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peer {
    id: u16,
    vdev: u8,
    mac: [u8; 6],
}
#[derive(Debug)]
struct Prepared {
    id: u16,
    length: usize,
    body: Vec<u8>,
}
#[derive(Debug)]
struct Queue {
    key: Key,
    push: u16,
    pending: VecDeque<Prepared>,
}
#[derive(Clone, Copy, Debug)]
struct Flight {
    id: u16,
    key: Option<Key>,
}
#[derive(Clone, Copy, Debug)]
struct Record {
    key: Key,
    msdus: u16,
    bytes: u32,
}
#[derive(Debug)]
struct Fetch {
    operation: u64,
    sequence: u16,
    token: u32,
    requested: Vec<Record>,
    actual: Vec<Record>,
    at: usize,
}
impl Fetch {
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 12 || b[0] != 0x16 {
            return Err(Error::Malformed);
        }
        let confirms = usize::from(word(b, 8)?);
        let count = usize::from(word(b, 10)?);
        let length = 12usize
            .checked_add(count.checked_mul(8).ok_or(Error::Malformed)?)
            .and_then(|n| n.checked_add(confirms.checked_mul(4)?))
            .ok_or(Error::Malformed)?;
        if count > MAX_FETCH_RECORDS || confirms > MAX_FETCHES || b.len() != length {
            return Err(Error::Malformed);
        }
        let mut requested = Vec::new();
        let mut actual = Vec::new();
        requested
            .try_reserve_exact(count)
            .map_err(|_| Error::NoMemory)?;
        actual
            .try_reserve_exact(count)
            .map_err(|_| Error::NoMemory)?;
        for at in (12..12 + count * 8).step_by(8) {
            let key = Key::decode(word(b, at)?)?;
            requested.push(Record {
                key,
                msdus: word(b, at + 2)?,
                bytes: dword(b, at + 4)?,
            });
            actual.push(Record {
                key,
                msdus: 0,
                bytes: 0,
            });
        }
        // Linux uses response-ID0 for convenience; it never denotes a TX ID.
        // Validate the complete confirm suffix before accepting any record.
        for at in (12 + count * 8..length).step_by(4) {
            if dword(b, at)? != 0 {
                return Err(Error::Malformed);
            }
        }
        Ok(Self {
            operation: 0,
            sequence: word(b, 2)?,
            token: dword(b, 4)?,
            requested,
            actual,
            at: 0,
        })
    }
    fn response(&self) -> Result<Vec<u8>, Error> {
        let mut b = Vec::new();
        b.try_reserve_exact(12 + self.actual.len() * 8)
            .map_err(|_| Error::NoMemory)?;
        b.extend_from_slice(&[11, 0, 0, 0]); // H2T FETCH_RESP, response-ID0.
        b.extend_from_slice(&self.sequence.to_le_bytes());
        b.extend_from_slice(&(self.actual.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.token.to_le_bytes());
        for record in &self.actual {
            b.extend_from_slice(&record.key.info().to_le_bytes());
            b.extend_from_slice(&record.msdus.to_le_bytes());
            b.extend_from_slice(&record.bytes.to_le_bytes());
        }
        Ok(b)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Push,
    Pull,
}
#[derive(Debug)]
pub(super) enum Work {
    Frame {
        key: Key,
        id: u16,
        length: usize,
        body: Vec<u8>,
        fetched: Option<u64>,
    },
    Response {
        operation: u64,
        sequence: u16,
        token: u32,
        body: Vec<u8>,
    },
}
impl Work {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Frame { body, .. } | Self::Response { body, .. } => body,
        }
    }
}
#[derive(Debug)]
pub(super) struct Owner {
    peers: Vec<Peer>,
    queues: Vec<Queue>,
    flights: Vec<Flight>,
    fetches: VecDeque<Fetch>,
    fetch_serial: u64,
    mode: Mode,
    enabled: bool,
    global_push: u16,
    limit: usize,
    serial: u32,
    failed: bool,
}
impl Owner {
    pub fn new(limit: u16) -> Self {
        Self {
            peers: Vec::new(),
            queues: Vec::new(),
            flights: Vec::new(),
            fetches: VecDeque::new(),
            fetch_serial: 0,
            mode: Mode::Push,
            enabled: false,
            global_push: 0,
            limit: usize::from(limit),
            serial: 0,
            failed: false,
        }
    }
    pub fn key(&self, vdev: u8, mac: [u8; 6], tid: u8) -> Result<Key, Error> {
        if self.failed || usize::from(tid) >= TIDS {
            return Err(Error::Failed);
        }
        let peer = self
            .peers
            .iter()
            .filter(|p| p.vdev == vdev && p.mac == mac)
            .map(|p| p.id)
            .min()
            .ok_or(Error::Failed)?;
        Ok(Key { peer, tid })
    }
    fn queue(&mut self, key: Key) -> Result<usize, Error> {
        if let Some(at) = self.queues.iter().position(|q| q.key == key) {
            return Ok(at);
        }
        self.queues.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.queues.push(Queue {
            key,
            push: 0,
            pending: VecDeque::new(),
        });
        Ok(self.queues.len() - 1)
    }
    fn has_id(&self, id: u16) -> bool {
        self.flights.iter().any(|f| f.id == id)
            || self
                .queues
                .iter()
                .any(|q| q.pending.iter().any(|p| p.id == id))
    }
    pub fn enqueue(
        &mut self,
        key: Key,
        id: u16,
        length: usize,
        body: Vec<u8>,
    ) -> Result<(), Error> {
        if !(24..=usize::from(u16::MAX)).contains(&length) {
            return Err(Error::Malformed);
        }
        if self.failed || self.has_id(id) || self.pending() + self.flights.len() >= self.limit {
            return Err(Error::Busy);
        }
        let at = self.queue(key)?;
        self.queues[at]
            .pending
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        self.queues[at]
            .pending
            .push_back(Prepared { id, length, body });
        Ok(())
    }
    pub fn pending(&self) -> usize {
        self.queues.iter().map(|q| q.pending.len()).sum()
    }
    pub fn validate_receipts(&self, ids: &[u16]) -> Result<(), Error> {
        if ids.iter().enumerate().any(|(at, id)| {
            ids[..at].contains(id)
                || self
                    .queues
                    .iter()
                    .any(|q| q.pending.iter().any(|p| p.id == *id))
        }) {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub fn complete(&mut self, ids: &[u16]) {
        self.flights.retain(|f| !ids.contains(&f.id));
    }
    pub fn observe(&mut self, b: &[u8]) -> Result<bool, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        match b.first() {
            Some(3) => {
                if b.len() != 12 || b[1] >= 64 {
                    return Err(Error::Malformed);
                }
                let id = word(b, 2)?;
                if usize::from(id) >= PEERS {
                    return Ok(false);
                }
                let mac: [u8; 6] = b[4..10].try_into().unwrap();
                if mac == [0; 6] || mac[0] & 1 != 0 {
                    return Err(Error::Malformed);
                }
                let peer = Peer {
                    id,
                    vdev: b[1],
                    mac,
                };
                if let Some(old) = self.peers.iter().find(|p| p.id == id) {
                    if *old == peer {
                        return Ok(false);
                    }
                    // No alias or new MAP can inherit an old queued/native ID.
                    return Err(Error::Malformed);
                }
                self.peers.try_reserve(1).map_err(|_| Error::NoMemory)?;
                self.peers.push(peer);
                Ok(false) // The station owner must also observe the original MAP.
            }
            Some(4) => {
                if b.len() != 4 {
                    return Err(Error::Malformed);
                }
                let id = word(b, 2)?;
                if self
                    .queues
                    .iter()
                    .any(|q| q.key.peer == id && !q.pending.is_empty())
                    || self
                        .flights
                        .iter()
                        .any(|f| f.key.is_some_and(|k| k.peer == id))
                {
                    return Err(Error::Failed);
                }
                self.peers.retain(|p| p.id != id);
                self.queues.retain(|q| q.key.peer != id);
                Ok(false)
            }
            Some(0x30) => {
                if b.len() < 8 {
                    return Err(Error::Malformed);
                }
                let info = word(b, 2)?;
                let mode = word(b, 4)?;
                let count = usize::from(info >> 1);
                if count > MAX_RECORDS || b.len() != 8 + count * 4 || mode & 3 > 1 {
                    return Err(Error::Malformed);
                }
                let mut limits = Vec::new();
                limits
                    .try_reserve_exact(count)
                    .map_err(|_| Error::NoMemory)?;
                for at in (8..b.len()).step_by(4) {
                    let key = Key::decode(word(b, at)?)?;
                    limits.push((key, word(b, at + 2)?));
                }
                if info & 1 == 0 {
                    return Ok(true);
                } // Linux ignores disabled indications.
                  // Reserve all new queue entries before changing any limits.
                self.queues
                    .try_reserve(count)
                    .map_err(|_| Error::NoMemory)?;
                for (key, push) in limits {
                    if self.peers.iter().any(|p| p.id == key.peer) {
                        let at = self.queue(key)?;
                        self.queues[at].push = push;
                    }
                }
                self.enabled = true;
                self.mode = if mode & 3 == 0 {
                    Mode::Push
                } else {
                    Mode::Pull
                };
                self.global_push = mode >> 2;
                Ok(true)
            }
            Some(0x16) => {
                // Full message validation precedes any queue or flight
                // change. Repeated peer/TID records are separate sequential
                // budgets, as in Linux, not duplicated native MSDU IDs.
                let mut fetch = Fetch::parse(b)?;
                if !self.enabled || self.mode != Mode::Pull {
                    return Err(Error::Malformed);
                }
                if self.fetches.len() == MAX_FETCHES {
                    return Err(Error::Busy);
                }
                self.fetches.try_reserve(1).map_err(|_| Error::NoMemory)?;
                // Linux only echoes token/sequence: their equality/order is
                // not a retry or authority contract. Each actual native event
                // owns a distinct private phase, including identical headers.
                let operation = self.fetch_serial.checked_add(1).ok_or(Error::Failed)?;
                fetch.operation = operation;
                self.fetch_serial = operation;
                self.fetches.push_back(fetch);
                Ok(true)
            }
            Some(0x17) => {
                if b.len() < 4 {
                    return Err(Error::Malformed);
                }
                let count = usize::from(word(b, 2)?);
                if count > MAX_FETCHES || b.len() != 4 + count * 4 {
                    return Err(Error::Malformed);
                }
                for at in (4..b.len()).step_by(4) {
                    if dword(b, at)? != 0 {
                        return Err(Error::Malformed);
                    }
                }
                Ok(true) // No payload, fragment, pending count or TX receipt changes.
            }
            _ => Ok(false),
        }
    }
    fn current(&self, key: Key, mac: [u8; 6], ids: &[u64; 32]) -> bool {
        self.peers
            .iter()
            .any(|p| p.id == key.peer && p.vdev == 0 && p.mac == mac)
            && ids[usize::from(key.peer) / 64] & (1u64 << (key.peer % 64)) != 0
    }
    pub fn next(
        &mut self,
        mac: [u8; 6],
        ids: &[u64; 32],
        native_pending: usize,
    ) -> Result<Option<Work>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        while let Some(fetch) = self.fetches.front() {
            let at = fetch.at;
            if at == fetch.requested.len() {
                return Ok(Some(Work::Response {
                    operation: fetch.operation,
                    sequence: fetch.sequence,
                    token: fetch.token,
                    body: fetch.response()?,
                }));
            }
            let requested = fetch.requested[at];
            let actual = fetch.actual[at];
            let q = self.queues.iter().find(|q| q.key == requested.key);
            let pending = q.and_then(|q| q.pending.front());
            let eligible = self.current(requested.key, mac, ids)
                && actual.msdus < requested.msdus
                // Linux tests accumulated bytes BEFORE one whole dequeue.
                // Its coarse qstate floors128-byte units: requiring the next
                // frame to fit would permanently starve a valid fetch. The
                // last real bounded MPDU may cross the byte threshold; full
                // checked accounting below still reports its actual length.
                && actual.bytes < requested.bytes;
            if let Some(p) = pending.filter(|_| eligible) {
                self.flights.try_reserve(1).map_err(|_| Error::NoMemory)?;
                return Ok(Some(Work::Frame {
                    key: requested.key,
                    id: p.id,
                    length: p.length,
                    body: p.body.clone(),
                    fetched: Some(fetch.operation),
                }));
            }
            self.fetches.front_mut().unwrap().at += 1;
        }
        for q in &self.queues {
            let Some(p) = q.pending.front() else {
                continue;
            };
            if !self.current(q.key, mac, ids) {
                return Err(Error::Failed);
            }
            if self.mode == Mode::Push
                || native_pending < usize::from(self.global_push)
                || self.flights.iter().filter(|f| f.key == Some(q.key)).count()
                    < usize::from(q.push)
            {
                self.flights.try_reserve(1).map_err(|_| Error::NoMemory)?;
                return Ok(Some(Work::Frame {
                    key: q.key,
                    id: p.id,
                    length: p.length,
                    body: p.body.clone(),
                    fetched: None,
                }));
            }
        }
        Ok(None)
    }
    /// Called only after the physical HTC source accepted this exact body.
    pub fn published(&mut self, work: Work) -> Result<(), Error> {
        match work {
            Work::Frame {
                key,
                id,
                length,
                fetched,
                ..
            } => {
                if let Some(operation) = fetched {
                    let fetch = self.fetches.front().ok_or(Error::Failed)?;
                    if fetch.operation != operation
                        || fetch.actual.get(fetch.at).is_none_or(|r| r.key != key)
                    {
                        return Err(Error::Failed);
                    }
                }
                let queue = self
                    .queues
                    .iter_mut()
                    .find(|q| q.key == key)
                    .ok_or(Error::Failed)?;
                if queue
                    .pending
                    .front()
                    .is_none_or(|p| p.id != id || p.length != length)
                {
                    return Err(Error::Failed);
                }
                queue.pending.pop_front();
                self.flights.push(Flight { id, key: Some(key) });
                if fetched.is_some() {
                    let fetch = self.fetches.front_mut().ok_or(Error::Failed)?;
                    let record = fetch.actual.get_mut(fetch.at).ok_or(Error::Failed)?;
                    if record.key != key {
                        return Err(Error::Failed);
                    }
                    record.msdus = record.msdus.checked_add(1).ok_or(Error::Failed)?;
                    record.bytes = record
                        .bytes
                        .checked_add(length as u32)
                        .ok_or(Error::Failed)?;
                }
            }
            Work::Response {
                operation,
                sequence,
                token,
                ..
            } => {
                let fetch = self.fetches.front().ok_or(Error::Failed)?;
                if operation != fetch.operation
                    || sequence != fetch.sequence
                    || token != fetch.token
                    || fetch.at != fetch.requested.len()
                {
                    return Err(Error::Failed);
                }
                self.fetches.pop_front();
            }
        }
        Ok(())
    }
    pub fn state(&mut self) -> Result<Vec<u8>, Error> {
        self.serial = self.serial.checked_add(1).ok_or(Error::Failed)?;
        let mut b = Vec::new();
        b.try_reserve_exact(STATE_BYTES)
            .map_err(|_| Error::NoMemory)?;
        b.resize(STATE_BYTES, 0);
        if self.enabled && self.mode == Mode::Pull {
            for q in &self.queues {
                let bytes = q.pending.iter().map(|p| p.length).sum();
                let count = encoded_size(bytes);
                b[usize::from(q.key.tid) * PEERS + usize::from(q.key.peer)] = count;
                if count != 0 {
                    let at = PEERS * TIDS
                        + (usize::from(q.key.tid) * PEERS.div_ceil(32)
                            + usize::from(q.key.peer) / 32)
                            * 4;
                    let map = u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
                        | (1 << (q.key.peer % 32));
                    b[at..at + 4].copy_from_slice(&map.to_le_bytes());
                }
            }
        }
        b[STATE_BYTES - 4..].copy_from_slice(&self.serial.to_le_bytes());
        Ok(b)
    }
}
fn encoded_size(bytes: usize) -> u8 {
    let mut exponent = 0;
    let mut factor = bytes >> 7;
    while factor >= 64 && exponent < 4 {
        factor >>= 3;
        exponent += 1;
    }
    if exponent == 4 {
        return 0xff;
    }
    if bytes != 0 {
        factor = factor.max(1);
    }
    (exponent << 6) | factor as u8
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "pfc_tests.rs"]
mod tests;
