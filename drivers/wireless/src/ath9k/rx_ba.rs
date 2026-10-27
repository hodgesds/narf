// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact AR9285 recipient BA. Linux ath9k main.c RX_START/STOP do no HW
//! programming; recv.c requires NULL tails because MAC can acknowledge BA
//! while copying into host/FIFO. Host ordering precedes original CCMP/PN.
use super::{
    descriptor::Mpdu,
    ht,
    packet::{Error, Port},
};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reorder::Reorder;
const HOLE_NS: u64 = 100_000_000;
const MAX_PPDU: usize = 8191; // LocalHt AMPDU factor0, not a BA-disable bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(base: &ht::Grant) -> Request {
    let (identity, digest, mac) = base.ba_identity();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF AR9285 N85B static recipient BA v1");
    h.update(b"pending proposal prealloc64 opaque originals bound to receive epoch and actual receipt; no crypto/PN/delivery before positive ACK+RXidle; pre-proposal or unopened port never staged; source/key/DELBA/cancel drops stage;8191 is captured MPDU+FCS+minimum delimiter extent, not fabricated total PHY length");
    h.update(&identity);
    h.update(&digest);
    h.update(&mac);
    h.update(b"same AR9285 rev2 HT20 MCS0..7 LGI noSGI20 noLDPC noTXSTBC noTXBA; actual AP TXSTBC bound RXSTBC1; MAC automatic ACK/BA and BAR responses full static envelope measured including transitions; source COMP_BAR RXFILTER417; NULLtail bufhold96/128 RX4092; exact Air ADDBA SSN/TID/window1..64 timeoutTU1024us inclBAR activity refresh; response ACK+RXidle activates; duplicate receipt no reset; timeout recipientDELBA reason39 exactACK+RXidle; DELBA closes; native perMPDU HT status checks; Aggr First More matching unicast peer/TID/rate/STBC PPDU8191/64/100ms; original3839 AMSDU within AMPDU when negotiated; original BlockAck policy; BAR and100ms holes before CCMP/PN; key epoch drops opaque buffers retaining protocolhead");
    Request {
        identity: h.finalize(),
        mac,
        filename: format!(
            "ath9k/ar9285-rxba-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
    }
}
pub(super) struct Grant {
    base: Arc<ht::Grant>,
    cap: Cap<FirmwareBlob, Read>,
    peak: i16,
    ceiling: i16,
    window: u8,
}
pub(super) enum Source {
    Registered,
    #[cfg(feature = "kernel-test")]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
impl Source {
    pub(super) fn load(self, base: Arc<ht::Grant>) -> Result<Arc<Grant>, Error> {
        struct Decode(Arc<ht::Grant>);
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(|_| Error::Access)?;
                    Grant::decode(v.bytes, v.signer, *cap, self.0)
                })())
            }
        }
        let g = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(Error::Access)?;
                let r = request(&base);
                let cap = narf_firmware::open(&r.filename, &loader).map_err(|_| Error::Access)?;
                cap.invoke(Decode(base)).map_err(|_| Error::Access)??
            }
            #[cfg(feature = "kernel-test")]
            Self::Verified { bytes, signer, cap } => Grant::decode(&bytes, signer, cap, base)?,
        };
        g.check()?;
        Ok(Arc::new(g))
    }
}
impl Grant {
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        base: Arc<ht::Grant>,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let r = request(&base);
        if signer.is_none()
            || b.len() != 96
            || b[..8] != [b'N', b'8', b'5', b'B', 1, 0, 96, 0]
            || b[8..12] != 96u32.to_le_bytes()
            || b[12..16] != [0x8c, 0x16, 0x2b, 0]
            || b[16..48] != r.identity
            || b[48..54] != r.mac
            || b[54..58] != [1, 20, 1, 1]
            || !(1..=64).contains(&b[60])
            || b[61] != 0
            || b[64..] != [0; 32]
        {
            return Err(Error::Packet);
        }
        let g = Self {
            base,
            cap,
            peak: i16::from_le_bytes([b[58], b[59]]),
            ceiling: i16::from_le_bytes([b[62], b[63]]),
            window: b[60],
        };
        if !(-512..=256).contains(&g.peak) || !(-512..=256).contains(&g.ceiling) {
            return Err(Error::Packet);
        }
        Ok(g)
    }
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Live<'a, F>(&'a Grant, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let (antenna, base_limit) = self.0.base.ba_limit();
                    let mut limit = self.0.ceiling.min(base_limit);
                    let d = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
                    for r in &d.rules {
                        if r.freq_start_mhz < 2422 && r.freq_end_mhz > 2402 {
                            limit = limit.min(i16::from(r.max_power_dbm) * 2);
                        }
                    }
                    if i32::from(self.0.peak) + i32::from(antenna) > i32::from(limit) {
                        return Err(Error::Access);
                    }
                    (self.1)()
                })())
            }
        }
        self.base
            .invoke(|| self.cap.invoke(Live(self, op)).map_err(|_| Error::Access)?)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
    pub(super) fn readback(&self, io: &impl Port) -> Result<(), Error> {
        self.check()?;
        self.base.readback(io)?;
        if io.read(0x803c)? != 0x417 {
            return Err(Error::Descriptor);
        }
        Ok(())
    }
    pub(super) fn window(&self) -> u8 {
        self.window
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Agreement {
    tid: u8,
    window: u8,
    ssn: u16,
    dialog: u8,
    amsdu: bool,
    timeout: u16,
}
struct Session<T> {
    agreement: Agreement,
    reorder: Reorder<T>,
    generation: u64,
    last_rx: u64,
}
struct Teardown {
    ticket: u64,
    bytes: Option<Vec<u8>>,
}
struct Pending<T> {
    ticket: u64,
    agreement: Agreement,
    reorder: Reorder<T>,
    ready: Vec<T>,
    epoch: u64,
}
#[derive(Clone, Copy)]
struct Ppdu {
    tid: u8,
    rate: usize,
    stbc: bool,
    bytes: usize,
    members: usize,
    started: u64,
    generation: u64,
}
pub(super) struct Reply {
    pub bytes: Vec<u8>,
    pub ticket: Option<u64>,
}
pub(super) enum Route {
    Pass,
    Ordered {
        tid: u8,
        sequence: u16,
        generation: u64,
    },
    Pending {
        tid: u8,
        sequence: u16,
        generation: u64,
    },
    Drop,
}
pub(super) struct Owner<T> {
    sessions: Vec<Option<Session<T>>>,
    pending: Option<Pending<T>>,
    serial: u64,
    ppdu: Option<Ppdu>,
    window: u8,
    teardowns: Vec<Option<Teardown>>,
}
impl<T> Owner<T> {
    pub(super) fn new(window: u8) -> Result<Self, Error> {
        if !(1..=64).contains(&window) {
            return Err(Error::Packet);
        }
        let mut sessions = Vec::new();
        sessions.try_reserve_exact(16).map_err(|_| Error::Memory)?;
        sessions.resize_with(16, || None);
        let mut teardowns = Vec::new();
        teardowns.try_reserve_exact(16).map_err(|_| Error::Memory)?;
        teardowns.resize_with(16, || None);
        Ok(Self {
            sessions,
            pending: None,
            serial: 0,
            ppdu: None,
            window,
            teardowns,
        })
    }
    /// Parse the actual bound immediate ADDBA, including its TU inactivity.
    pub(super) fn request(
        &mut self,
        f: &[u8],
        own: [u8; 6],
        ap: [u8; 6],
        now: u64,
        epoch: u64,
    ) -> Result<Option<Reply>, Error> {
        if f.len() != 33 || !action(f, own, ap, 0) {
            return Ok(None);
        }
        let parameter = u16::from_le_bytes([f[27], f[28]]);
        let start = u16::from_le_bytes([f[31], f[32]]);
        if parameter & 2 == 0 || start & 15 != 0 {
            return Ok(None);
        }
        let requested = parameter >> 6;
        if requested > 64 {
            return Ok(ht::decline(f, own, ap).map(|bytes| Reply {
                bytes,
                ticket: None,
            }));
        }
        let window = if requested == 0 {
            self.window
        } else {
            requested.min(u16::from(self.window)) as u8
        };
        let agreement = Agreement {
            tid: ((parameter >> 2) & 15) as u8,
            window,
            ssn: start >> 4,
            dialog: f[26],
            amsdu: parameter & 1 != 0,
            timeout: u16::from_le_bytes([f[29], f[30]]),
        };
        if self.teardowns[usize::from(agreement.tid)].is_some() {
            return Ok(ht::decline(f, own, ap).map(|bytes| Reply {
                bytes,
                ticket: None,
            }));
        }
        if let Some(session) = &self.sessions[usize::from(agreement.tid)] {
            if session.agreement != agreement {
                return Ok(ht::decline(f, own, ap).map(|bytes| Reply {
                    bytes,
                    ticket: None,
                }));
            }
            return Ok(Some(Reply {
                bytes: response(own, ap, agreement),
                ticket: None,
            }));
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let ticket = self.serial.checked_add(1).ok_or(Error::State)?;
        let mut reorder = Reorder::new(agreement.window, HOLE_NS).map_err(|_| Error::Memory)?;
        if !reorder
            .advance(agreement.ssn, now)
            .map_err(|_| Error::State)?
            .is_empty()
        {
            return Err(Error::State);
        }
        let mut ready = Vec::new();
        ready.try_reserve_exact(64).map_err(|_| Error::Memory)?;
        self.serial = ticket;
        self.pending = Some(Pending {
            ticket,
            agreement,
            reorder,
            ready,
            epoch,
        });
        Ok(Some(Reply {
            bytes: response(own, ap, agreement),
            ticket: Some(ticket),
        }))
    }
    /// Called only after exact native response ACK+queue-idle and a fresh RX
    /// idle fence. A DELBA observed before that fence cancels this ticket.
    pub(super) fn activate(&mut self, ticket: u64, now: u64, epoch: u64) -> Result<Vec<T>, Error> {
        let Some(mut p) = self.pending.take() else {
            return Ok(Vec::new());
        };
        if p.ticket != ticket {
            return Err(Error::State);
        }
        if p.epoch != epoch {
            self.ppdu = None;
            return Ok(Vec::new());
        }
        if self.sessions[usize::from(p.agreement.tid)].is_some() {
            return Err(Error::State);
        }
        let mut expired = p.reorder.expire(now).map_err(|_| Error::Memory)?;
        if p.ready.len() + expired.len() > 64 {
            return Err(Error::State);
        }
        p.ready.append(&mut expired);
        self.sessions[usize::from(p.agreement.tid)] = Some(Session {
            agreement: p.agreement,
            reorder: p.reorder,
            generation: ticket,
            last_rx: now,
        });
        Ok(p.ready)
    }
    pub(super) fn delba(&mut self, f: &[u8], own: [u8; 6], ap: [u8; 6]) -> bool {
        if f.len() != 30 || !action(f, own, ap, 2) {
            return false;
        }
        let p = u16::from_le_bytes([f[26], f[27]]);
        if p & 0xfff != 0x800 {
            return false;
        }
        let tid = (p >> 12) as u8;
        self.sessions[usize::from(tid)] = None;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.agreement.tid == tid)
        {
            self.pending = None;
        }
        self.ppdu = None;
        true
    }
    pub(super) fn route(
        &mut self,
        f: &Mpdu,
        own: [u8; 6],
        ap: [u8; 6],
        now: u64,
        epoch: u64,
    ) -> Route {
        let b = f.bytes();
        let flags = f.aggregation();
        if b.first() != Some(&0x88) {
            self.ppdu = None;
            if flags.aggregate || flags.first || flags.more {
                self.ppdu = None;
                return Route::Drop;
            }
            return Route::Pass;
        }
        if b.len() < 26
            || b[1] & 0xc7 != if b[1] & 0x40 != 0 { 0x42 } else { 2 }
            || b[4..10] != own && b[4] & 1 == 0
            || b[10..16] != ap
            || b[22] & 15 != 0
            || !matches!(b[24] & 0x70, 0 | 0x60)
            || b[25] != 0
        {
            self.ppdu = None;
            return Route::Drop;
        }
        if b[4] & 1 != 0 {
            self.ppdu = None;
            return if !flags.aggregate && !flags.first && !flags.more && b[24] & 0x60 == 0 {
                Route::Pass
            } else {
                Route::Drop
            };
        }
        let tid = b[24] & 15;
        let target = if let Some(session) = self.sessions[usize::from(tid)].as_ref() {
            Some((session.agreement, session.generation, true))
        } else {
            self.pending
                .as_ref()
                .filter(|p| p.agreement.tid == tid && p.epoch == epoch)
                .map(|p| (p.agreement, p.ticket, false))
        };
        let Some((agreement, generation, active)) = target else {
            self.ppdu = None;
            if flags.aggregate || flags.first || flags.more || b[24] & 0x60 != 0 {
                self.ppdu = None;
                return Route::Drop;
            }
            return Route::Pass;
        };
        if !flags.aggregate {
            self.ppdu = None;
            if flags.first || flags.more {
                return Route::Drop;
            }
        } else {
            if f.rate < 12 || b[24] & 0x80 != 0 && !agreement.amsdu {
                self.ppdu = None;
                return Route::Drop;
            }
            // Captured MPDU+FCS+delimiter extent. The final member need not
            // carry inter-member padding; null delimiters are not payload.
            let cost = if flags.more {
                (b.len() + 8).next_multiple_of(4)
            } else {
                b.len() + 8
            };
            let mut ppdu = if flags.first {
                Ppdu {
                    tid,
                    rate: f.rate,
                    stbc: f.stbc,
                    bytes: 0,
                    members: 0,
                    started: now,
                    generation,
                }
            } else {
                let Some(p) = self.ppdu else {
                    return Route::Drop;
                };
                p
            };
            if ppdu.tid != tid
                || ppdu.generation != generation
                || ppdu.rate != f.rate
                || ppdu.stbc != f.stbc
                || now < ppdu.started
                || now - ppdu.started >= HOLE_NS
                || ppdu.bytes + cost > MAX_PPDU
                || ppdu.members >= 64
            {
                self.ppdu = None;
                return Route::Drop;
            }
            ppdu.bytes += cost;
            ppdu.members += 1;
            self.ppdu = flags.more.then_some(ppdu);
        }
        let sequence = u16::from_le_bytes([b[22], b[23]]) >> 4;
        if active {
            self.sessions[usize::from(tid)].as_mut().unwrap().last_rx = now;
            Route::Ordered {
                tid,
                sequence,
                generation,
            }
        } else {
            Route::Pending {
                tid,
                sequence,
                generation,
            }
        }
    }
    pub(super) fn stage(
        &mut self,
        generation: u64,
        sequence: u16,
        now: u64,
        item: T,
    ) -> Result<(), Error> {
        let p = self
            .pending
            .as_mut()
            .filter(|p| p.ticket == generation)
            .ok_or(Error::State)?;
        if p.ready.len() + p.reorder.buffered() >= 64 {
            return Err(Error::State);
        }
        let mut output = p
            .reorder
            .push(sequence, now, item)
            .map_err(|_| Error::Memory)?;
        if p.ready.len() + output.len() + p.reorder.buffered() > 64 {
            return Err(Error::State);
        }
        p.ready.append(&mut output);
        Ok(())
    }
    pub(super) fn push(
        &mut self,
        tid: u8,
        sequence: u16,
        now: u64,
        item: T,
    ) -> Result<Vec<T>, Error> {
        self.sessions
            .get_mut(usize::from(tid))
            .and_then(Option::as_mut)
            .ok_or(Error::State)?
            .reorder
            .push(sequence, now, item)
            .map_err(|_| Error::Memory)
    }
    pub(super) fn expire(&mut self, now: u64, own: [u8; 6], ap: [u8; 6]) -> Result<Vec<T>, Error> {
        if self
            .ppdu
            .is_some_and(|p| now < p.started || now - p.started >= HOLE_NS)
        {
            self.ppdu = None;
        }
        let mut result = Vec::new();
        for tid in 0..16 {
            if self.sessions[tid].as_ref().is_some_and(|s| {
                s.agreement.timeout != 0
                    && now >= s.last_rx
                    && now - s.last_rx >= u64::from(s.agreement.timeout) * 1_024_000
            }) {
                let ticket = self.serial.checked_add(1).ok_or(Error::State)?;
                let bytes = delba(own, ap, tid as u8)?;
                self.sessions[tid] = None;
                self.serial = ticket;
                self.teardowns[tid] = Some(Teardown {
                    ticket,
                    bytes: Some(bytes),
                });
                self.ppdu = None;
            }
            let Some(session) = self.sessions[tid].as_mut() else {
                continue;
            };
            let mut batch = session.reorder.expire(now).map_err(|_| Error::Memory)?;
            result.try_reserve(batch.len()).map_err(|_| Error::Memory)?;
            result.append(&mut batch);
        }
        Ok(result)
    }
    pub(super) fn live(&self, tid: u8, generation: u64) -> bool {
        self.sessions
            .get(usize::from(tid))
            .and_then(Option::as_ref)
            .is_some_and(|s| s.generation == generation)
    }
    pub(super) fn take_teardown(&mut self) -> Option<(u64, Vec<u8>)> {
        self.teardowns
            .iter_mut()
            .flatten()
            .find_map(|t| t.bytes.take().map(|b| (t.ticket, b)))
    }
    pub(super) fn teardown_delivered(&mut self, ticket: u64) -> Result<(), Error> {
        let item = self
            .teardowns
            .iter_mut()
            .find(|t| t.as_ref().is_some_and(|t| t.ticket == ticket))
            .ok_or(Error::State)?;
        *item = None;
        Ok(())
    }
    pub(super) fn bar(
        &mut self,
        f: &[u8],
        own: [u8; 6],
        ap: [u8; 6],
        now: u64,
    ) -> Result<Option<Vec<T>>, Error> {
        self.ppdu = None;
        if f.len() != 20 || f[..2] != [0x84, 0] || f[4..10] != own || f[10..16] != ap {
            return Ok(None);
        }
        let control = u16::from_le_bytes([f[16], f[17]]);
        let seq = u16::from_le_bytes([f[18], f[19]]);
        if control & 0xfff != 4 || seq & 15 != 0 {
            return Ok(None);
        }
        let Some(session) = self.sessions[usize::from(control >> 12)].as_mut() else {
            return Ok(Some(Vec::new()));
        };
        self.ppdu = None;
        session.last_rx = now;
        session
            .reorder
            .advance(seq >> 4, now)
            .map(Some)
            .map_err(|_| Error::Memory)
    }
    pub(super) fn discard_ppdu(&mut self) {
        self.ppdu = None;
    }
    pub(super) fn key_epoch(&mut self, now: u64) -> Result<(), Error> {
        self.ppdu = None;
        self.pending = None;
        for s in self.sessions.iter_mut().flatten() {
            let head = s.reorder.head().ok_or(Error::State)?;
            s.reorder.clear();
            if !s
                .reorder
                .advance(head, now)
                .map_err(|_| Error::State)?
                .is_empty()
            {
                return Err(Error::State);
            }
        }
        Ok(())
    }
    pub(super) fn retire(&mut self) {
        self.ppdu = None;
        self.pending = None;
        for s in &mut self.sessions {
            *s = None;
        }
        for t in &mut self.teardowns {
            *t = None;
        }
    }
}
fn action(f: &[u8], own: [u8; 6], ap: [u8; 6], kind: u8) -> bool {
    f.len() >= 26
        && f[..2] == [0xd0, 0]
        && f[4..10] == own
        && f[10..16] == ap
        && f[16..22] == ap
        && f[22] & 15 == 0
        && f[24..26] == [3, kind]
}
fn response(own: [u8; 6], ap: [u8; 6], a: Agreement) -> Vec<u8> {
    let mut f = alloc::vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&ap);
    f.extend_from_slice(&own);
    f.extend_from_slice(&ap);
    f.extend_from_slice(&[0, 0, 3, 1, a.dialog, 0, 0]);
    let p = (u16::from(a.window) << 6) | (u16::from(a.tid) << 2) | 2 | u16::from(a.amsdu);
    f.extend_from_slice(&p.to_le_bytes());
    f.extend_from_slice(&a.timeout.to_le_bytes());
    f
}
fn delba(own: [u8; 6], ap: [u8; 6], tid: u8) -> Result<Vec<u8>, Error> {
    let mut f = Vec::new();
    f.try_reserve_exact(30).map_err(|_| Error::Memory)?;
    f.extend_from_slice(&[0xd0, 0, 0, 0]);
    f.extend_from_slice(&ap);
    f.extend_from_slice(&own);
    f.extend_from_slice(&ap);
    f.extend_from_slice(&[0, 0, 3, 2]);
    f.extend_from_slice(&(u16::from(tid) << 12).to_le_bytes());
    f.extend_from_slice(&39u16.to_le_bytes());
    Ok(f)
}

#[cfg(feature = "kernel-test")]
#[path = "rx_ba/tests.rs"]
pub(super) mod tests;
