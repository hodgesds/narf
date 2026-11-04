// SPDX-License-Identifier: GPL-2.0-or-later
//! One source-bound BE/TID0 sender. No key, PN or radio authority is created.
use super::{Grant, MAX_MEMBERS, RETRIES};
use crate::ath9k::packet::Error;
use alloc::{sync::Arc, vec, vec::Vec};
use narf_wireless::association::phy::{Negotiated, Offer};
const SETUP_NS: u64 = 100_000_000;
#[derive(Clone, Copy)]
pub(in crate::ath9k) struct AggregatePermit {
    pub seq: [u16; MAX_MEMBERS],
    pub count: usize,
    pub air: usize,
    pub delims: [u8; MAX_MEMBERS],
    pub generation: u64,
}
pub(in crate::ath9k) enum Action {
    Request(u64, Vec<u8>),
    Retry(u64, usize, Vec<u8>),
    Bar(u64, Vec<u8>),
    Delba(u64, Vec<u8>),
}
struct Proposal {
    ticket: u64,
    dialog: u8,
    ssn: u16,
    epoch: u64,
    receipt: bool,
    deadline: u64,
    cancelled: bool,
}
struct Session {
    head: u16,
    window: u8,
    timeout: u16,
    last: u64,
}
struct Flight {
    ticket: u64,
    epoch: u64,
    end: u16,
    originals: Vec<Option<Vec<u8>>>,
    tries: Vec<u8>,
    awaiting_pair: bool,
    retry: Option<usize>,
}
struct Bar {
    ticket: u64,
    target: u16,
    epoch: u64,
    receipt: bool,
    cancelled: bool,
    deadline: u64,
}
struct Delba {
    ticket: u64,
    reason: u16,
    sent: bool,
}
pub(in crate::ath9k) struct Owner {
    grant: Arc<Grant>,
    serial: u64,
    dialog: u8,
    proposal: Option<Proposal>,
    session: Option<Session>,
    flight: Option<Flight>,
    recovery: Option<u16>,
    bar: Option<Bar>,
    delba: Option<Delba>,
    disabled: bool,
    density: u8,
    geometry: crate::ath9k::channel_width::Geometry,
    short_gi: bool,
    max_air: usize,
}
impl Owner {
    pub(in crate::ath9k) fn new(
        grant: Arc<Grant>,
        offer: &Offer,
        n: &Negotiated,
    ) -> Result<Self, Error> {
        grant.check()?;
        let factor = offer
            .ht()
            .peer_ampdu_factor()
            .min(n.ht().peer_ampdu_factor());
        let density = offer
            .ht()
            .peer_mpdu_density()
            .max(n.ht().peer_mpdu_density());
        let geometry = grant.base.geometry();
        if geometry.is_wide() != (n.width() == narf_wireless::association::phy::Width::Forty) {
            return Err(Error::Packet);
        }
        Ok(Self {
            geometry,
            short_gi: geometry.is_wide() && n.ht().tx_sgi40(),
            grant: grant.clone(),
            serial: 0,
            dialog: 0,
            proposal: None,
            session: None,
            flight: None,
            recovery: None,
            bar: None,
            delba: None,
            disabled: false,
            density: [0, 1, 1, 1, 2, 4, 8, 16][usize::from(density)],
            max_air: grant.max_air.min((1usize << (13 + factor)) - 1),
        })
    }
    /// Current accepted beacon facts may only narrow this established
    /// sender. Match the actual installed TX mode after Packet::observe_ht.
    pub(in crate::ath9k) fn observe(
        &mut self,
        offer: &Offer,
        profile: crate::ath9k::ht::Profile,
    ) -> Result<(), Error> {
        if profile.geometry() != self.geometry {
            return Err(Error::Packet);
        }
        self.short_gi &= profile.tx_sgi40();
        let density = [0, 1, 1, 1, 2, 4, 8, 16][usize::from(offer.ht().peer_mpdu_density())];
        self.density = self.density.max(density);
        self.max_air = self
            .max_air
            .min((1usize << (13 + offer.ht().peer_ampdu_factor())) - 1);
        Ok(())
    }
    fn ticket(&mut self) -> Result<u64, Error> {
        self.serial = self.serial.checked_add(1).ok_or(Error::State)?;
        Ok(self.serial)
    }
    pub(in crate::ath9k) fn ready(&self) -> bool {
        (self.disabled || self.session.is_some())
            && self.proposal.is_none()
            && self.flight.is_none()
            && self.recovery.is_none()
            && self.bar.is_none()
            && self.delba.is_none()
    }
    pub(in crate::ath9k) fn paired(&self) -> bool {
        self.ready() && !self.disabled && self.session.as_ref().is_some_and(|s| s.window >= 4)
    }
    pub(in crate::ath9k) fn next(
        &mut self,
        own: [u8; 6],
        ap: [u8; 6],
        ssn: u16,
        now: u64,
        epoch: u64,
    ) -> Result<Option<Action>, Error> {
        self.grant.check()?;
        if let Some(p) = &self.proposal {
            if now >= p.deadline {
                return Err(Error::Timeout);
            }
            return Ok(None);
        }
        if let Some(b) = &self.bar {
            if now >= b.deadline {
                return Err(Error::Timeout);
            }
            return Ok(None);
        }
        if let Some(d) = &mut self.delba {
            if d.sent {
                return Ok(None);
            }
            d.sent = true;
            return Ok(Some(Action::Delba(d.ticket, delba(own, ap, d.reason))));
        }
        if self.session.as_ref().is_some_and(|s| {
            s.timeout != 0 && now.saturating_sub(s.last) >= u64::from(s.timeout) * 1_024_000
        }) && self.flight.is_none()
        {
            self.begin_delba(39)?;
            return self.next(own, ap, ssn, now, epoch);
        }
        if let Some(f) = &mut self.flight {
            if f.awaiting_pair || f.retry.is_some() {
                return Ok(None);
            }
            while let Some(i) = f.originals.iter().position(Option::is_some) {
                if f.tries[i] < RETRIES {
                    f.tries[i] += 1;
                    f.retry = Some(i);
                    let mut frame = f.originals[i].as_ref().unwrap().clone();
                    frame[1] |= 8;
                    return Ok(Some(Action::Retry(f.ticket, i, frame)));
                }
                if self.grant.members > 2 {
                    f.originals[i] = None;
                } else {
                    // Preserve the accepted v1/v2/v3 recovery recipe.
                    f.originals.iter_mut().for_each(|original| *original = None);
                }
                self.recovery = Some(f.end);
            }
            self.finish_flight(now)?;
        }
        if let Some(target) = self.recovery {
            let ticket = self.ticket()?;
            self.bar = Some(Bar {
                ticket,
                target,
                epoch,
                receipt: false,
                cancelled: false,
                deadline: now.checked_add(SETUP_NS).ok_or(Error::Timeout)?,
            });
            return Ok(Some(Action::Bar(ticket, bar(own, ap, target))));
        }
        if self.disabled || self.session.is_some() {
            return Ok(None);
        }
        self.dialog = self.dialog.checked_add(1).ok_or(Error::State)?;
        let ticket = self.ticket()?;
        self.proposal = Some(Proposal {
            ticket,
            dialog: self.dialog,
            ssn,
            epoch,
            receipt: false,
            deadline: now.checked_add(SETUP_NS).ok_or(Error::Timeout)?,
            cancelled: false,
        });
        let mut f = management(own, ap);
        f.extend_from_slice(&[3, 0, self.dialog]);
        f.extend_from_slice(&(2u16 | (u16::from(self.grant.window()) << 6)).to_le_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&(ssn << 4).to_le_bytes());
        Ok(Some(Action::Request(ticket, f)))
    }
    pub(in crate::ath9k) fn request_delivered(&mut self, ticket: u64) -> Result<(), Error> {
        let Some(p) = self.proposal.as_mut().filter(|p| p.ticket == ticket) else {
            return Ok(());
        };
        if p.cancelled {
            self.proposal = None;
            self.begin_delba(37)?;
        } else {
            p.receipt = true;
        }
        Ok(())
    }
    pub(in crate::ath9k) fn response(
        &mut self,
        b: &[u8],
        own: [u8; 6],
        ap: [u8; 6],
        now: u64,
        epoch: u64,
    ) -> Result<bool, Error> {
        if b.len() != 33
            || b[..2] != [0xd0, 0]
            || b[4..10] != own
            || b[10..16] != ap
            || b[16..22] != ap
            || b[22] & 15 != 0
            || b[24..26] != [3, 1]
        {
            return Ok(false);
        }
        let Some(p) = &self.proposal else {
            return Ok(true);
        };
        if p.cancelled || !p.receipt || p.epoch != epoch || b[26] != p.dialog || now >= p.deadline {
            return Ok(true);
        }
        let parameter = u16::from_le_bytes([b[29], b[30]]);
        let status = u16::from_le_bytes([b[27], b[28]]);
        if parameter & 0x3f != 2 {
            return Ok(true);
        }
        if status != 0 {
            self.proposal = None;
            self.disabled = true;
            return Ok(true);
        }
        let window = parameter >> 6;
        if !(1..=64).contains(&window) || window > u16::from(self.grant.window()) {
            return Ok(true);
        }
        let head = p.ssn;
        let timeout = u16::from_le_bytes([b[31], b[32]]);
        self.proposal = None;
        if window < 4 {
            self.begin_delba(37)?;
        } else {
            self.session = Some(Session {
                head,
                window: window as u8,
                timeout,
                last: now,
            });
        }
        Ok(true)
    }
    /// Bound a prefix before the caller consumes any QoS SN or CCMP PN.
    pub(in crate::ath9k) fn prefix(&self, lengths: &[usize], mcs: u8) -> usize {
        let mut count = 1;
        for end in 2..=lengths.len().min(self.grant.members) {
            if self.layout(&lengths[..end], mcs).is_err() {
                break;
            }
            count = end;
        }
        count
    }
    fn layout(&self, lengths: &[usize], mcs: u8) -> Result<AggregatePermit, Error> {
        if !self.paired() || mcs > 7 {
            return Err(Error::State);
        }
        let s = self.session.as_ref().ok_or(Error::State)?;
        let count = lengths.len();
        // ath_tx_form_aggr limits one chain to half the current BAW.
        if count < 2
            || count > self.grant.members
            || count > usize::from(s.window) / 2
            || lengths.iter().any(|length| !(34..=1550).contains(length))
        {
            return Err(Error::Packet);
        }
        let bits = if self.geometry.is_wide() {
            [54usize, 108, 162, 216, 324, 432, 486, 540]
        } else {
            [26usize, 52, 78, 104, 156, 208, 234, 260]
        }[usize::from(mcs)];
        let mut air = 0usize;
        let mut delims = [0; MAX_MEMBERS];
        for (index, original) in lengths.iter().enumerate() {
            let length = original + 4; // FCS, excluding native transport pad2.
            air += 4 + length;
            if index + 1 == count {
                continue; // No final alignment or padding on air.
            }
            let base = 256usize.saturating_sub(length).div_ceil(4);
            let symbols = if self.short_gi {
                (usize::from(self.density) * 5).saturating_sub(4) / 18
            } else {
                usize::from(self.density >> 2)
            }
            .max(1);
            let density = if self.density == 0 {
                0
            } else {
                (symbols * bits / 8).saturating_sub(length) / 4
            };
            let padding = base.max(density);
            if padding > 255 {
                return Err(Error::Packet);
            }
            delims[index] = padding as u8;
            air = air.next_multiple_of(4) + padding * 4;
        }
        if air > self.max_air
            || self
                .geometry
                .ht_duration(self.short_gi, air, mcs)
                .is_none_or(|duration| duration > 4000)
        {
            return Err(Error::Packet);
        }
        let mut seq = [0; MAX_MEMBERS];
        for (index, value) in seq[..count].iter_mut().enumerate() {
            *value = (s.head + index as u16) & 4095;
        }
        Ok(AggregatePermit {
            seq,
            count,
            air,
            delims,
            generation: self.serial,
        })
    }
    pub(in crate::ath9k) fn permit(
        &self,
        frames: &[&[u8]],
        own: [u8; 6],
        ap: [u8; 6],
        mcs: u8,
    ) -> Result<AggregatePermit, Error> {
        let lengths: Vec<usize> = frames.iter().map(|frame| frame.len()).collect();
        let permit = self.layout(&lengths, mcs)?;
        for (index, f) in frames.iter().enumerate() {
            if f[0] != 0x88
                || f[1] & !0x48 != 1
                || f[4..10] != ap
                || f[10..16] != own
                || f[22] & 15 != 0
                || f[24..26] != [0, 0]
                || u16::from_le_bytes([f[22], f[23]]) >> 4 != permit.seq[index]
            {
                return Err(Error::Packet);
            }
        }
        Ok(permit)
    }
    pub(in crate::ath9k) fn begin_pair(
        &mut self,
        permit: AggregatePermit,
        frames: Vec<Vec<u8>>,
        epoch: u64,
    ) -> Result<(), Error> {
        if !self.paired() || permit.generation != self.serial || frames.len() != permit.count {
            return Err(Error::State);
        }
        let ticket = self.ticket()?;
        self.flight = Some(Flight {
            ticket,
            epoch,
            end: (permit.seq[permit.count - 1] + 1) & 4095,
            originals: frames.into_iter().map(Some).collect(),
            tries: vec![0; permit.count],
            awaiting_pair: true,
            retry: None,
        });
        Ok(())
    }
    pub(in crate::ath9k) fn pair_delivered(
        &mut self,
        acked: Vec<bool>,
        now: u64,
        epoch: u64,
    ) -> Result<(), Error> {
        let Some(f) = &mut self.flight else {
            return Ok(());
        };
        if !f.awaiting_pair || acked.len() != f.originals.len() {
            return Err(Error::State);
        }
        f.awaiting_pair = false;
        if epoch != f.epoch {
            f.originals.iter_mut().for_each(|original| *original = None);
            self.recovery = Some(f.end);
        } else {
            for (i, ok) in acked.into_iter().enumerate() {
                if ok {
                    f.originals[i] = None;
                }
            }
        }
        self.finish_flight(now)
    }
    pub(in crate::ath9k) fn retry_delivered(
        &mut self,
        ticket: u64,
        index: usize,
        delivered: bool,
        now: u64,
        epoch: u64,
    ) -> Result<(), Error> {
        let Some(f) = self.flight.as_mut().filter(|f| f.ticket == ticket) else {
            return Ok(());
        };
        if f.retry != Some(index) {
            return Err(Error::State);
        }
        f.retry = None;
        if epoch != f.epoch {
            f.originals.iter_mut().for_each(|original| *original = None);
            self.recovery = Some(f.end);
        } else if delivered {
            f.originals[index] = None;
        }
        self.finish_flight(now)
    }
    fn finish_flight(&mut self, now: u64) -> Result<(), Error> {
        if self.flight.as_ref().is_some_and(|f| {
            !f.awaiting_pair && f.retry.is_none() && f.originals.iter().all(Option::is_none)
        }) {
            let f = self.flight.take().unwrap();
            if self.recovery.is_none() {
                let s = self.session.as_mut().ok_or(Error::State)?;
                s.head = f.end;
                s.last = now;
            }
        }
        Ok(())
    }
    pub(in crate::ath9k) fn single_delivered(
        &mut self,
        seq: u16,
        delivered: bool,
        now: u64,
        epoch: u64,
        captured: u64,
    ) -> Result<(), Error> {
        if let Some(s) = &mut self.session {
            if epoch == captured && delivered && self.recovery.is_none() {
                if seq != s.head {
                    return Err(Error::State);
                }
                s.head = (seq + 1) & 4095;
                s.last = now;
            } else {
                self.recovery = Some((seq + 1) & 4095);
            }
        }
        Ok(())
    }
    pub(in crate::ath9k) fn bar_delivered(&mut self, ticket: u64, epoch: u64) -> Result<(), Error> {
        let Some(b) = self.bar.as_mut().filter(|b| b.ticket == ticket) else {
            return Ok(());
        };
        if b.cancelled || b.epoch != epoch {
            self.bar = None;
        } else {
            b.receipt = true;
        }
        Ok(())
    }
    pub(in crate::ath9k) fn progress_bar(&mut self, now: u64) -> Result<(), Error> {
        if self.bar.as_ref().is_some_and(|b| now >= b.deadline) {
            return Err(Error::Timeout);
        }
        if self.bar.as_ref().is_some_and(|b| b.receipt && !b.cancelled) {
            let b = self.bar.take().unwrap();
            let s = self.session.as_mut().ok_or(Error::State)?;
            s.head = b.target;
            s.last = now;
            self.recovery = None;
        }
        Ok(())
    }
    pub(in crate::ath9k) fn key_epoch(&mut self, next: u16, now: u64) -> Result<(), Error> {
        let proposal_idle = self.proposal.as_ref().is_some_and(|p| p.receipt);
        if let Some(p) = &mut self.proposal {
            p.cancelled = true;
        }
        if proposal_idle {
            self.proposal = None;
            self.begin_delba(37)?;
        }
        if self.session.is_some() {
            self.recovery = Some(next);
        }
        let bar_idle = self.bar.as_ref().is_some_and(|b| b.receipt);
        if let Some(b) = &mut self.bar {
            b.cancelled = true;
        }
        if bar_idle {
            self.bar = None;
        }
        if let Some(f) = &mut self.flight {
            f.originals.iter_mut().for_each(|original| *original = None);
            f.end = next;
        }
        self.finish_flight(now)
    }
    fn begin_delba(&mut self, reason: u16) -> Result<(), Error> {
        let ticket = self.ticket()?;
        self.session = None;
        self.proposal = None;
        self.flight = None;
        self.recovery = None;
        self.bar = None;
        self.delba = Some(Delba {
            ticket,
            reason,
            sent: false,
        });
        Ok(())
    }
    pub(in crate::ath9k) fn delba_delivered(&mut self, ticket: u64) {
        if self.delba.as_ref().is_some_and(|d| d.ticket == ticket) {
            self.delba = None;
            self.disabled = true;
        }
    }
    pub(in crate::ath9k) fn peer_delba(&mut self, b: &[u8], own: [u8; 6], ap: [u8; 6]) -> bool {
        if b.len() != 30
            || b[..2] != [0xd0, 0]
            || b[4..10] != own
            || b[10..16] != ap
            || b[16..22] != ap
            || b[22] & 15 != 0
            || b[24..26] != [3, 2]
            || u16::from_le_bytes([b[26], b[27]]) != 0
        {
            return false;
        }
        self.retire();
        true
    }
    pub(in crate::ath9k) fn retire(&mut self) {
        self.proposal = None;
        self.session = None;
        self.flight = None;
        self.bar = None;
        self.recovery = None;
        self.delba = None;
        self.disabled = true;
    }
}
fn management(own: [u8; 6], ap: [u8; 6]) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&ap);
    f.extend_from_slice(&own);
    f.extend_from_slice(&ap);
    f.extend_from_slice(&[0, 0]);
    f
}
fn delba(own: [u8; 6], ap: [u8; 6], reason: u16) -> Vec<u8> {
    let mut f = management(own, ap);
    f.extend_from_slice(&[3, 2]);
    f.extend_from_slice(&0x800u16.to_le_bytes());
    f.extend_from_slice(&reason.to_le_bytes());
    f
}
fn bar(own: [u8; 6], ap: [u8; 6], ssn: u16) -> Vec<u8> {
    let mut f = vec![0x84, 0, 0, 0];
    f.extend_from_slice(&ap);
    f.extend_from_slice(&own);
    f.extend_from_slice(&4u16.to_le_bytes());
    f.extend_from_slice(&(ssn << 4).to_le_bytes());
    f
}
