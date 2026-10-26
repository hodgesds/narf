// SPDX-License-Identifier: GPL-2.0-or-later
//! Native firmware-negotiated RX BA and PPDU ownership before software CCMP.
//! Linux htt.h/htt_rx.c and mac80211 offloaded auto_seq are the wire sources.
use super::{ht, Error, Incoming};
use alloc::vec::Vec;
use narf_wireless::reorder::Reorder;

const TIMEOUT_NS: u64 = 100_000_000;
#[derive(Debug)]
struct Session {
    peer: u16,
    window: u8,
    order: Reorder<Incoming>,
}
#[derive(Debug)]
struct Ppdu {
    peer: u16,
    tid: u8,
    started: u64,
    count: u8,
    bytes: usize,
}
#[derive(Debug)]
pub(super) struct Owner {
    profile: Option<ht::Profile>,
    sessions: Vec<Option<Session>>,
    ppdu: Option<Ppdu>,
}
fn order_error(error: narf_wireless::reorder::Error) -> Error {
    match error {
        narf_wireless::reorder::Error::Allocation => Error::NoMemory,
        _ => Error::Malformed,
    }
}
impl Owner {
    pub(super) fn new(profile: Option<ht::Profile>) -> Result<Self, Error> {
        let mut sessions = Vec::new();
        sessions
            .try_reserve_exact(16)
            .map_err(|_| Error::NoMemory)?;
        sessions.resize_with(16, || None);
        Ok(Self {
            profile,
            sessions,
            ppdu: None,
        })
    }
    pub(super) fn ht(&self) -> bool {
        self.profile.is_some()
    }
    fn active(&self, peer: u16, tid: u8) -> bool {
        self.sessions
            .get(usize::from(tid))
            .and_then(Option::as_ref)
            .is_some_and(|s| s.peer == peer)
    }
    pub(super) fn discard_ppdu(&mut self) {
        self.ppdu = None;
    }
    pub(super) fn phy(
        &mut self,
        peer: u16,
        tid: u8,
        descriptor: &[u8],
        aggregateable: bool,
        mpdu_bytes: usize,
        now: u64,
    ) -> bool {
        let word = |at| u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
        let flags = word(4) & 3;
        if flags == 3 {
            self.ppdu = None;
            return self
                .profile
                .map_or_else(|| word(104) >> 24 == 4, |p| p.accepts(descriptor));
        }
        if !aggregateable || !self.active(peer, tid) {
            self.ppdu = None;
            return false;
        }
        if flags == 1 {
            self.ppdu = None;
            if !matches!(word(104) >> 24, 8 | 9)
                || self.profile.is_none_or(|p| !p.accepts(descriptor))
            {
                return false;
            }
            self.ppdu = Some(Ppdu {
                peer,
                tid,
                started: now,
                count: 1,
                bytes: 4 + mpdu_bytes.next_multiple_of(4),
            });
            return true;
        }
        let valid = self.ppdu.as_mut().is_some_and(|p| {
            if p.peer != peer
                || p.tid != tid
                || p.count == 64
                || p.bytes.saturating_add(4 + mpdu_bytes.next_multiple_of(4)) > 8191
                || now.saturating_sub(p.started) >= TIMEOUT_NS
            {
                return false;
            }
            p.count += 1;
            p.bytes += 4 + mpdu_bytes.next_multiple_of(4);
            true
        });
        // Middle descriptor PHY fields are not valid. Only a matching
        // retained FIRST context may admit them, through exactly this LAST.
        if !valid || flags == 2 {
            self.ppdu = None;
        }
        valid
    }
    pub(super) fn note(&mut self, bytes: &[u8], owns: impl Fn(u16) -> bool) -> Result<bool, Error> {
        match bytes.first() {
            Some(5 | 6) => {
                if bytes.len() != 4 {
                    return Err(Error::Malformed);
                }
                let info = u16::from_le_bytes([bytes[2], bytes[3]]);
                let peer = info >> 4;
                let tid = usize::from(info & 15);
                if !owns(peer) {
                    return Ok(true);
                }
                if self.profile.is_none() {
                    return Err(Error::Unsupported);
                }
                if bytes[0] == 5 {
                    let window = bytes[1];
                    if !(1..=64).contains(&window) {
                        return Err(Error::Malformed);
                    }
                    if let Some(s) = &self.sessions[tid] {
                        // A repeated notification cannot reset sequence/age.
                        if s.peer != peer || s.window != window {
                            return Err(Error::Malformed);
                        }
                    } else {
                        self.sessions[tid] = Some(Session {
                            peer,
                            window,
                            order: Reorder::new(window, TIMEOUT_NS).map_err(order_error)?,
                        });
                    }
                } else {
                    if bytes[1] != 0 {
                        return Err(Error::Malformed);
                    }
                    if self.sessions[tid].as_ref().is_some_and(|s| s.peer == peer) {
                        self.sessions[tid] = None;
                    }
                    if self
                        .ppdu
                        .as_ref()
                        .is_some_and(|p| p.peer == peer && usize::from(p.tid) == tid)
                    {
                        self.ppdu = None;
                    }
                }
                Ok(true)
            }
            Some(2) => {
                if bytes.len() != 8 {
                    return Err(Error::Malformed);
                }
                let peer = u16::from_le_bytes([bytes[1], bytes[2]]);
                if !owns(peer) {
                    return Ok(true);
                }
                if bytes[3] >= 16
                    || bytes[4] != 0
                    || bytes[5] > 1
                    || bytes[6] >= 64
                    || bytes[7] >= 64
                {
                    return Err(Error::Malformed);
                }
                // Native host sequence windows own reorder/timeout now. Linux
                // likewise ignores target FLUSH once mac80211 owns ordering.
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    pub(super) fn push(&mut self, incoming: Incoming, now: u64) -> Result<Vec<Incoming>, Error> {
        let frame = &incoming.frame.0;
        if frame[0] == 0x88 && frame[4] & 1 == 0 {
            let tid = usize::from(frame[24] & 15);
            if let Some(s) = self.sessions[tid]
                .as_mut()
                .filter(|s| s.peer == incoming.peer)
            {
                let sequence = u16::from_le_bytes([frame[22], frame[23]]) >> 4;
                return s.order.push(sequence, now, incoming).map_err(order_error);
            }
        }
        let mut ready = Vec::new();
        ready.try_reserve_exact(1).map_err(|_| Error::NoMemory)?;
        ready.push(incoming);
        Ok(ready)
    }
    pub(super) fn expire(&mut self, now: u64) -> Result<Vec<Incoming>, Error> {
        let count: usize = self
            .sessions
            .iter()
            .flatten()
            .map(|s| s.order.buffered())
            .sum();
        let mut ready = Vec::new();
        ready
            .try_reserve_exact(count)
            .map_err(|_| Error::NoMemory)?;
        for s in self.sessions.iter_mut().flatten() {
            ready.extend(s.order.expire(now).map_err(order_error)?);
        }
        if self
            .ppdu
            .as_ref()
            .is_some_and(|p| now.saturating_sub(p.started) >= TIMEOUT_NS)
        {
            self.ppdu = None;
        }
        Ok(ready)
    }
    pub(super) fn bar(
        &mut self,
        peer: u16,
        tid: u8,
        sequence: u16,
        now: u64,
    ) -> Result<Vec<Incoming>, Error> {
        let Some(s) = self
            .sessions
            .get_mut(usize::from(tid))
            .and_then(Option::as_mut)
            .filter(|s| s.peer == peer)
        else {
            return Ok(Vec::new());
        };
        s.order.advance(sequence, now).map_err(order_error)
    }
    pub(super) fn station_bar(
        &mut self,
        tid: u8,
        sequence: u16,
        now: u64,
    ) -> Result<Vec<Incoming>, Error> {
        let Some(peer) = self
            .sessions
            .get(usize::from(tid))
            .and_then(Option::as_ref)
            .map(|s| s.peer)
        else {
            return Ok(Vec::new());
        };
        self.bar(peer, tid, sequence, now)
    }
    pub(super) fn retain(&mut self, owns: impl Fn(u16) -> bool) {
        for slot in &mut self.sessions {
            if slot.as_ref().is_some_and(|s| !owns(s.peer)) {
                *slot = None;
            }
        }
        if self.ppdu.as_ref().is_some_and(|p| !owns(p.peer)) {
            self.ppdu = None;
        }
    }
    pub(super) fn flush(&mut self) {
        for s in self.sessions.iter_mut().flatten() {
            s.order.clear();
        }
        self.ppdu = None;
    }
    pub(super) fn clear(&mut self) {
        for s in &mut self.sessions {
            *s = None;
        }
        self.ppdu = None;
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn state(&self, tid: u8) -> Option<(u16, u8, usize, Option<u16>)> {
        let s = self.sessions.get(usize::from(tid))?.as_ref()?;
        Some((s.peer, s.window, s.order.buffered(), s.order.head()))
    }
}
