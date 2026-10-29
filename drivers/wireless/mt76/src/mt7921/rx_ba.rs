// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded recipient BA protocol/reorder owner. Source: Linux mt76/agg-rx.c,
//! mt76_connac_mcu.{c,h}, mt7921/mcu.c; IEEE ADDBA/DELBA/compressed BAR.
use alloc::{collections::VecDeque, vec, vec::Vec};

pub(super) const TIDS: usize = 8; // Native STA_REC_BA.ba_en is one octet.

// CONNAC2 WTBL/STA_REC_BA carry the actual16-bit window, without CONNAC1's
// discrete range index. mac80211 agg-rx.c bounds a non-HE peer at
// IEEE80211_MAX_AMPDU_BUF_HT (64) and an HE peer at IEEE80211_MAX_AMPDU_BUF_HE
// (256, also mt792x's max_rx_aggregation_subframes); EHT/MLO is not admitted.
pub(super) const HT_WINDOW: u16 = 64;
pub(super) const HE_WINDOW: u16 = crate::mt7921::he::MAX_AMPDU_BUF_HE;
/// mt792x_core.c `max_rx_aggregation_subframes = IEEE80211_MAX_AMPDU_BUF_HE`.
const DRIVER_WINDOW: u16 = HE_WINDOW;
const MAX_WINDOW: u16 = HE_WINDOW;
const MAX_READY: usize = TIDS * MAX_WINDOW as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub dialog: u8,
    pub tid: u8,
    pub ssn: u16,
    pub window: u16,
    pub timeout: u16,
    pub amsdu: bool,
}
impl Request {
    /// `limit` is the peer's mac80211 `max_buf_size`: `HE_WINDOW` for a
    /// negotiated HE peer, otherwise `HT_WINDOW`.
    pub fn parse(frame: &[u8], limit: u16) -> Option<Self> {
        if frame.len() != 33 || frame[24..26] != [3, 0] {
            return None;
        }
        let parameters = u16::from_le_bytes([frame[27], frame[28]]);
        let tid = ((parameters >> 2) & 15) as u8;
        let requested = parameters >> 6;
        let sequence = u16::from_le_bytes([frame[31], frame[32]]);
        if parameters & 2 == 0 || usize::from(tid) >= TIDS || sequence & 15 != 0 {
            return None;
        }
        if !matches!(limit, HT_WINDOW | HE_WINDOW) || requested > limit {
            return None; // Oversize: declined, see `oversize`.
        }
        // Zero selects max_buf_size; only then does mac80211 clamp to the
        // driver's max_rx_aggregation_subframes (mt792x: HE_WINDOW).
        let window = if requested == 0 { limit } else { requested }.min(DRIVER_WINDOW);
        Some(Self {
            dialog: frame[26],
            tid,
            ssn: sequence >> 4,
            window,
            timeout: u16::from_le_bytes([frame[29], frame[30]]),
            amsdu: parameters & 1 != 0,
        })
    }
    /// mac80211 `__ieee80211_start_rx_ba_session` (agg-rx.c:337-357):
    /// after the TID check (REQUEST_DECLINED), `buf_size > max_buf_size`
    /// is declined with WLAN_STATUS_INVALID_QOS_PARAM, never clamped.
    pub fn oversize(frame: &[u8], limit: u16) -> bool {
        if frame.len() != 33 || frame[24..26] != [3, 0] {
            return false;
        }
        let parameters = u16::from_le_bytes([frame[27], frame[28]]);
        usize::from((parameters >> 2) & 15) < TIDS && parameters >> 6 > limit
    }
    pub fn response(self, own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
        let mut frame = action(own, peer, 33);
        frame[24..29].copy_from_slice(&[3, 1, self.dialog, 0, 0]);
        // Permit nested A-MSDU only when the actual request offers it; the
        // host still assembles/checks a whole MPDU before reorder/PN commit.
        frame[29..31].copy_from_slice(
            &(2 | u16::from(self.amsdu) | u16::from(self.tid) << 2 | self.window << 6)
                .to_le_bytes(),
        );
        frame[31..33].copy_from_slice(&self.timeout.to_le_bytes());
        frame
    }
    pub fn wtbl(self, peer: [u8; 6], enable: bool) -> Vec<u8> {
        // STA_REC_UPDATE: one outer WTBL TLV, WTBL_SET, one WTBL_BA.
        let mut body = vec![0; 48];
        body[..8].copy_from_slice(&[0, 1, 1, 0, 1, 0, 0, 0]);
        body[8..20].copy_from_slice(&[13, 0, 40, 0, 1, 2, 1, 0, 0, 0, 0, 0]);
        body[20..24].copy_from_slice(&[8, 0, 28, 0]);
        body[24] = self.tid;
        body[25] = 2; // MT_BA_TYPE_RECIPIENT.
        body[32..34].copy_from_slice(&if enable { self.window } else { 0 }.to_le_bytes());
        body[34..40].copy_from_slice(&peer);
        body[40] = self.tid; // rst_ba_tid.
        body[42] = 1; // rst_ba_sel MAC_TID_MATCH=0; rst_ba_sb=1.
        body
    }
    pub fn station(self, enable: bool) -> Vec<u8> {
        let mut body = vec![0; 20];
        body[..8].copy_from_slice(&[0, 1, 1, 0, 1, 0, 0, 0]);
        body[8..12].copy_from_slice(&[6, 0, 12, 0]); // STA_REC_BA.
        body[12] = self.tid;
        body[13] = 2;
        body[14] = u8::from(self.amsdu); // Source STA_REC_BA.amsdu, independently of enable.
        body[15] = if enable { 1 << self.tid } else { 0 };
        body[16..18].copy_from_slice(&self.ssn.to_le_bytes());
        body[18..20].copy_from_slice(&self.window.to_le_bytes());
        body
    }
    pub fn delba(self, own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
        let mut frame = action(own, peer, 30);
        frame[24..26].copy_from_slice(&[3, 2]);
        frame[26..28].copy_from_slice(&(u16::from(self.tid) << 12).to_le_bytes()); // Recipient, initiator=0.
        frame[28..30].copy_from_slice(&39u16.to_le_bytes()); // WLAN_REASON_QSTA_TIMEOUT.
        frame
    }
}
fn action(own: [u8; 6], peer: [u8; 6], length: usize) -> Vec<u8> {
    let mut frame = vec![0; length];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&peer);
    frame[10..16].copy_from_slice(&own);
    frame[16..22].copy_from_slice(&peer);
    frame
}

#[derive(Debug)]
pub(super) struct Packet {
    pub sequence: u16,
    pub pn: Option<u64>,
    pub frames: VecDeque<Vec<u8>>,
    pub eapol: Option<Vec<u8>>,
    at: u64,
}
impl Packet {
    pub fn new(
        sequence: u16,
        pn: Option<u64>,
        frames: VecDeque<Vec<u8>>,
        eapol: Option<Vec<u8>>,
    ) -> Self {
        Self {
            sequence,
            pn,
            frames,
            eapol,
            at: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Active,
    Retiring,
}
#[derive(Debug)]
struct Agreement {
    request: Request,
    epoch: u64,
    phase: Phase,
    head: u16,
    activity: u64,
    slots: Vec<Option<Packet>>,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Work {
    Start(u8, u64),
    Repeat(u8, u64),
    Stop(u8, u64, bool),
}
#[derive(Debug)]
struct Ready {
    tid: u8,
    epoch: u64,
    packet: Packet,
}
#[derive(Debug)]
pub(super) struct Owner {
    epoch: u64,
    agreements: [Option<Agreement>; TIDS],
    work: VecDeque<Work>,
    ready: VecDeque<Ready>,
}
impl Default for Owner {
    fn default() -> Self {
        Self {
            epoch: 1,
            agreements: core::array::from_fn(|_| None),
            work: VecDeque::new(),
            ready: VecDeque::new(),
        }
    }
}
impl Owner {
    pub fn reserve(&mut self, request: Request, now: u64) -> bool {
        if usize::from(request.tid) >= TIDS
            || request.window == 0
            || request.window > MAX_WINDOW
            || request.ssn >= 4096
            || self.epoch == u64::MAX
        {
            return false;
        }
        let slot = &mut self.agreements[usize::from(request.tid)];
        if let Some(previous) = slot {
            if previous.phase == Phase::Active
                && previous.epoch == self.epoch
                && previous.request == request
            {
                if self.work.len() < 4 {
                    self.work.push_back(Work::Repeat(request.tid, self.epoch));
                }
                return true;
            }
            // No replacement/reset of a live sequence/PN owner. A duplicate
            // pending setup waits for its original response, without a new job.
            return previous.phase == Phase::Reserved && previous.request == request;
        }
        if self.work.len() >= 4 {
            return false;
        }
        *slot = Some(Agreement {
            request,
            epoch: self.epoch,
            phase: Phase::Reserved,
            head: request.ssn,
            activity: now,
            slots: (0..request.window).map(|_| None).collect(),
        });
        self.work.push_back(Work::Start(request.tid, self.epoch));
        true
    }
    pub fn pending(&self, now: u64) -> bool {
        !self.work.is_empty()
            || self
                .agreements
                .iter()
                .flatten()
                .any(|a| Self::expired(a, now))
    }
    fn expired(a: &Agreement, now: u64) -> bool {
        a.phase == Phase::Active
            && a.request.timeout != 0
            && now.saturating_sub(a.activity) >= u64::from(a.request.timeout) * 1_024_000
    }
    pub fn request(&self, tid: u8, epoch: u64) -> Option<Request> {
        self.agreements
            .get(usize::from(tid))?
            .as_ref()
            .filter(|a| a.epoch == epoch)
            .map(|a| a.request)
    }
    pub fn next(&mut self) -> Option<Work> {
        self.work.pop_front()
    }
    pub fn activate(&mut self, tid: u8, epoch: u64, now: u64) -> bool {
        let Some(a) = self
            .agreements
            .get_mut(usize::from(tid))
            .and_then(Option::as_mut)
        else {
            return false;
        };
        if a.epoch != epoch || a.epoch != self.epoch || a.phase != Phase::Reserved {
            return false;
        }
        a.phase = Phase::Active;
        a.activity = now;
        true
    }
    pub fn response_complete(&mut self, tid: u8, epoch: u64, now: u64) {
        if let Some(a) = self
            .agreements
            .get_mut(usize::from(tid))
            .and_then(Option::as_mut)
            .filter(|a| a.phase == Phase::Active && a.epoch == epoch)
        {
            a.activity = now;
        }
    }
    pub fn active(&self, tid: u8) -> bool {
        self.agreements
            .get(usize::from(tid))
            .and_then(Option::as_ref)
            .is_some_and(|a| a.phase == Phase::Active && a.epoch == self.epoch)
    }
    pub fn owns(&self, tid: u8) -> bool {
        self.agreements
            .get(usize::from(tid))
            .is_some_and(Option::is_some)
    }
    pub fn amsdu(&self, tid: u8) -> bool {
        self.active(tid)
            && self.agreements[usize::from(tid)]
                .as_ref()
                .is_some_and(|agreement| agreement.request.amsdu)
    }
    pub fn stop(&mut self, tid: u8, notify: bool) {
        let Some(a) = self
            .agreements
            .get_mut(usize::from(tid))
            .and_then(Option::as_mut)
        else {
            return;
        };
        if a.phase == Phase::Retiring {
            return;
        }
        a.phase = Phase::Retiring;
        a.slots.iter_mut().for_each(|s| *s = None);
        self.ready.retain(|ready| ready.tid != tid);
        // At most eight stop jobs plus the four bounded setup/repeat jobs.
        self.work
            .retain(|w| !matches!(w, Work::Start(t, _) | Work::Repeat(t, _) if *t == tid));
        self.work.push_back(Work::Stop(tid, a.epoch, notify));
    }
    pub fn finish_stop(&mut self, tid: u8, epoch: u64) {
        if self.request(tid, epoch).is_some() {
            self.agreements[usize::from(tid)] = None;
        }
    }
    pub fn fence(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.work.clear();
        self.ready.clear();
        for a in self.agreements.iter_mut().flatten() {
            a.phase = Phase::Retiring;
            a.slots.iter_mut().for_each(|s| *s = None);
        }
    }
    pub fn records(&self) -> Vec<(u8, u64, Request)> {
        self.agreements
            .iter()
            .flatten()
            .map(|a| (a.request.tid, a.epoch, a.request))
            .collect()
    }
    pub fn reset_after_quiescence(&mut self) {
        self.fence();
        self.agreements = core::array::from_fn(|_| None);
    }
    pub fn begin_connection(&mut self) -> bool {
        if self.agreements.iter().any(Option::is_some) || self.epoch == u64::MAX {
            return false;
        }
        self.fence();
        true
    }
    fn distance(sequence: u16, head: u16) -> u16 {
        sequence.wrapping_sub(head) & 4095
    }
    fn release(a: &mut Agreement, ready: &mut VecDeque<Ready>) {
        let index = a.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|packet| packet.sequence == a.head)
        });
        if let Some(packet) = index.and_then(|index| a.slots[index].take()) {
            if ready.len() < MAX_READY {
                ready.push_back(Ready {
                    tid: a.request.tid,
                    epoch: a.epoch,
                    packet,
                });
            }
        }
        a.head = (a.head + 1) & 4095;
    }
    fn advance(a: &mut Agreement, ready: &mut VecDeque<Ready>, target: u16) {
        let delta = Self::distance(target, a.head);
        if delta >= 2048 {
            return;
        }
        for _ in 0..delta.min(a.request.window) {
            Self::release(a, ready);
        }
        a.head = target;
    }
    fn contiguous(a: &mut Agreement, ready: &mut VecDeque<Ready>) {
        for _ in 0..a.request.window {
            if !a
                .slots
                .iter()
                .flatten()
                .any(|packet| packet.sequence == a.head)
            {
                break;
            }
            Self::release(a, ready);
        }
    }
    pub fn insert(&mut self, tid: u8, mut packet: Packet, now: u64) {
        if !self.active(tid) {
            return;
        }
        let a = self.agreements[usize::from(tid)].as_mut().unwrap();
        let delta = Self::distance(packet.sequence, a.head);
        if delta >= 2048
            || a.slots
                .iter()
                .flatten()
                .any(|p| p.sequence == packet.sequence || packet.pn.is_some() && p.pn == packet.pn)
            || self
                .ready
                .iter()
                .any(|p| p.tid == tid && packet.pn.is_some() && p.packet.pn == packet.pn)
        {
            return;
        }
        if delta >= a.request.window {
            Self::advance(
                a,
                &mut self.ready,
                packet
                    .sequence
                    .wrapping_sub(a.request.window)
                    .wrapping_add(1)
                    & 4095,
            );
        }
        // Sequence modulo window aliases different live SNs when an
        // arbitrary negotiated window crosses4095->0. Store the exact SN
        // in one of at most64 independent slots instead.
        let Some(slot) = a.slots.iter_mut().find(|slot| slot.is_none()) else {
            return;
        };
        packet.at = now;
        a.activity = now;
        *slot = Some(packet);
        Self::contiguous(a, &mut self.ready);
    }
    pub fn bar(&mut self, tid: u8, ssn: u16) {
        if !self.active(tid) {
            return;
        }
        let a = self.agreements[usize::from(tid)].as_mut().unwrap();
        Self::advance(a, &mut self.ready, ssn);
        Self::contiguous(a, &mut self.ready);
    }
    pub fn tick(&mut self, now: u64) -> bool {
        let mut retired = false;
        for tid in 0..TIDS {
            if self.agreements[tid]
                .as_ref()
                .is_some_and(|a| Self::expired(a, now))
            {
                self.stop(tid as u8, true);
                retired = true;
                continue;
            }
            if !self.active(tid as u8) {
                continue;
            }
            let a = self.agreements[tid].as_mut().unwrap();
            let timeout = if tid >= 4 { 40_000_000 } else { 100_000_000 };
            let mut target = None;
            for offset in 0..a.request.window {
                let sequence = (a.head + offset) & 4095;
                if a.slots.iter().flatten().any(|packet| {
                    packet.sequence == sequence && now.saturating_sub(packet.at) >= timeout
                }) {
                    target = Some((sequence + 1) & 4095);
                }
            }
            if let Some(target) = target {
                Self::advance(a, &mut self.ready, target);
                Self::contiguous(a, &mut self.ready);
            }
        }
        retired
    }
    pub fn pop(&mut self) -> Option<(u8, Packet)> {
        while let Some(ready) = self.ready.pop_front() {
            if ready.epoch == self.epoch && self.active(ready.tid) {
                return Some((ready.tid, ready.packet));
            }
        }
        None
    }
}
