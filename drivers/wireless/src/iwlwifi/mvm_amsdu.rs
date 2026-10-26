//! API4 firmware deaggregation: no prefix delivery or replay update before
//! the last checked subframe. Linux mvm/rxmq.c::iwl_mvm_is_dup describes the
//! per-sequence/index same-PN exception; this owner bounds it to one aggregate.
use super::super::{
    frame_api::{self, Replay},
    scan_api::Mpdu,
};
use alloc::{collections::VecDeque, vec::Vec};

fn ethernet_allowed(frame: &[u8], local: [u8; 6]) -> bool {
    if frame.len() < 14 || frame[6] & 1 != 0 || frame[6..12] == [0; 6] || frame[6..12] == local {
        return false;
    }
    let mut protocol = u16::from_be_bytes([frame[12], frame[13]]);
    let mut at = 14;
    for _ in 0..2 {
        if !matches!(protocol, 0x8100 | 0x88a8) {
            break;
        }
        let Some(tag) = frame.get(at..at + 4) else {
            return false;
        };
        protocol = u16::from_be_bytes([tag[2], tag[3]]);
        at += 4;
    }
    protocol >= 0x600
        && !matches!(
            protocol,
            0x888e | 0x88c7 | 0x80f3 | 0x8137 | 0x8100 | 0x88a8
        )
}

#[derive(Default)]
pub(super) struct Receiver {
    pending: Option<Pending>,
    ready: VecDeque<Vec<u8>>,
}
struct Pending {
    identity: ([u8; 6], u8, u16, u8, u64),
    next: u8,
    bytes: usize,
    deadline: u64,
    replay: Replay,
    frames: VecDeque<Vec<u8>>,
}
impl Receiver {
    pub fn cancel_pending(&mut self) {
        self.pending = None;
    }
    pub fn defer_validated(&mut self, frame: Vec<u8>) {
        // Only a completed native receive may requeue its owned Ethernet
        // result while management work takes the sole producer slot.
        self.ready.push_front(frame);
    }
    pub fn clear(&mut self) {
        self.pending = None;
        self.ready.clear();
    }
    pub fn pop(&mut self, now: u64) -> Option<Vec<u8>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| now.wrapping_sub(p.deadline) < (1u64 << 63))
        {
            self.pending = None;
        }
        self.ready.pop_front()
    }
    pub fn observe(
        &mut self,
        mpdu: &Mpdu<'_>,
        own: [u8; 6],
        peer: [u8; 6],
        secure: bool,
        replay: &mut Replay,
        now: u64,
    ) -> Option<Vec<u8>> {
        if !mpdu.amsdu {
            self.pending = None;
            return frame_api::receive(mpdu, own, peer, secure, replay);
        }
        let f = mpdu.frame;
        let mut result = None;
        let accepted = (|| {
            if f.get(24).is_none_or(|q| q & 15 > 7 || q & 0x80 == 0) {
                return None;
            }
            let tid = f[24] & 15;
            let sequence = u16::from_le_bytes(f.get(22..24)?.try_into().ok()?);
            let encrypted = f[1] & 0x40 != 0;
            let (pn, key) = if encrypted {
                let iv = f.get(26..34)?.try_into().ok()?;
                let (pn, key) = narf_wireless::ccmp::decode_ccmp_header(iv).ok()?;
                (pn, key + if f[4] & 1 != 0 { 2 } else { 1 })
            } else {
                (0, 0)
            };
            let identity = (peer, tid, sequence, key, pn);
            if let Some(p) = &self.pending {
                if p.identity != identity
                    || p.next != mpdu.amsdu_index
                    || now.wrapping_sub(p.deadline) < (1u64 << 63)
                {
                    return None;
                }
            } else {
                // API4's explicit low7 subframe index must start at zero.
                // A suffix beginning at1 can never establish completeness.
                if mpdu.amsdu_index != 0 {
                    return None;
                }
                self.pending = Some(Pending {
                    identity,
                    next: mpdu.amsdu_index,
                    bytes: 0,
                    deadline: now.wrapping_add(narf_time::wall::ns_to_cycles(100_000_000)),
                    replay: replay.clone(),
                    frames: VecDeque::new(),
                });
            }
            let p = self.pending.as_mut()?;
            let ethernet = frame_api::receive(mpdu, own, peer, secure, &mut p.replay)?;
            if ethernet.len() > 1514 || !ethernet_allowed(&ethernet, own) {
                return None;
            }
            let extent = ethernet.len().checked_add(8)?;
            p.bytes = p.bytes.checked_add(if mpdu.amsdu_last {
                extent
            } else {
                extent.next_multiple_of(4)
            })?;
            if p.bytes > 3839 || p.frames.len() >= 128 {
                return None;
            }
            p.frames.push_back(ethernet);
            if mpdu.amsdu_last {
                let complete = self.pending.take()?;
                *replay = complete.replay;
                self.ready = complete.frames;
                result = self.ready.pop_front();
            } else {
                p.next = p.next.checked_add(1)?;
            }
            Some(())
        })();
        if accepted.is_none() {
            self.clear();
        }
        result
    }
}
