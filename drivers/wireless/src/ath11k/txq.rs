//! Per-AC transmit queues between the netdev and `ath11k_dp_tx` —
//! mac80211's intermediate TX queues (`struct txq_info`) and hardware
//! queue stop / wake (`local->queue_stop_reasons[]`) for the one station
//! vif.
//!
//! | NARF | Linux |
//! |---|---|
//! | one stack TX ring per netdev | `ieee80211_if_add`: `alloc_netdev_mqs(.., 1, 1)` (a single netdev queue; mac80211 queues per TXQ) |
//! | [`TxQueues::enqueue`] | `ieee80211_select_queue` (the AC) → `ieee80211_queue_skb` → `fq_tin_enqueue` (overlimit: `fq->limit` 8192 packets / `memory_limit` 16 MiB, drop from the fattest flow's head) |
//! | [`TxQueues::dequeue`] | `ieee80211_handle_wake_tx_queue` → `ieee80211_next_txq` / `ieee80211_tx_dequeue`: nothing leaves a TXQ whose hardware queue `vif->hw_queue[ac]` has a stop reason |
//! | [`TxQueues::stop`] / [`TxQueues::wake`] | `ieee80211_stop_queues_by_reason` / `ieee80211_wake_queues_by_reason` |
//! | [`TxQueues::purge`] | `ieee80211_purge_sta_txqs` / `ieee80211_txq_purge` |
//! | [`hw_queue`] | `ath11k_mac_op_add_interface`: `vif->hw_queue[i] = i % (ATH11K_HW_MAX_QUEUES - 1)` |
//!
//! Order: frames reach the driver as they are enqueued unless their
//! hardware queue is stopped (mac80211 transmits from the sender's
//! context); a backlog — frames that queued while their queue was
//! stopped, or while the runtime was busy — drains AC by AC from VO to
//! BK, the order `_ieee80211_wake_txqs` walks the ACs in. Within an AC
//! frames keep their order (one station, so mac80211's airtime round
//! robin over TXQs never applies across stations; NARF keeps one FIFO
//! per AC instead of one TXQ per TID — the deviation is listed in
//! `ath11k.md` §8).

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// `IEEE80211_NUM_ACS`.
pub const NUM_ACS: usize = 4;
/// `ATH11K_HW_MAX_QUEUES` (`hw->queues`).
pub const ATH11K_HW_MAX_QUEUES: usize = 4;
/// `fq_init`: `fq->limit`.
pub const FQ_LIMIT: usize = 8192;
/// `ieee80211_txq_setup_flows`: `fq->memory_limit` (16 MiB; 4 MiB only
/// without VHT, which every ath11k part has).
pub const FQ_MEMORY_LIMIT: usize = 16 << 20;

/// `enum queue_stop_reason` (net/mac80211/ieee80211_i.h).
pub mod reason {
    pub const DRIVER: u32 = 0;
    pub const PS: u32 = 1;
    pub const CSA: u32 = 2;
    pub const AGGREGATION: u32 = 3;
    pub const SUSPEND: u32 = 4;
    pub const SKB_ADD: u32 = 5;
    pub const OFFCHANNEL: u32 = 6;
    pub const FLUSH: u32 = 7;
    pub const TDLS_TEARDOWN: u32 = 8;
    pub const RESERVE_TID: u32 = 9;
    pub const IFTYPE_CHANGE: u32 = 10;
}

/// The hardware queue of access category `ac` (`vif->hw_queue[ac]`):
/// VO → 0, VI → 1, BE → 2, BK → 0.
pub const fn hw_queue(ac: u16) -> usize {
    ac as usize % (ATH11K_HW_MAX_QUEUES - 1)
}

/// One queued frame: the Ethernet frame from the stack and its
/// `CHECKSUM_PARTIAL` flag (`skb->ip_summed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queued {
    pub eth: Vec<u8>,
    pub csum_partial: bool,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxqStats {
    pub enqueued: u32,
    /// `fq->overlimit`.
    pub overlimit: u32,
    /// Purged (`ieee80211_purge_sta_txqs`, interface down).
    pub purged: u32,
}

/// The station's TX queues (indexed by `enum ieee80211_ac_numbers`:
/// VO 0, VI 1, BE 2, BK 3) and the stop reasons of the four hardware
/// queues.
#[derive(Debug)]
pub struct TxQueues {
    q: [VecDeque<Queued>; NUM_ACS],
    /// `local->queue_stop_reasons[queue]` (a bit per reason).
    stop: [u32; ATH11K_HW_MAX_QUEUES],
    limit: usize,
    memory_limit: usize,
    backlog_bytes: usize,
    pub stats: TxqStats,
}

impl Default for TxQueues {
    fn default() -> Self {
        Self::with_limits(FQ_LIMIT, FQ_MEMORY_LIMIT)
    }
}

impl TxQueues {
    /// Queues with mac80211's limits replaced (tests).
    pub fn with_limits(limit: usize, memory_limit: usize) -> Self {
        TxQueues {
            q: Default::default(),
            stop: [0; ATH11K_HW_MAX_QUEUES],
            limit,
            memory_limit,
            backlog_bytes: 0,
            stats: TxqStats::default(),
        }
    }

    /// Frames waiting in AC `ac`.
    pub fn len(&self, ac: u16) -> usize {
        self.q[ac as usize & 3].len()
    }

    /// Frames waiting in every AC (`fq->backlog`).
    pub fn backlog(&self) -> usize {
        self.q.iter().map(VecDeque::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.backlog() == 0
    }

    /// `local->queue_stop_reasons[queue]`.
    pub fn stop_reasons(&self, queue: usize) -> u32 {
        self.stop[queue % ATH11K_HW_MAX_QUEUES]
    }

    /// `fq_tin_enqueue` into AC `ac`. Over `fq->limit` / `memory_limit`
    /// the head of the longest queue is dropped (`fq_drop` from the
    /// fattest flow; one flow per AC here) and returned.
    pub fn enqueue(&mut self, ac: u16, f: Queued) -> Vec<Queued> {
        self.backlog_bytes += f.eth.len();
        self.q[ac as usize & 3].push_back(f);
        self.stats.enqueued += 1;
        let mut dropped = Vec::new();
        while self.backlog() > self.limit || self.backlog_bytes > self.memory_limit {
            let fattest = (0..NUM_ACS).max_by_key(|&i| self.q[i].len()).unwrap_or(0);
            let Some(d) = self.q[fattest].pop_front() else {
                break;
            };
            self.backlog_bytes -= d.eth.len();
            self.stats.overlimit += 1;
            dropped.push(d);
        }
        dropped
    }

    /// The next frame the driver gets: the first AC from VO to BK that
    /// has a frame and whose hardware queue has no stop reason.
    pub fn dequeue(&mut self) -> Option<(u16, Queued)> {
        for ac in 0..NUM_ACS as u16 {
            if self.stop[hw_queue(ac)] != 0 {
                continue;
            }
            if let Some(f) = self.q[ac as usize].pop_front() {
                self.backlog_bytes -= f.eth.len();
                return Some((ac, f));
            }
        }
        None
    }

    /// `ieee80211_stop_queues_by_reason(hw, queues, reason, false)` for
    /// the hardware queues in the bitmap `queues`.
    pub fn stop(&mut self, queues: u32, reason: u32) {
        for (i, s) in self.stop.iter_mut().enumerate() {
            if queues & (1 << i) != 0 {
                *s |= 1 << reason;
            }
        }
    }

    /// `ieee80211_wake_queues_by_reason(hw, queues, reason, false)`.
    pub fn wake(&mut self, queues: u32, reason: u32) {
        for (i, s) in self.stop.iter_mut().enumerate() {
            if queues & (1 << i) != 0 {
                *s &= !(1 << reason);
            }
        }
    }

    /// `ieee80211_get_vif_queues` for the station vif: every AC's
    /// hardware queue (+ the CAB queue, unused by a station).
    pub const fn vif_queues() -> u32 {
        (1 << hw_queue(0)) | (1 << hw_queue(1)) | (1 << hw_queue(2)) | (1 << hw_queue(3))
    }

    /// `ieee80211_purge_sta_txqs`: drop every queued frame; returns how
    /// many.
    pub fn purge(&mut self) -> u32 {
        let n = self.backlog() as u32;
        for q in self.q.iter_mut() {
            q.clear();
        }
        self.backlog_bytes = 0;
        self.stats.purged += n;
        n
    }
}
