//! mac80211-style transmit queues between the netdev and `ath11k_dp_tx`.
//!
//! NARF has one stack TX ring per netdev, so this module supplies the layer
//! mac80211 normally provides between that ring and ath11k's
//! `wake_tx_queue` callback: one TXQ for each 802.11 TID, a 4096-bucket
//! shared flow table, deficit round-robin within each TID, and fq_codel's
//! bounded-delay active queue management.
//!
//! | NARF | Linux |
//! |---|---|
//! | [`TxQueues::enqueue`] | `ieee80211_select_queue` → `ieee80211_queue_skb` → `fq_tin_enqueue` |
//! | [`TxQueues::dequeue`] | `ieee80211_handle_wake_tx_queue` → `ieee80211_next_txq` / `ieee80211_tx_dequeue` |
//! | [`TxQueues::stop`] / [`TxQueues::wake`] | `ieee80211_stop_queues_by_reason` / `ieee80211_wake_queues_by_reason` |
//! | [`TxQueues::purge`] | `ieee80211_purge_sta_txqs` / `ieee80211_txq_purge` |
//! | [`hw_queue`] | `ath11k_mac_op_add_interface`: `vif->hw_queue[i] = i % (ATH11K_HW_MAX_QUEUES - 1)` |
//!
//! Linux gets a precomputed `skb_get_hash()` from its stack. NARF's frame
//! ring deliberately carries no stack-private skb metadata, so [`flow_hash`]
//! derives an equivalent stable L2/L3/L4 hash at the boundary.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::dp_ring::ETH_HLEN;
use super::tx_hdr::{self, ac};

/// `IEEE80211_NUM_ACS`.
pub const NUM_ACS: usize = 4;
/// `IEEE80211_NUM_TIDS`.
pub const NUM_TIDS: usize = 16;
/// `ATH11K_HW_MAX_QUEUES` (`hw->queues`).
pub const ATH11K_HW_MAX_QUEUES: usize = 4;
/// `ieee80211_txq_setup_flows`: `fq_init(fq, 4096)`.
pub const FQ_FLOW_COUNT: usize = 4096;
/// `fq_init`: `fq->quantum`.
pub const FQ_QUANTUM: i32 = 300;
/// `fq_init`: `fq->limit`.
pub const FQ_LIMIT: usize = 8192;
/// `ieee80211_txq_setup_flows`: `fq->memory_limit` (16 MiB; WCN6855 has
/// VHT, so its 4 MiB non-VHT fallback never applies).
pub const FQ_MEMORY_LIMIT: usize = 16 << 20;
/// mac80211's `cparams.target` in `ieee80211_txq_setup_flows`.
pub const CODEL_TARGET_MS: u64 = 20;
/// mac80211's `cparams.interval` in `ieee80211_txq_setup_flows`.
pub const CODEL_INTERVAL_MS: u64 = 100;
/// The `codel_should_drop` low-backlog guard (`params->mtu`).
pub const CODEL_MTU: usize = 1500;

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
    pub const DFS_CAC: u32 = 11;
}

/// The hardware queue of access category `ac` (`vif->hw_queue[ac]`):
/// VO → 0, VI → 1, BE → 2, BK → 0.
pub const fn hw_queue(ac: u16) -> usize {
    ac as usize % (ATH11K_HW_MAX_QUEUES - 1)
}

/// The access category for a TID (`ieee80211_ac_from_tid`).
pub const fn ac_for_tid(tid: u8) -> u16 {
    tx_hdr::IEEE802_1D_TO_AC[tid as usize & 7]
}

/// One queued frame: the Ethernet frame from the stack, its
/// `CHECKSUM_PARTIAL` flag (`skb->ip_summed`) and, when the sender asked
/// for the TX status, its ack id (`IEEE80211_TX_CTL_REQ_TX_STATUS` +
/// `info->status_data` from `ieee80211_store_ack_skb`). `no_encrypt` is
/// `IEEE80211_TX_INTFL_DONT_ENCRYPT` for an nl80211 control-port frame or
/// an ordinary Ethernet frame matching an association configured with
/// `CONTROL_PORT_NO_ENCRYPT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queued {
    pub eth: Vec<u8>,
    pub csum_partial: bool,
    pub no_encrypt: bool,
    pub ack_id: Option<u32>,
}

/// Counters corresponding to the fq / CoDel state mac80211 maintains for
/// TXQs. `codel_dropped` frames are retrievable through
/// [`TxQueues::take_dropped`] so their requested TX status is completed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxqStats {
    pub enqueued: u32,
    /// `fq->overlimit`.
    pub overlimit: u32,
    /// `codel_stats.drop_count`.
    pub codel_dropped: u32,
    /// `codel_stats.ecn_mark` (`cparams.ecn = true`).
    pub codel_ecn_marked: u32,
    /// Hash buckets occupied by a different TID and therefore routed to
    /// that TID's `default_flow` (`fq->collisions`).
    pub collisions: u32,
    /// Purged (`ieee80211_purge_sta_txqs`, interface down).
    pub purged: u32,
}

#[derive(Clone, Debug)]
struct Entry {
    frame: Queued,
    enqueue_ms: u64,
    /// NARF's `skb->truesize` counterpart: owned Ethernet allocation plus
    /// the queue entry. This bounds retained memory even when a producer
    /// supplied a vector with spare capacity.
    memory_bytes: usize,
}

impl Entry {
    fn new(frame: Queued, enqueue_ms: u64) -> Self {
        let memory_bytes = frame
            .eth
            .capacity()
            .saturating_add(core::mem::size_of::<Entry>());
        Entry {
            frame,
            enqueue_ms,
            memory_bytes,
        }
    }

    fn len(&self) -> usize {
        self.frame.eth.len()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Codel {
    first_above_ms: Option<u64>,
    dropping: bool,
    drop_next_ms: u64,
    count: u32,
    lastcount: u32,
}

#[derive(Debug, Default)]
struct Flow {
    queue: VecDeque<Entry>,
    backlog_bytes: usize,
    deficit: i32,
    codel: Codel,
}

impl Flow {
    fn push(&mut self, entry: Entry) {
        self.backlog_bytes = self.backlog_bytes.saturating_add(entry.len());
        self.queue.push_back(entry);
    }

    fn pop(&mut self) -> Option<Entry> {
        let entry = self.queue.pop_front()?;
        self.backlog_bytes = self.backlog_bytes.saturating_sub(entry.len());
        if self.queue.is_empty() {
            self.codel.dropping = false;
            self.codel.first_above_ms = None;
        }
        Some(entry)
    }
}

#[derive(Debug, Default)]
struct GlobalFlow {
    /// The one TID that may occupy this shared fq bucket. Linux routes a
    /// collision with a different `fq_tin` to that tin's fallback flow.
    owner: Option<u8>,
    flow: Flow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowId {
    Global(usize),
    Default,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowChain {
    New,
    Old,
}

#[derive(Debug, Default)]
struct Tin {
    /// `fq_tin::new_flows` and `old_flows`; both contain a flow at most once.
    new_flows: VecDeque<FlowId>,
    old_flows: VecDeque<FlowId>,
    default_flow: Flow,
    /// `fq_tin::backlog_packets`; also makes the active-TXQ probe O(1).
    backlog_packets: usize,
}

/// The station's TXQs (one `fq_tin` per TID), a shared `fq` flow table, and
/// the stop reasons of the four hardware queues.
#[derive(Debug)]
pub struct TxQueues {
    tins: [Tin; NUM_TIDS],
    flows: Vec<GlobalFlow>,
    /// `local->queue_stop_reasons[queue]` (a bit per reason).
    stop: [u32; ATH11K_HW_MAX_QUEUES],
    /// The equivalent of mac80211's active-TXQ scheduler cursor for each AC.
    next_tid: [u8; NUM_ACS],
    limit: usize,
    memory_limit: usize,
    backlog_packets: usize,
    backlog_memory: usize,
    /// CoDel drops that still need requested-status handling in the runtime.
    dropped: VecDeque<Queued>,
    pub stats: TxqStats,
}

impl Default for TxQueues {
    fn default() -> Self {
        Self::with_limits(FQ_LIMIT, FQ_MEMORY_LIMIT)
    }
}

impl TxQueues {
    /// Queues with mac80211's packet and memory limits replaced (tests).
    pub fn with_limits(limit: usize, memory_limit: usize) -> Self {
        let mut flows = Vec::with_capacity(FQ_FLOW_COUNT);
        for _ in 0..FQ_FLOW_COUNT {
            flows.push(GlobalFlow::default());
        }
        TxQueues {
            tins: core::array::from_fn(|_| Tin::default()),
            flows,
            stop: [0; ATH11K_HW_MAX_QUEUES],
            next_tid: [0; NUM_ACS],
            limit,
            memory_limit,
            backlog_packets: 0,
            backlog_memory: 0,
            dropped: VecDeque::new(),
            stats: TxqStats::default(),
        }
    }

    /// Frames waiting in AC `ac`, across every one of its TID TXQs.
    pub fn len(&self, ac: u16) -> usize {
        (0..NUM_TIDS)
            .filter(|&tid| ac_for_tid(tid as u8) == (ac & 3))
            .map(|tid| self.len_tid(tid as u8))
            .sum()
    }

    /// Frames waiting in one `ieee80211_txq`.
    pub fn len_tid(&self, tid: u8) -> usize {
        let tid = usize::from(tid & 0x0f);
        self.tins[tid].backlog_packets
    }

    /// Frames waiting in every TXQ (`fq->backlog`).
    pub fn backlog(&self) -> usize {
        self.backlog_packets
    }

    pub fn is_empty(&self) -> bool {
        self.backlog_packets == 0
    }

    /// `local->queue_stop_reasons[queue]`.
    pub fn stop_reasons(&self, queue: usize) -> u32 {
        self.stop[queue % ATH11K_HW_MAX_QUEUES]
    }

    fn flow(&self, tid: u8, id: FlowId) -> &Flow {
        match id {
            FlowId::Global(i) => &self.flows[i].flow,
            FlowId::Default => &self.tins[usize::from(tid)].default_flow,
        }
    }

    fn flow_mut(&mut self, tid: u8, id: FlowId) -> &mut Flow {
        match id {
            FlowId::Global(i) => &mut self.flows[i].flow,
            FlowId::Default => &mut self.tins[usize::from(tid)].default_flow,
        }
    }

    /// Remove an empty flow from the active lists. The lists are short (at
    /// most the number of nonempty flows in one TID), so this avoids an
    /// intrusive-list allocation while retaining mac80211's no-duplicate
    /// invariant.
    fn unlink_active(&mut self, tid: u8, id: FlowId) {
        let tin = &mut self.tins[usize::from(tid)];
        for chain in [&mut tin.new_flows, &mut tin.old_flows] {
            let n = chain.len();
            for _ in 0..n {
                let current = chain.pop_front().expect("known queue length");
                if current != id {
                    chain.push_back(current);
                }
            }
        }
    }

    fn clear_owner_if_empty(&mut self, tid: u8, id: FlowId) {
        if let FlowId::Global(i) = id {
            if self.flows[i].flow.queue.is_empty() {
                debug_assert_eq!(self.flows[i].owner, Some(tid));
                self.flows[i].owner = None;
            }
        }
    }

    /// Dequeue one entry from a concrete flow and update the global fq
    /// accounting (`__fq_adjust_removal`).
    fn pop_flow(&mut self, tid: u8, id: FlowId) -> Option<Entry> {
        let entry = self.flow_mut(tid, id).pop()?;
        self.backlog_packets = self.backlog_packets.saturating_sub(1);
        self.backlog_memory = self.backlog_memory.saturating_sub(entry.memory_bytes);
        let tin = &mut self.tins[usize::from(tid)];
        tin.backlog_packets = tin.backlog_packets.saturating_sub(1);
        if self.flow(tid, id).queue.is_empty() {
            self.clear_owner_if_empty(tid, id);
            self.unlink_active(tid, id);
        }
        Some(entry)
    }

    /// Linux's `reciprocal_scale(hash, 4096)`: the high 12 bits select a
    /// bucket. A nonzero hash avoids putting unknown traffic in bucket zero.
    fn flow_bucket(hash: u32) -> usize {
        ((u64::from(hash) * FQ_FLOW_COUNT as u64) >> 32) as usize
    }

    /// `fq_tin_enqueue` into the selected TID. `now_ms` is the runtime's
    /// monotonic clock, captured when a netdev frame crosses into the TXQ.
    /// Over `fq->limit` / `memory_limit`, `fq_flow_drop` drops up to half
    /// (at most 32) of the fattest flow's head and returns those frames.
    pub fn enqueue(&mut self, tid: u8, now_ms: u64, frame: Queued) -> Vec<Queued> {
        let tid = tid & 0x0f;
        let index = Self::flow_bucket(flow_hash(&frame.eth));
        let id = match self.flows[index].owner {
            Some(owner) if owner != tid => {
                self.stats.collisions = self.stats.collisions.saturating_add(1);
                FlowId::Default
            }
            _ => FlowId::Global(index),
        };
        if let FlowId::Global(i) = id {
            self.flows[i].owner = Some(tid);
        }
        let entry = Entry::new(frame, now_ms);
        let was_empty = self.flow(tid, id).queue.is_empty();
        self.backlog_packets = self.backlog_packets.saturating_add(1);
        self.backlog_memory = self.backlog_memory.saturating_add(entry.memory_bytes);
        let tin = &mut self.tins[usize::from(tid)];
        tin.backlog_packets = tin.backlog_packets.saturating_add(1);
        self.flow_mut(tid, id).push(entry);
        if was_empty {
            self.flow_mut(tid, id).deficit = FQ_QUANTUM;
            self.tins[usize::from(tid)].new_flows.push_back(id);
        }
        self.stats.enqueued = self.stats.enqueued.saturating_add(1);

        let mut dropped = Vec::new();
        while self.backlog_packets > self.limit || self.backlog_memory > self.memory_limit {
            let Some((drop_tid, drop_id)) = self.fattest_flow() else {
                break;
            };
            // `fq_flow_drop`: `min(32, qlen / 2)`, with its do/while
            // guaranteeing one dropped packet for a one-packet flow.
            let n = (self.flow(drop_tid, drop_id).queue.len() / 2).clamp(1, 32);
            let mut made_progress = false;
            for _ in 0..n {
                let Some(entry) = self.pop_flow(drop_tid, drop_id) else {
                    break;
                };
                dropped.push(entry.frame);
                made_progress = true;
            }
            if !made_progress {
                break;
            }
            self.stats.overlimit = self.stats.overlimit.saturating_add(1);
        }
        dropped
    }

    fn fattest_flow(&self) -> Option<(u8, FlowId)> {
        let mut best: Option<(u8, FlowId, usize)> = None;
        for (i, global) in self.flows.iter().enumerate() {
            let Some(tid) = global.owner else { continue };
            let bytes = global.flow.backlog_bytes;
            if match best {
                None => true,
                Some((_, _, current)) => bytes > current,
            } {
                best = Some((tid, FlowId::Global(i), bytes));
            }
        }
        for tid in 0..NUM_TIDS as u8 {
            let bytes = self.tins[usize::from(tid)].default_flow.backlog_bytes;
            if match best {
                None => true,
                Some((_, _, current)) => bytes > current,
            } {
                best = Some((tid, FlowId::Default, bytes));
            }
        }
        match best {
            Some((tid, id, bytes)) if bytes != 0 => Some((tid, id)),
            _ => None,
        }
    }

    fn has_pending_tid(&self, tid: u8) -> bool {
        self.len_tid(tid) != 0
    }

    /// The next frame the driver gets. This combines mac80211's active-TXQ
    /// scheduler (round robin among TIDs in one AC), `fq_tin_dequeue`
    /// (new/old-flow DRR), and `codel_dequeue`. AC priority remains VO → VI
    /// → BE → BK as in ath11k's wake path.
    pub fn dequeue(&mut self, now_ms: u64) -> Option<(u16, Queued)> {
        for ac_index in 0..NUM_ACS {
            let ac = ac_index as u16;
            if self.stop[hw_queue(ac)] != 0 {
                continue;
            }
            let start = self.next_tid[ac_index];
            for step in 0..NUM_TIDS as u8 {
                let tid = start.wrapping_add(step) & 0x0f;
                if ac_for_tid(tid) != ac || !self.has_pending_tid(tid) {
                    continue;
                }
                if let Some(frame) = self.dequeue_tin(tid, now_ms) {
                    self.next_tid[ac_index] = tid.wrapping_add(1) & 0x0f;
                    return Some((ac, frame));
                }
            }
        }
        None
    }

    fn dequeue_tin(&mut self, tid: u8, now_ms: u64) -> Option<Queued> {
        loop {
            let (id, chain) = {
                let tin = &mut self.tins[usize::from(tid)];
                if let Some(id) = tin.new_flows.pop_front() {
                    (id, FlowChain::New)
                } else {
                    (tin.old_flows.pop_front()?, FlowChain::Old)
                }
            };
            if self.flow(tid, id).queue.is_empty() {
                self.clear_owner_if_empty(tid, id);
                continue;
            }
            let deficit = self.flow(tid, id).deficit;
            if deficit <= 0 {
                self.flow_mut(tid, id).deficit = deficit.saturating_add(FQ_QUANTUM);
                self.tins[usize::from(tid)].old_flows.push_back(id);
                continue;
            }

            match self.codel_action(tid, id, now_ms) {
                CodelAction::Send { ecn_marked } => {
                    let entry = self.pop_flow(tid, id)?;
                    let after = self
                        .flow(tid, id)
                        .deficit
                        .saturating_sub(entry.len() as i32);
                    self.flow_mut(tid, id).deficit = after;
                    if !self.flow(tid, id).queue.is_empty() {
                        self.requeue_front(tid, chain, id);
                    }
                    if ecn_marked {
                        self.stats.codel_ecn_marked = self.stats.codel_ecn_marked.saturating_add(1);
                    }
                    return Some(entry.frame);
                }
                CodelAction::Drop => {
                    let entry = self.pop_flow(tid, id)?;
                    self.dropped.push_back(entry.frame);
                    self.stats.codel_dropped = self.stats.codel_dropped.saturating_add(1);
                    // CoDel immediately evaluates the next packet while its
                    // control law is due, without charging DRR service.
                    if !self.flow(tid, id).queue.is_empty() {
                        self.requeue_front(tid, chain, id);
                    }
                }
            }
        }
    }

    fn requeue_front(&mut self, tid: u8, chain: FlowChain, id: FlowId) {
        match chain {
            FlowChain::New => self.tins[usize::from(tid)].new_flows.push_front(id),
            FlowChain::Old => self.tins[usize::from(tid)].old_flows.push_front(id),
        }
    }

    /// Return CoDel drops since the prior runtime pass. They are deliberately
    /// not silently discarded: a requested status must see the same dropped
    /// result as `ieee80211_free_txskb` in mac80211.
    pub fn take_dropped(&mut self) -> Vec<Queued> {
        self.dropped.drain(..).collect()
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

    /// `ieee80211_get_vif_queues` for the station vif: every AC's hardware
    /// queue (+ the CAB queue, unused by a station).
    pub const fn vif_queues() -> u32 {
        (1 << hw_queue(ac::VO))
            | (1 << hw_queue(ac::VI))
            | (1 << hw_queue(ac::BE))
            | (1 << hw_queue(ac::BK))
    }

    fn first_pending_flow(&self) -> Option<(u8, FlowId)> {
        for tid in 0..NUM_TIDS as u8 {
            if !self.tins[usize::from(tid)].default_flow.queue.is_empty() {
                return Some((tid, FlowId::Default));
            }
            if let Some((i, _)) = self
                .flows
                .iter()
                .enumerate()
                .find(|(_, flow)| flow.owner == Some(tid) && !flow.flow.queue.is_empty())
            {
                return Some((tid, FlowId::Global(i)));
            }
        }
        None
    }

    /// Take any queued frame (for a purge that reports each one). Queue-stop
    /// and CoDel do not apply to an explicit purge.
    pub fn take_any(&mut self) -> Option<Queued> {
        let (tid, id) = self.first_pending_flow()?;
        let entry = self.pop_flow(tid, id)?;
        self.stats.purged = self.stats.purged.saturating_add(1);
        Some(entry.frame)
    }

    /// `ieee80211_purge_sta_txqs`: drop every queued frame; returns how many.
    /// Frames already placed in [`Self::take_dropped`] are terminal CoDel
    /// drops, not newly purged frames.
    pub fn purge(&mut self) -> u32 {
        let mut n = 0u32;
        while self.take_any().is_some() {
            n = n.saturating_add(1);
        }
        for tin in &mut self.tins {
            tin.new_flows.clear();
            tin.old_flows.clear();
        }
        n
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodelAction {
    Send { ecn_marked: bool },
    Drop,
}

impl TxQueues {
    /// Port of the decisions in Linux's `codel_dequeue`. NARF keeps queue
    /// timestamps in milliseconds; mac80211 sets 20 ms target, 100 ms
    /// interval, and ECN enabled for TXQs.
    fn codel_action(&mut self, tid: u8, id: FlowId, now_ms: u64) -> CodelAction {
        let flow = self.flow_mut(tid, id);
        let delay = match flow.queue.front() {
            Some(head) => now_ms.saturating_sub(head.enqueue_ms),
            None => {
                flow.codel.dropping = false;
                return CodelAction::Drop;
            }
        };
        let should_drop = if delay < CODEL_TARGET_MS || flow.backlog_bytes <= CODEL_MTU {
            flow.codel.first_above_ms = None;
            false
        } else {
            match flow.codel.first_above_ms {
                None => {
                    flow.codel.first_above_ms = Some(now_ms.saturating_add(CODEL_INTERVAL_MS));
                    false
                }
                // `codel_time_after`, rather than `after_eq`: the queue
                // must remain above target for the whole interval.
                Some(at) => now_ms > at,
            }
        };

        if flow.codel.dropping {
            if !should_drop {
                flow.codel.dropping = false;
                return CodelAction::Send { ecn_marked: false };
            }
            if now_ms < flow.codel.drop_next_ms {
                return CodelAction::Send { ecn_marked: false };
            }
            flow.codel.count = flow.codel.count.saturating_add(1);
            flow.codel.drop_next_ms =
                codel_control_law(flow.codel.drop_next_ms, CODEL_INTERVAL_MS, flow.codel.count);
            let marked = flow
                .queue
                .front_mut()
                .is_some_and(|entry| mark_ecn(&mut entry.frame.eth));
            return if marked {
                CodelAction::Send { ecn_marked: true }
            } else {
                CodelAction::Drop
            };
        }

        if !should_drop {
            return CodelAction::Send { ecn_marked: false };
        }

        // `codel_dequeue` starts (or quickly restarts) the control law at
        // the first packet above target. Linux's reciprocal-square-root
        // approximation and this exact integer square root choose the same
        // monotonically increasing drop cadence.
        let delta = flow.codel.count.saturating_sub(flow.codel.lastcount);
        if delta <= 1
            || now_ms.saturating_sub(flow.codel.drop_next_ms)
                >= CODEL_INTERVAL_MS.saturating_mul(16)
        {
            flow.codel.count = 1;
        } else {
            flow.codel.count = delta;
        }
        flow.codel.lastcount = flow.codel.count;
        flow.codel.dropping = true;
        flow.codel.drop_next_ms = codel_control_law(now_ms, CODEL_INTERVAL_MS, flow.codel.count);
        let marked = flow
            .queue
            .front_mut()
            .is_some_and(|entry| mark_ecn(&mut entry.frame.eth));
        if marked {
            CodelAction::Send { ecn_marked: true }
        } else {
            CodelAction::Drop
        }
    }
}

fn codel_control_law(at_ms: u64, interval_ms: u64, count: u32) -> u64 {
    at_ms.saturating_add(interval_ms / u64::from(integer_sqrt(count.max(1))))
}

fn integer_sqrt(n: u32) -> u32 {
    let mut op = n;
    let mut res = 0u32;
    let mut one = 1u32 << 30;
    while one > op {
        one >>= 2;
    }
    while one != 0 {
        let trial = res.saturating_add(one);
        if op >= trial {
            op = op.saturating_sub(trial);
            res = res.saturating_add(one << 1);
        }
        res >>= 1;
        one >>= 2;
    }
    res.max(1)
}

/// Stable fallback for Linux's `skb_get_hash()`. It includes every Ethernet
/// byte for non-IP traffic; IP packets use network addresses, transport
/// protocol and ports so one 5-tuple shares an fq flow across payloads.
pub fn flow_hash(eth: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32; // FNV-1a offset basis
    let mut mix = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
    };
    let Some((ethertype, l3)) = ethernet_l3(eth) else {
        mix(eth);
        return nonzero_hash(hash);
    };
    match ethertype {
        tx_hdr::ETH_P_IP if eth.len() >= l3 + 20 && eth[l3] >> 4 == 4 => {
            let ihl = usize::from(eth[l3] & 0x0f) * 4;
            if ihl < 20 || eth.len() < l3 + ihl {
                mix(eth);
            } else {
                mix(&eth[l3 + 9..l3 + 10]);
                mix(&eth[l3 + 12..l3 + 20]);
                if matches!(eth[l3 + 9], 6 | 17 | 33 | 132) && eth.len() >= l3 + ihl + 4 {
                    mix(&eth[l3 + ihl..l3 + ihl + 4]);
                }
            }
        }
        tx_hdr::ETH_P_IPV6 if eth.len() >= l3 + 40 && eth[l3] >> 4 == 6 => {
            mix(&eth[l3 + 6..l3 + 7]);
            mix(&eth[l3 + 8..l3 + 40]);
            if matches!(eth[l3 + 6], 6 | 17 | 33 | 132) && eth.len() >= l3 + 44 {
                mix(&eth[l3 + 40..l3 + 44]);
            }
        }
        _ => mix(eth),
    }
    nonzero_hash(hash)
}

fn nonzero_hash(hash: u32) -> u32 {
    if hash == 0 {
        1
    } else {
        hash
    }
}

/// Returns `(EtherType, L3 offset)` and accepts up to two in-band VLAN tags.
fn ethernet_l3(eth: &[u8]) -> Option<(u16, usize)> {
    if eth.len() < ETH_HLEN {
        return None;
    }
    let mut ty = u16::from_be_bytes([eth[12], eth[13]]);
    let mut off = ETH_HLEN;
    for _ in 0..2 {
        if !matches!(ty, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if eth.len() < off + 4 {
            return None;
        }
        ty = u16::from_be_bytes([eth[off + 2], eth[off + 3]]);
        off += 4;
    }
    Some((ty, off))
}

/// Linux's `INET_ECN_set_ce(skb)` as applied by mac80211's ECN-enabled
/// CoDel. Non-ECT packets return false and follow CoDel's drop path. IPv4
/// header checksums are recomputed after changing the TOS byte; IPv6 has none.
fn mark_ecn(eth: &mut [u8]) -> bool {
    let Some((ethertype, l3)) = ethernet_l3(eth) else {
        return false;
    };
    match ethertype {
        tx_hdr::ETH_P_IP if eth.len() >= l3 + 20 && eth[l3] >> 4 == 4 => {
            let ihl = usize::from(eth[l3] & 0x0f) * 4;
            if ihl < 20 || eth.len() < l3 + ihl || !matches!(eth[l3 + 1] & 3, 1 | 2) {
                return false;
            }
            eth[l3 + 1] |= 3;
            eth[l3 + 10] = 0;
            eth[l3 + 11] = 0;
            let check = ipv4_checksum(&eth[l3..l3 + ihl]);
            eth[l3 + 10..l3 + 12].copy_from_slice(&check.to_be_bytes());
            true
        }
        tx_hdr::ETH_P_IPV6 if eth.len() >= l3 + 40 && eth[l3] >> 4 == 6 => {
            let traffic_class = ((eth[l3] & 0x0f) << 4) | (eth[l3 + 1] >> 4);
            if !matches!(traffic_class & 3, 1 | 2) {
                return false;
            }
            let ce = traffic_class | 3;
            eth[l3] = (eth[l3] & 0xf0) | (ce >> 4);
            eth[l3 + 1] = (ce << 4) | (eth[l3 + 1] & 0x0f);
            true
        }
        _ => false,
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks_exact(2) {
        sum = sum.saturating_add(u32::from(u16::from_be_bytes([word[0], word[1]])));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff).saturating_add(sum >> 16);
    }
    !(sum as u16)
}

// ── TX status (`ieee80211_tx_status_ext` inputs) ─────────────────────

/// `ieee80211_store_ack_skb`: ack ids are `idr_alloc(.., 1, 0x2000)`.
pub const ACK_ID_START: u32 = 1;
pub const ACK_ID_END: u32 = 0x2000;

/// What mac80211 learns about one transmitted MSDU.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxStatus {
    /// `IEEE80211_TX_STAT_ACK`.
    pub acked: bool,
    /// Freed without a status (`ieee80211_free_txskb`: no vif, no peer /
    /// station, refused before TCL, purged) — reported as not acked
    /// (`ieee80211_report_used_skb(.., dropped = true)`).
    pub dropped: bool,
    /// `info->status.ack_signal` (dBm) when
    /// `IEEE80211_TX_STATUS_ACK_SIGNAL_VALID`.
    pub ack_signal: Option<i32>,
}

impl TxStatus {
    pub const DROPPED: TxStatus = TxStatus {
        acked: false,
        dropped: true,
        ack_signal: None,
    };
}

/// The status of one completion, as `ath11k_dp_tx_htt_tx_complete_buf`
/// (firmware release: `ts->acked` = HTT_TX_COMP_STATUS_OK) and
/// `ath11k_dp_tx_complete_msdu` (TQM release: FRAME_ACKED) build it.
/// Neither path sees `IEEE80211_TX_CTL_NO_ACK` here (a station's frames
/// go to the BSSID, never a group address). The ack signal is
/// `ack_rssi` (+ `ATH11K_DEFAULT_NOISE_FLOOR` unless the firmware has
/// `WMI_TLV_SERVICE_HW_DB2DBM_CONVERSION_SUPPORT`). `vif` false
/// (`skb_cb->vif` cleared by `ath11k_mac_vif_unref`) or `sta` false
/// (`ath11k_peer_find_by_id` → no peer / `peer->sta`) frees the frame
/// instead: dropped.
pub fn tx_status(acked: bool, ack_rssi: u8, db2dbm: bool, vif: bool, sta: bool) -> TxStatus {
    if !vif || !sta {
        return TxStatus::DROPPED;
    }
    let ack_signal = acked.then(|| {
        let s = ack_rssi as i32;
        if db2dbm {
            s
        } else {
            s + super::wmi::ATH11K_DEFAULT_NOISE_FLOOR
        }
    });
    TxStatus {
        acked,
        dropped: false,
        ack_signal,
    }
}
