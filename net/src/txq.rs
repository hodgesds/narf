//! Transmit-queue backpressure: the contract between a multi-queue NIC
//! driver and the stack, and the per-connection limit built on it.
//!
//! Without it a full transmit ring refuses a frame the stack has already
//! accounted as sent, and the segment is silently lost. Linux never loses
//! one that way: the driver stops the queue before it can overflow
//! (`netif_txq_maybe_stop`), wakes it from its completion handler
//! (`netif_txq_completed_wake`), and TCP Small Queues bounds what one socket
//! may leave in the device (`tcp_small_queue_check`, released by `tcp_wfree`).
//!
//! Everything here is per transmit queue or per connection. The transmit and
//! completion fast paths touch only atomics on those objects; the one lock,
//! [`TxQueue`]'s waiter list, is taken when a queue is stopped, when a
//! throttled connection's bytes complete, and by the wake pass. Nothing is
//! allocated per frame.
//!
//! # Driver contract
//!
//! A driver implements [`TxBackpressure`], creates one [`TxQueue`] per
//! hardware queue from the [`TxQueueGeometry`] of the physical ring, and:
//!
//! * after posting a frame calls [`TxQueue::sent`] with the frame's bytes
//!   and the descriptors still free;
//! * when a frame that fits an empty ring finds no room calls
//!   [`TxQueue::refused`] and returns [`TxRefusal::Busy`];
//! * once per reclaim batch calls [`TxQueue::completed`];
//! * from its completion context, holding no queue lock, calls
//!   [`TxQueue::run_wakeups`];
//! * after a ring reset calls [`TxQueue::reset`].
//!
//! A frame offered through [`TxBackpressure::try_xmit`] is refused while the
//! queue is stopped. Frames sent through the interface's ordinary transmit
//! hook (pure ACKs, SYN/FIN/RST, retransmissions, every other protocol) are
//! accepted while descriptors remain. That is not a guaranteed reserve: a
//! queue stops after a post that leaves fewer than `max_frame_descs` free,
//! so what is left for them is anywhere from nothing to one descriptor less
//! than a worst-case frame. The ordinary hook also ignores the stopped
//! flag, so traffic through it at or above the link's rate can hold the
//! ring below the wake threshold and keep waiting TCP data out; Linux
//! arbitrates the two in the qdisc, which this stack does not have.
//!
//! [`stats`] counts the conditions that should not last: a queue stopped
//! for more than a second, a connection waiting that long, a sender refused
//! many times in a row, and a transmit pool with no buffer.
//!
//! Not implemented: the adaptive per-queue byte limit of
//! `lib/dynamic_queue_limits.c`. `sent`/`completed` already carry the byte
//! and packet counts `netdev_tx_sent_queue`/`netdev_tx_completed_queue`
//! take, so it can be added here without touching a driver.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// What the device reports for one transmit ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxQueueGeometry {
    /// Descriptors in the ring (`ethtool -g` TX).
    pub ring_len: u32,
    /// Most descriptors a single frame can consume, context descriptors
    /// included (Linux `DESC_NEEDED`).
    pub max_frame_descs: u32,
}

/// Why a frame offered with backpressure was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRefusal {
    /// The queue is stopped or has no room (`NETDEV_TX_BUSY`). The frame was
    /// not transmitted and will not be; offer it again after a wake.
    Busy,
    /// The device cannot send this frame at all (down, malformed, larger
    /// than the ring). Retrying will not help.
    Dropped,
}

/// The transmit side of a multi-queue driver, as the stack sees it.
pub trait TxBackpressure: core::fmt::Debug + Send + Sync {
    /// Number of transmit queues.
    fn tx_queue_count(&self) -> u16;
    /// Shared state of queue `q`.
    fn tx_queue(&self, q: u16) -> Option<Arc<TxQueue>>;
    /// The queue this frame's flow maps to (`ndo_select_queue`). Must be a
    /// pure function of the flow so a connection stays on one queue.
    fn tx_select_queue(&self, frame: &[u8]) -> u16;
    /// Negotiated link speed in Mbit/s, 0 when unknown.
    fn tx_link_speed_mbps(&self) -> u32;
    /// Offer an owned frame to queue `q`. Refused with [`TxRefusal::Busy`]
    /// while the queue is stopped.
    fn try_xmit(&self, q: u16, frame: crate::Frame, meta: crate::TxMeta) -> Result<(), TxRefusal>;
    /// As [`Self::try_xmit`] for a frame the driver must copy. `charge` is
    /// the sending connection's byte charge: the driver attaches it to the
    /// frame it builds ([`crate::Frame::set_tx_charge`]) so it is returned
    /// when that frame completes, exactly as for an owned frame.
    fn try_xmit_copy(
        &self,
        q: u16,
        frame: &[u8],
        meta: crate::TxMeta,
        charge: Option<TxCharge>,
    ) -> Result<(), TxRefusal>;
}

#[derive(Debug, Default)]
struct WakeLists {
    /// Connections refused by a stopped queue.
    waiters: Vec<u32>,
    /// Throttled connections whose bytes have completed.
    tsq: Vec<u32>,
}

/// Per-queue transmit state shared by a driver and the stack: Linux
/// `struct netdev_queue`.
#[derive(Debug)]
#[repr(align(64))]
pub struct TxQueue {
    geometry: TxQueueGeometry,
    stop_thrs: u32,
    wake_thrs: u32,
    stopped: AtomicBool,
    wake_pending: AtomicBool,
    restarts: AtomicU64,
    busy: AtomicU64,
    sent_bytes: AtomicU64,
    completed_bytes: AtomicU64,
    /// When the queue last stopped (cycles); meaningful while stopped.
    stopped_at: AtomicU64,
    long_stops: AtomicU64,
    long_stop_seen: AtomicU64,
    lists: IrqSafeSpinLock<WakeLists>,
}

impl TxQueue {
    /// Thresholds follow the ring: stop when fewer than one worst-case frame
    /// of descriptors is free (igc `igc_maybe_stop_tx(ring, DESC_NEEDED)`),
    /// wake at twice that (`TX_WAKE_THRESHOLD`), both bounded by what an
    /// empty ring offers so a small ring still wakes.
    pub fn new(geometry: TxQueueGeometry) -> Arc<Self> {
        let usable = geometry.ring_len.saturating_sub(1).max(1);
        let stop_thrs = geometry.max_frame_descs.clamp(1, usable);
        let wake_thrs = geometry
            .max_frame_descs
            .saturating_mul(2)
            .clamp(stop_thrs, usable);
        Arc::new(Self {
            geometry,
            stop_thrs,
            wake_thrs,
            stopped: AtomicBool::new(false),
            wake_pending: AtomicBool::new(false),
            restarts: AtomicU64::new(0),
            busy: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
            completed_bytes: AtomicU64::new(0),
            stopped_at: AtomicU64::new(0),
            long_stops: AtomicU64::new(0),
            long_stop_seen: AtomicU64::new(0),
            lists: IrqSafeSpinLock::new(WakeLists::default()),
        })
    }

    pub fn geometry(&self) -> TxQueueGeometry {
        self.geometry
    }
    /// `(stop, wake)` thresholds in free descriptors.
    pub fn thresholds(&self) -> (u32, u32) {
        (self.stop_thrs, self.wake_thrs)
    }
    /// A frame needing more descriptors than an empty ring has can never be
    /// sent; refusing it as busy would wait forever.
    pub fn fits_empty_ring(&self, descs: u32) -> bool {
        descs < self.geometry.ring_len
    }
    /// `netif_tx_queue_stopped`.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
    /// Times the queue was woken (`tx_queue_%u_restart`).
    pub fn restarts(&self) -> u64 {
        self.restarts.load(Ordering::Relaxed)
    }
    /// Frames refused as busy.
    pub fn busy(&self) -> u64 {
        self.busy.load(Ordering::Relaxed)
    }
    /// Bytes posted and not yet completed.
    pub fn inflight_bytes(&self) -> u64 {
        self.sent_bytes
            .load(Ordering::Relaxed)
            .saturating_sub(self.completed_bytes.load(Ordering::Relaxed))
    }

    /// Driver: a frame of `bytes` was posted. `free` re-reads the free
    /// descriptor count. `netdev_tx_sent_queue` + `netif_txq_maybe_stop`,
    /// including its re-check for a completion that ran in between.
    pub fn sent(&self, bytes: u32, free: impl Fn() -> u32) {
        self.sent_bytes
            .fetch_add(u64::from(bytes), Ordering::Relaxed);
        if free() < self.stop_thrs {
            self.mark_stopped();
            if free() >= self.wake_thrs {
                self.stopped.store(false, Ordering::SeqCst);
            }
        }
    }

    /// Driver: a frame that fits an empty ring found no room. The queue is
    /// stopped; the completion that makes room wakes it.
    pub fn refused(&self) {
        self.busy.fetch_add(1, Ordering::Relaxed);
        self.mark_stopped();
    }

    fn mark_stopped(&self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
            self.stopped_at.store(
                narf_scheduler::narf_time::now_cycles().max(1),
                Ordering::Relaxed,
            );
        }
    }

    /// Driver's periodic task: `Some(cycles stopped)` when the queue has
    /// been stopped for at least `threshold` cycles, at most once per
    /// `threshold`. A healthy queue is stopped for a completion interval;
    /// one stopped for a second has frames that do not complete.
    pub fn stopped_too_long(&self, now: u64, threshold: u64) -> Option<u64> {
        if !self.is_stopped() {
            return None;
        }
        let stopped_for = now.saturating_sub(self.stopped_at.load(Ordering::Relaxed));
        if stopped_for < threshold
            || now.saturating_sub(self.long_stop_seen.load(Ordering::Relaxed)) < threshold
        {
            return None;
        }
        self.long_stop_seen.store(now, Ordering::Relaxed);
        self.long_stops.fetch_add(1, Ordering::Relaxed);
        stats::LONG_STOPS.fetch_add(1, Ordering::Relaxed);
        Some(stopped_for)
    }
    /// Times [`Self::stopped_too_long`] reported.
    pub fn long_stops(&self) -> u64 {
        self.long_stops.load(Ordering::Relaxed)
    }
    /// Connections listed as waiting for room.
    pub fn waiters(&self) -> usize {
        self.lists.lock().waiters.len()
    }

    /// Driver: one reclaim batch freed `pkts` frames of `bytes`, leaving
    /// `free` descriptors. `netif_txq_completed_wake`: at most one wake per
    /// batch, and only once the wake threshold is reached.
    pub fn completed(&self, pkts: u32, bytes: u64, free: u32) {
        self.completed_bytes.fetch_add(bytes, Ordering::Relaxed);
        if pkts != 0 && free >= self.wake_thrs && self.stopped.load(Ordering::SeqCst) {
            self.stopped.store(false, Ordering::SeqCst);
            self.restarts.fetch_add(1, Ordering::Relaxed);
            self.wake_pending.store(true, Ordering::SeqCst);
        }
    }

    /// Driver: the ring was reset and everything in it discarded
    /// (`netdev_tx_reset_queue`). Every waiter is released; the frames it
    /// held are gone and their owners recover them as losses.
    pub fn reset(&self) {
        self.sent_bytes.store(0, Ordering::Relaxed);
        self.completed_bytes.store(0, Ordering::Relaxed);
        self.stopped.store(false, Ordering::SeqCst);
        self.wake_pending.store(true, Ordering::SeqCst);
    }

    /// Driver: the wake pass. Call from the completion context after a
    /// reclaim batch, and from a periodic task, with no queue lock held: it
    /// resumes connections, which transmit.
    pub fn run_wakeups(&self) -> usize {
        if !self.wake_pending.swap(false, Ordering::SeqCst) {
            return 0;
        }
        let (tsq, waiters) = {
            let mut lists = self.lists.lock();
            let tsq = core::mem::take(&mut lists.tsq);
            // Waiters stay put if the queue stopped again; the next wake
            // sets `wake_pending` and takes them.
            let waiters = if self.is_stopped() {
                Vec::new()
            } else {
                core::mem::take(&mut lists.waiters)
            };
            (tsq, waiters)
        };
        let woken = tsq.len() + waiters.len();
        for id in tsq.into_iter().chain(waiters) {
            crate::tcp::core::tx_resume(id);
        }
        woken
    }

    /// Stack: `account`'s connection was refused. Returns whether the queue
    /// is still stopped. The connection is listed before the flag is read
    /// and the waker clears the flag before it takes the list, so a wake
    /// between the refusal and this call is seen here as "not stopped" and
    /// the caller simply tries again.
    pub(crate) fn wait(&self, account: &TxAccount) -> bool {
        if !account.waiting.swap(true, Ordering::SeqCst) {
            self.lists.lock().waiters.push(account.id);
        }
        self.is_stopped()
    }

    fn tsq_ready(&self, id: u32) {
        self.lists.lock().tsq.push(id);
        self.wake_pending.store(true, Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn waiter_count(&self) -> usize {
        self.lists.lock().waiters.len()
    }
}

/// One connection's bytes in a device queue: Linux `sk->sk_wmem_alloc` as
/// TCP Small Queues uses it.
#[derive(Debug)]
pub struct TxAccount {
    id: u32,
    queue: Arc<TxQueue>,
    queued: AtomicU32,
    throttled: AtomicBool,
    waiting: AtomicBool,
}

impl TxAccount {
    pub fn new(id: u32, queue: Arc<TxQueue>) -> Arc<Self> {
        Arc::new(Self {
            id,
            queue,
            queued: AtomicU32::new(0),
            throttled: AtomicBool::new(false),
            waiting: AtomicBool::new(false),
        })
    }
    pub fn queue(&self) -> &Arc<TxQueue> {
        &self.queue
    }
    /// Bytes handed to the device and not yet completed.
    pub fn queued(&self) -> u32 {
        self.queued.load(Ordering::SeqCst)
    }
    /// Charge a frame to the connection. The charge travels inside the
    /// frame and is returned when the frame is destroyed, wherever that
    /// happens: completion, a refused post or a ring reset.
    pub fn charge(self: &Arc<Self>, bytes: u32) -> TxCharge {
        self.queued.fetch_add(bytes, Ordering::SeqCst);
        TxCharge {
            account: self.clone(),
            bytes,
        }
    }
    /// `tcp_small_queue_check`: true when the connection must wait for its
    /// own completions. The flag is set before the second read so that a
    /// completion racing with it either lowers the count seen here or finds
    /// the flag and schedules the wake.
    pub fn throttle(&self, limit: u32) -> bool {
        if self.queued() > limit {
            self.throttled.store(true, Ordering::SeqCst);
            if self.queued() > limit {
                return true;
            }
        }
        false
    }
    /// The wake pass is about to resume the connection.
    pub(crate) fn resumed(&self) {
        self.waiting.store(false, Ordering::SeqCst);
    }
}

/// A frame's share of its connection's device-queue bytes (`tcp_wfree`).
#[derive(Debug)]
pub struct TxCharge {
    account: Arc<TxAccount>,
    bytes: u32,
}

impl Drop for TxCharge {
    fn drop(&mut self) {
        let account = &self.account;
        account.queued.fetch_sub(self.bytes, Ordering::SeqCst);
        // Runs under the driver's queue lock: atomics, and the waiter-list
        // lock only for a connection that is actually throttled.
        if account.throttled.swap(false, Ordering::SeqCst) {
            account.queue.tsq_ready(account.id);
        }
    }
}

/// `tcp_small_queue_check`'s limit: the larger of two segments and about a
/// millisecond at the pacing rate (`sk_pacing_rate >> sk_pacing_shift`, shift
/// 10), capped by `tcp_limit_output_bytes`. The pacing rate is
/// `tcp_update_pacing_rate`'s: 200% of `cwnd / srtt` in slow start, 120%
/// after, and unlimited before the first RTT sample.
pub fn tsq_limit(segment: u32, cwnd: u32, ssthresh: u32, srtt_us: u64, cap: u32) -> u32 {
    let ratio: u64 = if cwnd < ssthresh / 2 { 200 } else { 120 };
    let rate = if srtt_us == 0 {
        u64::MAX
    } else {
        (u64::from(cwnd) * ratio / 100).saturating_mul(1_000_000) / srtt_us
    };
    (u64::from(segment) * 2).max(rate >> 10).min(u64::from(cap)) as u32
}

/// Counts of transmit conditions that should not last, for `ethtool -S`.
/// Written only when the condition occurs, never per healthy frame.
pub mod stats {
    use core::sync::atomic::AtomicU64;

    /// A connection was refused 64 more times in a row without sending.
    pub static REOFFER_STORMS: AtomicU64 = AtomicU64::new(0);
    /// A connection had waited another second for its queue.
    pub static LONG_WAITS: AtomicU64 = AtomicU64::new(0);
    /// A queue had been stopped for another second.
    pub static LONG_STOPS: AtomicU64 = AtomicU64::new(0);
    /// A frame was copied because its queue's zero-copy pool was empty.
    pub static POOL_EMPTY: AtomicU64 = AtomicU64::new(0);
}

static LAST_REPORT: AtomicU64 = AtomicU64::new(0);

/// Whether a diagnostic line may be logged now: one per second for all of
/// the conditions in [`stats`] together. The counters carry the totals.
pub fn report_allowed() -> bool {
    let now = narf_scheduler::narf_time::now_cycles().max(1);
    let last = LAST_REPORT.load(Ordering::Relaxed);
    if last != 0
        && now.saturating_sub(last) < narf_scheduler::narf_time::ns_to_cycles(1_000_000_000)
    {
        return false;
    }
    LAST_REPORT
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

    fn txq_reports_a_long_stop_once_per_interval() -> TestResult {
        const T: u64 = 1_000_000;
        let q = TxQueue::new(TxQueueGeometry {
            ring_len: 256,
            max_frame_descs: 20,
        });
        let before = narf_scheduler::narf_time::now_cycles();
        kt_assert_eq!(
            q.stopped_too_long(before + 10 * T, T),
            None,
            "running queue"
        );
        q.refused();
        let after = narf_scheduler::narf_time::now_cycles();
        kt_assert_eq!(q.stopped_too_long(after, T + (after - before)), None);
        kt_assert!(q
            .stopped_too_long(after + 2 * T, T)
            .is_some_and(|c| c >= 2 * T));
        kt_assert_eq!(
            q.stopped_too_long(after + 2 * T + 1, T),
            None,
            "reported twice"
        );
        kt_assert!(q.stopped_too_long(after + 4 * T, T).is_some());
        kt_assert_eq!(q.long_stops(), 2);
        q.completed(1, 0, 255);
        kt_assert_eq!(q.stopped_too_long(after + 9 * T, T), None, "woken queue");
        // A later stop is timed from when it happened.
        q.refused();
        kt_assert_eq!(q.waiters(), 0);
        TestResult::Pass
    }
    kernel_test_in!("net/txq", txq_reports_a_long_stop_once_per_interval);

    fn geometry(ring_len: u32, max_frame_descs: u32) -> TxQueueGeometry {
        TxQueueGeometry {
            ring_len,
            max_frame_descs,
        }
    }

    /// Thresholds come from the ring the device reports, for an I225-sized
    /// ring, a 100G-class ring and a ring too small for the usual margins.
    fn txq_thresholds_follow_ring_geometry() -> TestResult {
        kt_assert_eq!(TxQueue::new(geometry(256, 20)).thresholds(), (20, 40));
        kt_assert_eq!(TxQueue::new(geometry(8192, 45)).thresholds(), (45, 90));
        // Wake is bounded by an empty ring, or the queue could never wake.
        kt_assert_eq!(TxQueue::new(geometry(32, 20)).thresholds(), (20, 31));
        kt_assert_eq!(TxQueue::new(geometry(16, 20)).thresholds(), (15, 15));
        let q = TxQueue::new(geometry(16, 20));
        kt_assert!(q.fits_empty_ring(15) && !q.fits_empty_ring(16));
        TestResult::Pass
    }
    kernel_test_in!("net/txq", txq_thresholds_follow_ring_geometry);

    fn txq_stops_below_one_frame_and_wakes_once_per_batch() -> TestResult {
        let q = TxQueue::new(geometry(256, 20));
        q.sent(1500, || 20);
        kt_assert!(!q.is_stopped(), "stopped with a full frame of room");
        q.sent(1500, || 19);
        kt_assert!(q.is_stopped(), "not stopped below one frame of room");
        kt_assert_eq!(q.inflight_bytes(), 3000);
        // Below the wake threshold, or with nothing completed: stay stopped.
        q.completed(4, 1500, 39);
        q.completed(0, 0, 255);
        kt_assert!(q.is_stopped() && q.restarts() == 0);
        q.completed(8, 1500, 40);
        kt_assert!(!q.is_stopped() && q.restarts() == 1);
        // A second batch on a running queue is not another wake.
        q.completed(8, 0, 200);
        kt_assert_eq!(q.restarts(), 1);
        kt_assert_eq!(q.inflight_bytes(), 0);
        // A completion that lands between the stop and its re-check.
        let reads = core::sync::atomic::AtomicU32::new(0);
        q.sent(1500, || {
            if reads.fetch_add(1, Ordering::Relaxed) == 0 {
                5
            } else {
                200
            }
        });
        kt_assert!(!q.is_stopped(), "stop was not undone by the re-check");
        TestResult::Pass
    }
    kernel_test_in!(
        "net/txq",
        txq_stops_below_one_frame_and_wakes_once_per_batch
    );

    /// The waiter protocol: a connection listed while the queue is stopped is
    /// taken by the next wake; one that registers after the wake sees "not
    /// stopped" and is told to retry; a queue that stopped again keeps its
    /// waiters for the following wake.
    fn txq_waiters_survive_every_wake_interleaving() -> TestResult {
        let q = TxQueue::new(geometry(256, 20));
        // Ids that name no connection: the wake pass skips them.
        let a = TxAccount::new(0xfff0_0001, q.clone());
        let b = TxAccount::new(0xfff0_0002, q.clone());
        q.refused();
        kt_assert!(q.wait(&a), "a stopped queue told its waiter to retry");
        kt_assert!(q.wait(&a), "second refusal");
        kt_assert_eq!(q.waiter_count(), 1, "one connection listed twice");
        kt_assert_eq!(q.busy(), 1);
        // Wake between b's refusal and its registration.
        q.completed(1, 0, 255);
        kt_assert_eq!(q.run_wakeups(), 1);
        kt_assert!(!q.wait(&b), "a missed wake left the waiter asleep");
        // Woken, then stopped again before the pass runs: waiters are kept
        // for the next wake, not lost and not resumed into a full ring.
        q.refused();
        q.completed(1, 0, 255);
        q.refused();
        kt_assert_eq!(q.run_wakeups(), 0);
        kt_assert_eq!(q.waiter_count(), 1);
        q.completed(1, 0, 255);
        kt_assert_eq!(q.run_wakeups(), 1);
        kt_assert_eq!(q.waiter_count(), 0);
        // A reset releases whoever is waiting.
        q.refused();
        a.resumed();
        kt_assert!(q.wait(&a));
        q.reset();
        kt_assert!(!q.is_stopped());
        kt_assert_eq!(q.run_wakeups(), 1);
        TestResult::Pass
    }
    kernel_test_in!("net/txq", txq_waiters_survive_every_wake_interleaving);

    fn tsq_charge_returns_on_drop_and_wakes_only_the_throttled() -> TestResult {
        let q = TxQueue::new(geometry(256, 20));
        let account = TxAccount::new(0xfff0_0003, q.clone());
        let first = account.charge(60_000);
        let second = account.charge(60_000);
        kt_assert_eq!(account.queued(), 120_000);
        kt_assert!(!account.throttle(120_000), "throttled at the limit");
        // Not throttled: a completion costs no list work and no wake.
        drop(first);
        kt_assert_eq!(account.queued(), 60_000);
        kt_assert_eq!(q.run_wakeups(), 0);
        let third = account.charge(60_000);
        kt_assert!(account.throttle(100_000), "not throttled over the limit");
        drop(second);
        kt_assert_eq!(q.run_wakeups(), 1, "completion did not schedule the wake");
        // One wake per throttle episode.
        drop(third);
        kt_assert_eq!(q.run_wakeups(), 0);
        kt_assert_eq!(account.queued(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "net/txq",
        tsq_charge_returns_on_drop_and_wakes_only_the_throttled
    );

    /// Linux's rule scales with the connection's rate, not with a link speed
    /// baked in: 1 ms at 1, 25 and 100 Gbit/s, two segments as the floor,
    /// `tcp_limit_output_bytes` as the ceiling.
    fn tsq_limit_follows_linux_rule() -> TestResult {
        const CAP: u32 = 4 << 20;
        // No RTT sample: unlimited pacing rate, so the cap.
        kt_assert_eq!(tsq_limit(65_536, 14_600, u32::MAX, 0, CAP), CAP);
        // Slow start, cwnd 1 MiB, srtt 10 ms: 200% of 104.8 MB/s >> 10.
        let rate = 1_048_576u64 * 2 * 1_000_000 / 10_000;
        kt_assert_eq!(
            tsq_limit(1448, 1 << 20, u32::MAX, 10_000, CAP),
            (rate >> 10) as u32
        );
        // Congestion avoidance uses 120%.
        let rate = (1_048_576u64 * 120 / 100) * 1_000_000 / 10_000;
        kt_assert_eq!(
            tsq_limit(1448, 1 << 20, 1 << 20, 10_000, CAP),
            (rate >> 10) as u32
        );
        // A slow flow is still allowed two segments.
        kt_assert_eq!(tsq_limit(65_536, 14_600, 14_600, 200_000, CAP), 131_072);
        // A 100 Gbit/s flow (cwnd 125 MB at 10 ms) hits the cap, not a
        // figure sized for a slower link.
        kt_assert_eq!(tsq_limit(65_536, 125_000_000, 1, 10_000, CAP), CAP);
        // About 1 ms of a 25 Gbit/s flow: 3.125 MB/ms * 1.2 * 1000/1024.
        let limit = tsq_limit(65_536, 31_250_000, 1, 10_000, 64 << 20);
        kt_assert!((3_500_000..3_800_000).contains(&limit));
        TestResult::Pass
    }
    kernel_test_in!("net/txq", tsq_limit_follows_linux_rule);
}
