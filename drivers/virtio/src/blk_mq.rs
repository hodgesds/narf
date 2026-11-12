//! Queued virtio-blk submission (Linux `virtio_blk.c` on blk-mq): many
//! requests in flight on the one virtqueue, each with its own descriptor
//! chain and header/status slot, completions matched by chain head on
//! the used ring and the owner woken by reference.
//!
//! The shape is the NVMe driver's `mq` module with the virtqueue in place
//! of SQ/CQ pairs: a request takes a *slot* (its 16-byte header + 1-byte
//! status in the pool page, the blk-mq tag), builds its chain, adds it
//! under the virtqueue lock and kicks; whoever notices a used entry first
//! — the queue's MSI-X handler ([`isr`]) or any waiter — walks the used
//! ring under the same lock ([`BlkQueue::process_used`]), publishes each
//! completion's status in its slot, frees the chain and wakes the owner.
//! Owners reap (release the payload pin, return the slot) in process
//! context, never in the interrupt. A request whose owner went away while
//! it was in flight stays abandoned until its used entry lands (AGENTS.md
//! invariant 7). Timeouts follow blk-mq's `virtio_blk` (no `.timeout` op,
//! `BLK_EH_RESET_TIMER`): a per-queue timer reports a stalled request and
//! keeps waiting — virtio has no abort, and QEMU completes in microseconds.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{
    compiler_fence, AtomicBool, AtomicPtr, AtomicU16, AtomicU64, AtomicU8, AtomicUsize, Ordering,
};
use core::task::{Context, Poll, Waker};

use narf_io::DmaBuffer;
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::timer::{self as wheel, TimerList};

use crate::blk_pci::{
    STALLED_QUEUE_STATE, STALLED_REQUEST, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN,
    VIRTIO_BLK_T_OUT,
};
use crate::pci::{VirtioPciError, VirtioRegion};
use crate::queue::{VirtqDesc, Virtqueue, VIRTQ_DESC_F_WRITE};

/// Bytes per header/status slot in the pool page (16 B header + 1 B
/// status, padded to a cache line).
pub const SLOT_BYTES: usize = 64;
/// Descriptors per request chain: header, payload (reads/writes), status.
const CHAIN_DESCS: u16 = 3;
/// Most payload segments one chain carries (one descriptor each); bounded
/// by the queue size at construction.
pub const MAX_SEGMENTS: u16 = 32;
/// How long a wait parks before the used ring is looked at regardless of
/// the vector (lost-interrupt fallback; the only clock on a polled queue).
pub const POLL_SLICE_MS: u64 = 250;
/// A request outstanding this long is reported as stalled (and waited on
/// further: `BLK_EH_RESET_TIMER`).
pub const STALL_REPORT_MS: u64 = 30_000;
const ISR_NAME: &str = "virtio-blk";

const FREE: u8 = 0;
const INFLIGHT: u8 = 1;
const DONE: u8 = 2;
const ABANDONED: u8 = 3;
const ABANDONED_DONE: u8 = 4;

/// What a request asks of the device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlkOp {
    Read,
    Write,
    Flush,
}

struct Slot {
    state: AtomicU8,
    /// The device's status byte once completed.
    status: AtomicU8,
    /// Descriptor chain head while in flight.
    head: AtomicU16,
    deadline_ns: AtomicU64,
    reported: AtomicBool,
    waker: IrqSafeSpinLock<Option<Waker>>,
    hold: IrqSafeSpinLock<Option<Arc<DmaBuffer>>>,
    pages: IrqSafeSpinLock<Option<Arc<narf_io::sg::PageList>>>,
}

impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(FREE),
            status: AtomicU8::new(0xFF),
            head: AtomicU16::new(0),
            deadline_ns: AtomicU64::new(u64::MAX),
            reported: AtomicBool::new(false),
            waker: IrqSafeSpinLock::new(None),
            hold: IrqSafeSpinLock::new(None),
            pages: IrqSafeSpinLock::new(None),
        }
    }
    fn wake(&self) {
        if let Some(w) = self.waker.lock().as_ref() {
            w.wake_by_ref();
        }
    }
}

struct TagState {
    free: VecDeque<u16>,
    waiters: VecDeque<Waker>,
}

#[repr(C)]
struct QueueTimer {
    timer: TimerList,
    queue: AtomicPtr<BlkQueue>,
}

/// Outcome of a posted request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The used entry landed; `status` is the device's status byte.
    Completed { status: u8 },
}

/// The queued request table over virtqueue 0.
pub struct BlkQueue {
    queue: IrqSafeSpinLock<Option<Virtqueue>>,
    notify: VirtioRegion,
    notify_off: u64,
    /// Header/status slots, `slots.len() * SLOT_BYTES` bytes.
    pool: DmaBuffer,
    slots: Box<[Slot]>,
    tags: IrqSafeSpinLock<TagState>,
    /// Chain head → slot, for requests in flight.
    inflight: IrqSafeSpinLock<BTreeMap<u16, u16>>,
    max_segs: u16,
    vector: AtomicU8,
    has_vector: AtomicBool,
    in_flight: AtomicUsize,
    isr_cookie: AtomicU64,
    timer: Box<QueueTimer>,
}

impl core::fmt::Debug for BlkQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlkQueue")
            .field("slots", &self.slots.len())
            .field("in_flight", &self.in_flight())
            .finish_non_exhaustive()
    }
}

// SAFETY: the raw back pointer in the boxed timer is only read by the timer
// callback while the queue is alive (the queue deletes the timer
// synchronously before dropping); everything else is `Sync`.
unsafe impl Sync for BlkQueue {}
// SAFETY: as above.
unsafe impl Send for BlkQueue {}

/// A posted request's identity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReqId {
    pub slot: u16,
}

impl BlkQueue {
    /// Wrap virtqueue `queue` (size `qsize`) with `slots` request slots.
    /// `pool` must hold `slots * SLOT_BYTES` bytes.
    pub fn new(
        queue: Virtqueue,
        qsize: u16,
        notify: VirtioRegion,
        notify_off: u64,
        pool: DmaBuffer,
    ) -> Arc<Self> {
        let n = ((qsize / CHAIN_DESCS).max(1) as usize).min(pool.len() / SLOT_BYTES);
        let mut free = VecDeque::with_capacity(n);
        let mut slots = Vec::with_capacity(n);
        for i in 0..n as u16 {
            free.push_back(i);
            slots.push(Slot::new());
        }
        let q = Arc::new(Self {
            queue: IrqSafeSpinLock::new(Some(queue)),
            notify,
            notify_off,
            pool,
            slots: slots.into_boxed_slice(),
            tags: IrqSafeSpinLock::new(TagState {
                free,
                waiters: VecDeque::with_capacity(n),
            }),
            inflight: IrqSafeSpinLock::new(BTreeMap::new()),
            max_segs: MAX_SEGMENTS.min(qsize.saturating_sub(2)).max(1),
            vector: AtomicU8::new(0),
            has_vector: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
            isr_cookie: AtomicU64::new(0),
            timer: Box::new(QueueTimer {
                timer: TimerList::new(timeout_timer, 0),
                queue: AtomicPtr::new(core::ptr::null_mut()),
            }),
        });
        q.timer
            .queue
            .store(Arc::as_ptr(&q) as *mut BlkQueue, Ordering::Release);
        q
    }

    /// Requests the queue can hold at once.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn free_slots(&self) -> usize {
        self.tags.lock().free.len()
    }

    pub fn vector(&self) -> Option<u8> {
        self.has_vector
            .load(Ordering::Acquire)
            .then(|| self.vector.load(Ordering::Relaxed))
    }

    /// Run `f` on the virtqueue (diagnostics).
    pub fn with_virtqueue<R>(&self, f: impl FnOnce(&mut Virtqueue) -> Option<R>) -> Option<R> {
        self.queue.lock().as_mut().and_then(f)
    }

    /// Install the completion handler on `vector` (MSI-X entry 0 bound).
    pub fn install_isr(self: &Arc<Self>, vector: u8) {
        if self.isr_cookie.load(Ordering::Acquire) != 0 {
            return;
        }
        self.vector.store(vector, Ordering::Relaxed);
        self.has_vector.store(true, Ordering::Release);
        let cookie = Arc::into_raw(Arc::clone(self)) as u64;
        self.isr_cookie.store(cookie, Ordering::Release);
        narf_interrupts::install_handler_named(vector, ISR_NAME, cookie, isr);
    }

    // ── slots ─────────────────────────────────────────────────────

    pub fn try_alloc_slot(&self, waker: Option<&Waker>) -> Option<u16> {
        if let Some(t) = self.tags.lock().free.pop_front() {
            return Some(t);
        }
        if self.sweep() > 0 {
            if let Some(t) = self.tags.lock().free.pop_front() {
                return Some(t);
            }
        }
        if let Some(w) = waker {
            let mut g = self.tags.lock();
            if let Some(t) = g.free.pop_front() {
                return Some(t);
            }
            if !g.waiters.iter().any(|q| q.will_wake(w)) {
                g.waiters.push_back(w.clone());
            }
        }
        None
    }

    fn free_slot(&self, slot: u16) {
        let waiter = {
            let mut g = self.tags.lock();
            g.free.push_back(slot);
            g.waiters.pop_front()
        };
        if let Some(w) = waiter {
            w.wake();
        }
    }

    pub fn release_slot_unused(&self, slot: u16) {
        self.free_slot(slot);
    }

    fn header_phys(&self, slot: u16) -> u64 {
        self.pool.dma_addr().raw() + slot as u64 * SLOT_BYTES as u64
    }

    fn status_ptr(&self, slot: u16) -> *mut u8 {
        // SAFETY: slot < slots.len(), and the pool holds SLOT_BYTES per slot.
        unsafe {
            self.pool
                .cpu_mut_ptr::<u8>()
                .add(slot as usize * SLOT_BYTES + 16)
        }
    }

    /// Most payload segments a chain on this queue may carry.
    pub fn max_segments(&self) -> u16 {
        self.max_segs
    }

    /// Post a request under `slot`: `payload` (`len` bytes, device-written
    /// for a read) is pinned until the terminal completion. Builds the
    /// header, the 2- or 3-descriptor chain, adds it and kicks.
    pub fn post(
        &self,
        slot: u16,
        op: BlkOp,
        sector: u64,
        payload: Option<Arc<DmaBuffer>>,
        len: usize,
    ) -> Result<ReqId, VirtioPciError> {
        let segs: Vec<(u64, u32)> = match (&payload, op) {
            (Some(p), BlkOp::Read | BlkOp::Write) => {
                if len == 0 || len > p.len() {
                    return Err(VirtioPciError::QueueTooSmall);
                }
                alloc::vec![(p.dma_addr().raw(), len as u32)]
            }
            _ => Vec::new(),
        };
        self.post_segments(slot, op, sector, &segs, payload, None)
    }

    /// [`Self::post`] over `segs` (device addresses + lengths, one
    /// descriptor each, at most [`Self::max_segments`]); `hold` / `pages`
    /// pin whatever backs them until the terminal completion.
    pub fn post_segments(
        &self,
        slot: u16,
        op: BlkOp,
        sector: u64,
        segs: &[(u64, u32)],
        hold: Option<Arc<DmaBuffer>>,
        pages: Option<Arc<narf_io::sg::PageList>>,
    ) -> Result<ReqId, VirtioPciError> {
        if segs.len() > self.max_segs as usize || (op != BlkOp::Flush && segs.is_empty()) {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let s = &self.slots[slot as usize];
        debug_assert_eq!(s.state.load(Ordering::Relaxed), FREE);
        let type_tag = match op {
            BlkOp::Read => VIRTIO_BLK_T_IN,
            BlkOp::Write => VIRTIO_BLK_T_OUT,
            BlkOp::Flush => VIRTIO_BLK_T_FLUSH,
        };
        let header_phys = self.header_phys(slot);
        // SAFETY: the pool is a live coherent buffer; the slot's 64 bytes are
        // ours while the slot is allocated.
        unsafe {
            let h = self
                .pool
                .cpu_mut_ptr::<u8>()
                .add(slot as usize * SLOT_BYTES);
            core::ptr::write_volatile(h as *mut u32, type_tag);
            core::ptr::write_volatile(h.add(4) as *mut u32, 0);
            core::ptr::write_volatile(h.add(8) as *mut u64, sector);
            core::ptr::write_volatile(self.status_ptr(slot), 0xFF);
        }
        let mut descs: Vec<VirtqDesc> = Vec::with_capacity(segs.len() + 2);
        descs.push(VirtqDesc {
            addr: header_phys,
            len: 16,
            flags: 0,
            next: 0,
        });
        if op != BlkOp::Flush {
            for &(addr, len) in segs {
                descs.push(VirtqDesc {
                    addr,
                    len,
                    flags: if op == BlkOp::Read {
                        VIRTQ_DESC_F_WRITE
                    } else {
                        0
                    },
                    next: 0,
                });
            }
        }
        descs.push(VirtqDesc {
            addr: header_phys + 16,
            len: 1,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        });
        let n = descs.len();
        *s.hold.lock() = hold;
        *s.pages.lock() = pages;
        s.status.store(0xFF, Ordering::Relaxed);
        s.reported.store(false, Ordering::Relaxed);
        let deadline = narf_time::monotonic_ns().saturating_add(STALL_REPORT_MS * 1_000_000);
        s.deadline_ns.store(deadline, Ordering::Relaxed);
        compiler_fence(Ordering::Release);
        s.state.store(INFLIGHT, Ordering::Release);
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let head = {
            let mut g = self.queue.lock();
            let Some(q) = g.as_mut() else {
                drop(g);
                self.reap(slot);
                return Err(VirtioPciError::NoQueues);
            };
            let Some(head) = q.add_buffer(&descs[..n]) else {
                drop(g);
                self.reap(slot);
                return Err(VirtioPciError::QueueTooSmall);
            };
            s.head.store(head, Ordering::Relaxed);
            self.inflight.lock().insert(head, slot);
            head
        };
        let _ = head;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(self.notify_off, 0);
        }
        self.arm_timer(deadline);
        Ok(ReqId { slot })
    }

    fn arm_timer(&self, deadline_ns: u64) {
        let expires = wheel::ns_to_jiffies(deadline_ns) + 1;
        let t = &self.timer.timer;
        if t.is_pending() && t.expires() <= expires {
            return;
        }
        // SAFETY: the timer lives in a `Box` inside this queue, deleted
        // synchronously before the queue is freed.
        unsafe {
            wheel::mod_timer(t, expires);
        }
    }

    /// The stall timer fired: report each overdue request once (the
    /// watchdog's snapshot), wake its owner, and keep waiting.
    fn on_timer(&self) {
        let now = narf_time::monotonic_ns();
        let mut next = u64::MAX;
        for (i, s) in self.slots.iter().enumerate() {
            let st = s.state.load(Ordering::Acquire);
            if st != INFLIGHT && st != ABANDONED {
                continue;
            }
            let dl = s.deadline_ns.load(Ordering::Relaxed);
            if dl > now {
                next = next.min(dl);
                continue;
            }
            if !s.reported.swap(true, Ordering::AcqRel) {
                self.report_stall(i as u16);
                s.wake();
            }
        }
        if next != u64::MAX {
            self.arm_timer(next);
        }
    }

    /// Publish the stalled request for the fatal stall watchdog
    /// (`blk_pci::stalled_queue_snapshot`); this crate has no console.
    fn report_stall(&self, slot: u16) {
        let s = &self.slots[slot as usize];
        let (avail, last_used, device_used, free) = self
            .queue
            .lock()
            .as_ref()
            .map(Virtqueue::diagnostic_snapshot)
            .unwrap_or((0, 0, 0, 0));
        // SAFETY: the slot's status byte is live DMA memory owned by this
        // request.
        let status = unsafe { core::ptr::read_volatile(self.status_ptr(slot)) };
        let head = s.head.load(Ordering::Relaxed);
        STALLED_REQUEST.store(((status as u64) << 8) | head as u64, Ordering::Relaxed);
        STALLED_QUEUE_STATE.store(
            ((avail as u64) << 48)
                | ((last_used as u64) << 32)
                | ((device_used as u64) << 16)
                | free as u64,
            Ordering::Release,
        );
    }

    // ── completion ────────────────────────────────────────────────

    /// Consume every used entry: match each chain head to its slot, publish
    /// the status, free the chain, wake the owner. From the ISR nothing is
    /// freed; from process context completed abandoned requests are
    /// reclaimed too. Returns how many were consumed.
    pub fn process_used(&self, from_irq: bool) -> usize {
        let mut reclaim: [u16; 16] = [0; 16];
        let mut n_reclaim = 0usize;
        let mut n = 0usize;
        {
            let mut g = self.queue.lock();
            let Some(q) = g.as_mut() else {
                return 0;
            };
            while let Some((id, _len)) = q.poll_used() {
                n += 1;
                let head = id as u16;
                q.free_chain(head);
                let Some(slot) = self.inflight.lock().remove(&head) else {
                    continue;
                };
                let s = &self.slots[slot as usize];
                // SAFETY: live status byte of this request.
                let status = unsafe { core::ptr::read_volatile(self.status_ptr(slot)) };
                s.status.store(status, Ordering::Relaxed);
                if s.state
                    .compare_exchange(INFLIGHT, DONE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.in_flight.fetch_sub(1, Ordering::AcqRel);
                    s.wake();
                } else if s
                    .state
                    .compare_exchange(
                        ABANDONED,
                        ABANDONED_DONE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    self.in_flight.fetch_sub(1, Ordering::AcqRel);
                    if !from_irq && n_reclaim < reclaim.len() {
                        reclaim[n_reclaim] = slot;
                        n_reclaim += 1;
                    }
                }
            }
        }
        for &slot in &reclaim[..n_reclaim] {
            self.reclaim(slot);
        }
        n
    }

    /// Whether the device has published a used entry not yet consumed.
    pub fn used_pending(&self) -> bool {
        let g = self.queue.lock();
        g.as_ref().is_some_and(Virtqueue::has_used)
    }

    /// Owner-side: the outcome if terminal, reaping the slot.
    pub fn poll_req(&self, slot: u16) -> Option<Outcome> {
        let s = &self.slots[slot as usize];
        if s.state.load(Ordering::Acquire) == DONE {
            let status = s.status.load(Ordering::Relaxed);
            self.reap(slot);
            return Some(Outcome::Completed { status });
        }
        None
    }

    pub fn register_waker(&self, slot: u16, waker: &Waker) {
        let mut g = self.slots[slot as usize].waker.lock();
        match g.as_ref() {
            Some(w) if w.will_wake(waker) => {}
            _ => {
                let old = g.replace(waker.clone());
                drop(g);
                drop(old);
            }
        }
    }

    pub fn abandon(&self, slot: u16) {
        let s = &self.slots[slot as usize];
        let old = s.waker.lock().take();
        drop(old);
        loop {
            match s.state.load(Ordering::Acquire) {
                INFLIGHT => {
                    if s.state
                        .compare_exchange(INFLIGHT, ABANDONED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return;
                    }
                }
                DONE => return self.reap(slot),
                _ => return,
            }
        }
    }

    pub fn sweep(&self) -> usize {
        let mut n = 0;
        for slot in 0..self.slots.len() as u16 {
            if self.slots[slot as usize].state.load(Ordering::Acquire) == ABANDONED_DONE {
                self.reclaim(slot);
                n += 1;
            }
        }
        n
    }

    fn reclaim(&self, slot: u16) {
        if self.slots[slot as usize]
            .state
            .compare_exchange(ABANDONED_DONE, DONE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.reap(slot);
        }
    }

    fn reap(&self, slot: u16) {
        let s = &self.slots[slot as usize];
        let hold = s.hold.lock().take();
        let pages = s.pages.lock().take();
        let old = s.waker.lock().take();
        drop(old);
        drop(hold);
        drop(pages);
        s.deadline_ns.store(u64::MAX, Ordering::Relaxed);
        s.state.store(FREE, Ordering::Release);
        self.free_slot(slot);
    }
}

impl Drop for BlkQueue {
    fn drop(&mut self) {
        wheel::del_timer_sync(&self.timer.timer);
    }
}

fn isr(cookie: u64) -> narf_interrupts::IrqStatus {
    // SAFETY: `cookie` is the leaked `Arc<BlkQueue>` of `install_isr`; the
    // queue lives for the controller's lifetime.
    let q = unsafe { &*(cookie as *const BlkQueue) };
    q.process_used(true);
    narf_interrupts::IrqStatus::Handled
}

fn timeout_timer(t: &TimerList) {
    // SAFETY: only `QueueTimer` uses this callback; `timer` is its first
    // field (repr(C)); the queue deletes the timer before it is freed.
    let qt = unsafe { &*(t as *const TimerList as *const QueueTimer) };
    let q = qt.queue.load(Ordering::Acquire);
    if !q.is_null() {
        // SAFETY: as above.
        unsafe { &*q }.on_timer();
    }
}

// ── owner side ────────────────────────────────────────────────────

/// One posted request, owned until its outcome; dropping it first
/// abandons the request.
pub struct Req {
    queue: Arc<BlkQueue>,
    id: ReqId,
    wait: Option<ReqWait>,
    done: bool,
}

enum ReqWait {
    Irq(narf_time::Timeout<narf_interrupts::WaitForIrq>),
    Slice(narf_time::SleepUntil),
}

impl core::fmt::Debug for Req {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Req")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Req {
    pub fn new(queue: Arc<BlkQueue>, id: ReqId) -> Self {
        Self {
            queue,
            id,
            wait: None,
            done: false,
        }
    }

    fn arm(&mut self) {
        let slice = narf_time::Deadline::after_ms(POLL_SLICE_MS);
        self.wait = Some(match self.queue.vector() {
            Some(v) => ReqWait::Irq(narf_interrupts::wait_for_irq_until(v, slice)),
            None => ReqWait::Slice(narf_time::sleep_until(slice)),
        });
    }

    pub fn poll_outcome(&mut self, cx: &mut Context<'_>) -> Poll<Outcome> {
        let slot = self.id.slot;
        for round in 0..3 {
            if let Some(o) = self.queue.poll_req(slot) {
                self.done = true;
                return Poll::Ready(o);
            }
            if round == 0 {
                self.queue.register_waker(slot, cx.waker());
                continue;
            }
            if self.queue.used_pending() {
                self.queue.process_used(false);
                continue;
            }
            if self.wait.is_none() {
                self.arm();
            }
            let fired = match self.wait.as_mut() {
                Some(ReqWait::Irq(w)) => Pin::new(w).poll(cx).is_ready(),
                Some(ReqWait::Slice(s)) => Pin::new(s).poll(cx).is_ready(),
                None => false,
            };
            if fired {
                self.wait = None;
                if round < 2 {
                    continue;
                }
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        Poll::Pending
    }

    /// Synchronous wait (the sync wrappers): spins responsively, no lock
    /// held, until the request completes — never abandoning an in-flight
    /// chain.
    pub fn wait_sync(mut self) -> Outcome {
        let slot = self.id.slot;
        loop {
            if let Some(o) = self.queue.poll_req(slot) {
                self.done = true;
                return o;
            }
            let q = Arc::clone(&self.queue);
            let v = q.vector();
            let baseline = v.map(narf_interrupts::fire_count);
            let _ = narf_scheduler::responsive_spin_until(
                || {
                    q.used_pending()
                        || q.slots[slot as usize].state.load(Ordering::Acquire) != INFLIGHT
                        || v.is_some_and(|v| Some(narf_interrupts::fire_count(v)) != baseline)
                },
                narf_time::Deadline::after_ms(POLL_SLICE_MS),
            );
            if self.queue.used_pending() {
                self.queue.process_used(false);
            }
        }
    }
}

impl Drop for Req {
    fn drop(&mut self) {
        if !self.done {
            self.queue.abandon(self.id.slot);
        }
    }
}

/// Post `op` and wait for it synchronously, taking a slot as one comes
/// free. `Ok(status)` is the device's status byte.
pub fn submit_sync(
    q: &Arc<BlkQueue>,
    op: BlkOp,
    sector: u64,
    payload: Option<Arc<DmaBuffer>>,
    len: usize,
) -> Result<u8, VirtioPciError> {
    let mut slot = q.try_alloc_slot(None);
    if slot.is_none() {
        narf_scheduler::responsive_spin_until(
            || {
                if q.used_pending() {
                    q.process_used(false);
                }
                slot = q.try_alloc_slot(None);
                slot.is_some()
            },
            narf_time::Deadline::after_ms(STALL_REPORT_MS),
        );
    }
    let slot = slot.ok_or(VirtioPciError::QueueTooSmall)?;
    let id = q.post(slot, op, sector, payload, len)?;
    let Outcome::Completed { status } = Req::new(Arc::clone(q), id).wait_sync();
    Ok(status)
}

/// Whether the device reported success.
pub fn ok(status: u8) -> Result<(), VirtioPciError> {
    if status == VIRTIO_BLK_S_OK {
        Ok(())
    } else {
        Err(VirtioPciError::DeviceRejectedFeatures)
    }
}

/// Post `op` and await it: a slot as one comes free (woken by the
/// release), then the completion. `Ok(status)` is the device's status
/// byte.
pub fn submit_async(
    q: Arc<BlkQueue>,
    op: BlkOp,
    sector: u64,
    payload: Option<Arc<DmaBuffer>>,
    len: usize,
) -> Submit {
    Submit {
        q,
        op,
        sector,
        payload,
        len,
        segs: None,
        req: None,
    }
}

/// Future of [`submit_async`].
pub struct Submit {
    q: Arc<BlkQueue>,
    op: BlkOp,
    sector: u64,
    payload: Option<Arc<DmaBuffer>>,
    len: usize,
    /// Scatter-gather form: the segments and the page list that backs them.
    segs: Option<(Vec<(u64, u32)>, Arc<narf_io::sg::PageList>)>,
    req: Option<Req>,
}

/// [`submit_async`] over the segments of `pages`.
pub fn submit_async_segments(
    q: Arc<BlkQueue>,
    op: BlkOp,
    sector: u64,
    segs: Vec<(u64, u32)>,
    pages: Arc<narf_io::sg::PageList>,
) -> Submit {
    Submit {
        q,
        op,
        sector,
        payload: None,
        len: 0,
        segs: Some((segs, pages)),
        req: None,
    }
}

impl core::fmt::Debug for Submit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Submit")
            .field("op", &self.op)
            .finish_non_exhaustive()
    }
}

impl Future for Submit {
    type Output = Result<u8, VirtioPciError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.req.is_none() {
            let Some(slot) = this.q.try_alloc_slot(Some(cx.waker())) else {
                return Poll::Pending;
            };
            let posted = match this.segs.take() {
                Some((segs, pages)) => {
                    this.q
                        .post_segments(slot, this.op, this.sector, &segs, None, Some(pages))
                }
                None => this
                    .q
                    .post(slot, this.op, this.sector, this.payload.take(), this.len),
            };
            let id = match posted {
                Ok(id) => id,
                Err(e) => return Poll::Ready(Err(e)),
            };
            this.req = Some(Req::new(Arc::clone(&this.q), id));
        }
        let req = this.req.as_mut().expect("request posted");
        match req.poll_outcome(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Outcome::Completed { status }) => Poll::Ready(Ok(status)),
        }
    }
}

// SAFETY: `Submit` owns `Arc`s, plain data and the IRQ / timer waits, all of
// which may move between executor CPUs.
unsafe impl Send for Submit {}

// ── the block-layer queue ─────────────────────────────────────────

/// The virtio-blk device as a [`narf_block::BlockQueue`]: what
/// `VirtioBlkBlockSync::queue()` exposes and `SyncBlock` submits through.
pub struct VirtioBlkQueue {
    q: Arc<BlkQueue>,
    flush_supported: bool,
}

impl core::fmt::Debug for VirtioBlkQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioBlkQueue").finish_non_exhaustive()
    }
}

impl VirtioBlkQueue {
    pub fn new(q: Arc<BlkQueue>, flush_supported: bool) -> Self {
        Self { q, flush_supported }
    }
}

fn map_status(status: u8) -> Result<(), narf_block::BlockError> {
    if status == VIRTIO_BLK_S_OK {
        Ok(())
    } else {
        Err(narf_block::BlockError::IOError)
    }
}

impl narf_block::BlockQueue for VirtioBlkQueue {
    fn limits(&self) -> narf_block::QueueLimits {
        narf_block::QueueLimits {
            logical_block_size: 512,
            max_transfer_bytes: crate::blk_pci::MAX_IO_SECTORS as u32 * 512,
            max_segments: self.q.max_segments() as u32,
            max_segment_bytes: crate::blk_pci::MAX_IO_SECTORS as u32 * 512,
            dma_alignment: 1,
            queue_depth: self.q.slot_count() as u32,
            nr_queues: 1,
        }
    }

    fn submit(&self, req: narf_block::BlockRequest) -> narf_block::BoxedCompletion {
        use narf_block::{BlockError, BlockOp};
        let user_tag = req.user_tag;
        let op = match req.op {
            BlockOp::Read => BlkOp::Read,
            BlockOp::Write { .. } => BlkOp::Write,
            // Not negotiated (no VIRTIO_BLK_F_DISCARD / WRITE_ZEROES): the
            // device cannot do them, and `SyncBlock` never advertises them.
            BlockOp::Trim | BlockOp::WriteZeroes => {
                return narf_block::queue::ready_completion(user_tag, Err(BlockError::IOError));
            }
        };
        let fua = matches!(req.op, BlockOp::Write { fua: true });
        let Some(buffer) = narf_io::resolve_cap(&req.buffer) else {
            return narf_block::queue::ready_completion(
                user_tag,
                Err(BlockError::PermissionDenied),
            );
        };
        let len = req.blocks as usize * 512;
        if len == 0 {
            return narf_block::queue::ready_completion(user_tag, Ok(()));
        }
        if len > buffer.len()
            || req.blocks > crate::blk_pci::MAX_IO_SECTORS as u32
            || req.lba.checked_add(req.blocks as u64).is_none()
        {
            return narf_block::queue::ready_completion(user_tag, Err(BlockError::InvalidRange));
        }
        let q = Arc::clone(&self.q);
        let flush_after = fua && self.flush_supported;
        let lba = req.lba;
        Box::pin(async move {
            let mut result = submit_async(Arc::clone(&q), op, lba, Some(buffer), len)
                .await
                .map_err(|_| BlockError::IOError)
                .and_then(map_status);
            if result.is_ok() && flush_after {
                // FUA is not native: write + flush, as the block layer
                // emulates it.
                result = submit_async(q, BlkOp::Flush, 0, None, 0)
                    .await
                    .map_err(|_| BlockError::IOError)
                    .and_then(map_status);
            }
            narf_block::BlockCompletion {
                tag: lba,
                user_tag,
                result,
            }
        })
    }

    fn flush(&self) -> narf_block::BoxedResult {
        if !self.flush_supported {
            return Box::pin(core::future::ready(Ok(())));
        }
        let q = Arc::clone(&self.q);
        Box::pin(async move {
            submit_async(q, BlkOp::Flush, 0, None, 0)
                .await
                .map_err(|_| narf_block::BlockError::IOError)
                .and_then(map_status)
        })
    }

    /// virtio-blk has no abort: a request in flight completes on its own.
    fn cancel(&self, _tag: u64) -> narf_block::BoxedCancel {
        Box::pin(core::future::ready(narf_block::CancelResult::Completed))
    }

    fn in_flight(&self) -> usize {
        self.q.in_flight()
    }

    /// One conforming scatter-gather request: a descriptor per segment.
    fn submit_sg(&self, req: narf_block::SgRequest) -> narf_block::BoxedCompletion {
        use narf_block::{BlockError, BlockOp};
        let user_tag = req.user_tag;
        let op = match req.op {
            BlockOp::Read => BlkOp::Read,
            BlockOp::Write { .. } => BlkOp::Write,
            BlockOp::Trim | BlockOp::WriteZeroes => {
                return narf_block::queue::ready_completion(user_tag, Err(BlockError::IOError));
            }
        };
        let Some(list) = req.resolve() else {
            return narf_block::queue::ready_completion(
                user_tag,
                Err(BlockError::PermissionDenied),
            );
        };
        let Some(segs) = req.segments(&list, 512) else {
            return narf_block::queue::ready_completion(user_tag, Err(BlockError::InvalidRange));
        };
        let segs: Vec<(u64, u32)> = segs.iter().map(|s| (s.dma, s.len)).collect();
        let fua = matches!(req.op, BlockOp::Write { fua: true });
        let q = Arc::clone(&self.q);
        let flush_after = fua && self.flush_supported;
        let lba = req.lba;
        Box::pin(async move {
            let mut result = submit_async_segments(Arc::clone(&q), op, lba, segs, list)
                .await
                .map_err(|_| BlockError::IOError)
                .and_then(map_status);
            if result.is_ok() && flush_after {
                result = submit_async(q, BlkOp::Flush, 0, None, 0)
                    .await
                    .map_err(|_| BlockError::IOError)
                    .and_then(map_status);
            }
            narf_block::BlockCompletion {
                tag: lba,
                user_tag,
                result,
            }
        })
    }
}
