//! `epoll_create1(2)`, `epoll_ctl(2)`, `epoll_wait(2)` — interest-set
//! based I/O event notification.
//!
//! Linux refs:
//!   `fs/eventpoll.c`:ep_insert / ep_modify / ep_remove / ep_poll
//!   (GPL-2.0-or-later, kernel.org).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use crate::errno::{to_ret, *};
use crate::fd;
use crate::handlers::current_task_id;
use crate::syscall::{SyscallReturn, TrapContext};

// ── epoll event flag constants ───────────────────────────────────────
// Matches Linux `<sys/epoll.h>` (GPL-2.0-or-later, kernel.org).

/// Data available to read.
pub const EPOLLIN: u32 = 0x00000001;
/// Urgent (OOB) data available.
pub const EPOLLPRI: u32 = 0x00000002;
/// Data can be written without blocking.
pub const EPOLLOUT: u32 = 0x00000004;
/// Stream peer half-closed (read half).
pub const EPOLLRDHUP: u32 = 0x00002000;
/// Error condition.
pub const EPOLLERR: u32 = 0x00000008;
/// Hang-up / peer closed.
pub const EPOLLHUP: u32 = 0x00000010;
/// Level-triggered is default; set this for edge-triggered.
pub const EPOLLET: u32 = 1 << 31;
/// Disarm the interest record after the first delivery.
pub const EPOLLONESHOT: u32 = 1 << 30;
/// Exclusive wakeup for multiple tasks on same FD.
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;

// ── epoll_ctl ops ────────────────────────────────────────────────────

pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

// ── Wire layout: struct epoll_event ─────────────────────────────────
// Packed on Linux x86_64: u32 events + u64 data = 12 bytes.
pub const EPOLL_EVENT_SIZE: usize = 12;

/// Read a user-supplied `epoll_event` struct (12 bytes).
fn read_epoll_event(ptr: u64) -> Result<(u32, u64), ()> {
    let mut buf = [0u8; 12];
    // SAFETY: runs in the calling task's syscall context (its address space,
    // never IRQ); `copy_from_user` range-validates `ptr` for `buf.len()` (12)
    // bytes and brackets the read with the SMAP window itself.
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_from_user(&mut buf, ptr) }.is_err() {
        return Err(());
    }
    let events = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
    let data = u64::from_ne_bytes(buf[4..12].try_into().unwrap());
    Ok((events, data))
}

/// Write an `epoll_event` struct to user memory.
fn write_epoll_event(ptr: u64, events: u32, data: u64) -> Result<(), ()> {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&events.to_ne_bytes());
    buf[4..12].copy_from_slice(&data.to_ne_bytes());
    // SAFETY: runs in the calling task's syscall context (its address space,
    // never IRQ); `copy_to_user` range-validates `ptr` for `buf.len()` (12)
    // bytes and brackets the write with the SMAP window itself.
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_to_user(ptr, &buf) }.is_err() {
        return Err(());
    }
    Ok(())
}

// ── EpollItem — per-fd interest record ──────────────────────────────

#[derive(Clone)]
struct EpollItem {
    registration: Arc<EpollRegistration>,
}

#[derive(Clone)]
struct EpollSnapshot {
    registration: Arc<EpollRegistration>,
    /// Weak reference to the open file description captured by
    /// `EPOLL_CTL_ADD`. A strong reference would keep a socket alive after
    /// its final descriptor closes and suppress EOF/HUP; a bare fd number
    /// aliases an unrelated file when the slot is reused.
    file: Weak<dyn FileOps>,
    /// Readiness providers that use the file position consult the offset
    /// captured with this registration. Socket/event sources ignore it.
    offset: u64,
    /// Provider-subscription version sampled with the delivery state.
    sub_id: u64,
    /// User-requested interest bits.
    events: u32,
    /// Opaque user data echoed back in every event notification.
    data: u64,
    /// Last readiness mask observed — for EPOLLET rising-mask edge detection.
    last_mask: u32,
}

impl core::fmt::Debug for EpollSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpollSnapshot")
            .field("fd", &self.registration.fd)
            .field("file_live", &self.file.strong_count().ne(&0))
            .field("offset", &self.offset)
            .field("sub_id", &self.sub_id)
            .field("events", &self.events)
            .field("data", &self.data)
            .field("last_mask", &self.last_mask)
            .finish()
    }
}

/// Hot per-registration state, corresponding to Linux's `struct epitem`
/// readiness linkage. `active` invalidates delayed callbacks after DEL/fd reuse;
/// `ready_state` serializes ready-list ownership with an unlocked provider poll.
/// State transitions happen under the instance ready lock, while the atomic lets
/// passive readiness queries observe queued membership without searching.
#[derive(Debug)]
struct EpollRegistration {
    fd: i32,
    active: AtomicBool,
    ready_state: AtomicU8,
    /// Intrusive ready-list links. The owning instance's `ready` lock is the
    /// sole writer; atomics make the stable `Arc` node `Sync` without a second
    /// per-node lock. A linked node carries one raw `Arc` strong reference.
    ready_prev: core::sync::atomic::AtomicPtr<EpollRegistration>,
    ready_next: core::sync::atomic::AtomicPtr<EpollRegistration>,
    file: Weak<dyn FileOps>,
    offset: u64,
    state: IrqSafeSpinLock<EpollItemState>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct EpollItemState {
    /// Every provider arm gets a fresh identity. A stale ADD/MOD completion can
    /// therefore disarm only its own waiter, never a newer re-arm that won the
    /// race on this registration.
    sub_id: u64,
    events: u32,
    data: u64,
    last_mask: u32,
    cell_backed: bool,
}

impl EpollRegistration {
    fn new(
        fd: i32,
        sub_id: u64,
        file: &Arc<dyn FileOps>,
        offset: u64,
        events: u32,
        data: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            fd,
            active: AtomicBool::new(true),
            ready_state: AtomicU8::new(READY_IDLE),
            ready_prev: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            ready_next: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            file: Arc::downgrade(file),
            offset,
            state: IrqSafeSpinLock::new(EpollItemState {
                sub_id,
                events,
                data,
                last_mask: 0,
                cell_backed: false,
            }),
        })
    }

    fn snapshot(self: &Arc<Self>) -> EpollSnapshot {
        let state = *self.state.lock();
        EpollSnapshot {
            registration: Arc::clone(self),
            file: self.file.clone(),
            offset: self.offset,
            sub_id: state.sub_id,
            events: state.events,
            data: state.data,
            last_mask: state.last_mask,
        }
    }
}

impl core::fmt::Debug for EpollItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.registration.snapshot().fmt(f)
    }
}

/// Monotonic key source for persistent per-fd epoll waiters (Linux
/// `eppoll_entry`). The top bit is forced set so an epoll subscription key can
/// never collide with a task-id-keyed `poll(2)`/blocking waiter sharing the same
/// Readiness cell's waiter map (task ids are small counters, never near 2^63).
static EPOLL_SUB_SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn next_sub_id() -> u64 {
    (EPOLL_SUB_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed) & (u64::MAX >> 1))
        | (1u64 << 63)
}

// ── EpollInstance — the core object ──────────────────────────────────

#[derive(Debug)]
pub struct EpollInstance {
    /// Cold `epoll_ctl` metadata plus per-subscription delivery state.
    inner: IrqSafeSpinLock<EpollInner>,
    /// Ordered ready index plus cold fallback-poll membership. This mirrors
    /// Linux's single `rdllist`: callbacks only link/refresh registrations,
    /// while delivery snapshots a bounded window and polls without the lock.
    ready: IrqSafeSpinLock<EpollReady>,
    /// Shared-epoll sleepers, kept off the ready-list lock.
    waiters: IrqSafeSpinLock<EpollWaiters>,
    /// Lockless equivalent of Linux's `waitqueue_active(&ep->wq)`: avoid taking
    /// the shared waiter lock for every callback in a large ready burst once
    /// all sleepers have already been woken. A false-negative race with waiter
    /// publication is covered by epoll_wait's register-then-recheck.
    has_parked_waiters: AtomicBool,
    /// This epoll fd's OWN durable readiness cell. An epoll fd is itself
    /// pollable (Linux `ep_eventpoll_poll`), so a PARENT epoll / `poll(2)` that
    /// watches this instance as a nested fd arms its per-fd waker here via
    /// [`FileOps::arm_readiness_persistent`]. [`EpollInstance::push_ready`]
    /// fires it, chaining a TARGETED wake UP to the parent when a child becomes
    /// ready (Linux `ep_poll_safewake`). Without it a nested-epoll parent is not
    /// cell-backed, gets no targeted wake, and only re-discovers a ready child on
    /// a full re-scan driven by the ~10 ms lost-wake backstop — which on a
    /// NO_HZ-idle CPU stops re-arming, stretching recovery to ~900 ms. That is
    /// the CachyOS dbus-broker accept strand: the broker waits on epfd A that
    /// nests epfd B that nests the bus listener, so a new connection reached it
    /// only via the global `notify(0)` herd (or the dead backstop). `poll_readiness`
    /// stays the authoritative level query; this cell carries only the wake.
    self_readiness: narf_lib::readiness::Readiness,
    /// Set once a parent epoll / `poll(2)` arms a persistent waiter on
    /// [`Self::self_readiness`] (i.e. this instance is nested somewhere). The
    /// common case — an epoll waited on DIRECTLY — never nests, so `push_ready`
    /// (hot: fires on every inbound event of every watched fd) skips the
    /// self-cell set+notify behind this relaxed load instead of taking the cell
    /// lock twice per event. Latched, never cleared: a `CTL_DEL` of the nesting
    /// parent is rare, and a stale `true` only reinstates the (correct) cell
    /// fire — it never drops a wake.
    has_nested_parent: core::sync::atomic::AtomicBool,
}

#[derive(Debug)]
struct EpollInner {
    /// fd → interest record.
    interest: BTreeMap<i32, EpollItem>,
}

/// Ready-list and fallback-poll state, isolated from the cold interest tree.
#[derive(Debug)]
struct EpollReady {
    /// Intrusive FIFO of ready registrations. Every linked node owns one raw
    /// `Arc` strong reference, transferred back to a normal `Arc` on removal.
    /// This is Linux's `rdllist` shape: hot enqueue/dequeue/delete are O(1),
    /// independent of the number of watched or ready fds.
    head: core::sync::atomic::AtomicPtr<EpollRegistration>,
    tail: core::sync::atomic::AtomicPtr<EpollRegistration>,
    len: usize,
    /// Cursor for sources that cannot publish into the ready list and must be
    /// polled. This cold set remains ordered; it is not on the callback path.
    scan_after: Option<i32>,
    /// Alternate the first candidate when both queues have work so an always-
    /// polled timer/nested fd cannot starve behind a permanently-ready LT fd.
    prefer_always_poll: bool,
    /// Interest records without a durable readiness cell. The registration
    /// identity, not merely its reusable numeric fd, makes stale DEL/MOD cleanup
    /// unable to remove a newer fd incarnation.
    always_poll: BTreeMap<i32, (Arc<EpollRegistration>, u64)>,
    /// Cell-backed nested epolls can still forward timer deadlines from
    /// non-cell-backed children. Keep only those forwarders in this cold index
    /// so deadline discovery is O(number of timed/fallback sources), not O(all
    /// interests).
    deadline_poll: BTreeMap<i32, (Arc<EpollRegistration>, u64)>,
}

type ReadyCandidate = (Arc<EpollRegistration>, bool);

// A callback may run while a collector polls the provider without `ready`
// held. It must not relink the same intrusive node while the collector owns it,
// and a second collector must not reserve that occurrence. PENDING records the
// callback in-place; the first collector publishes it when it finishes.
const READY_IDLE: u8 = 0;
const READY_QUEUED: u8 = 1;
const READY_POLLING: u8 = 2;
const READY_PENDING: u8 = 3;

impl EpollReady {
    fn remove_always_poll(&mut self, registration: &Arc<EpollRegistration>) {
        let fd = registration.fd;
        let matches = self
            .always_poll
            .get(&fd)
            .is_some_and(|(current, _)| Arc::ptr_eq(current, registration));
        if matches {
            self.always_poll.remove(&fd);
        }
    }

    fn remove_always_poll_version(&mut self, registration: &Arc<EpollRegistration>, sub_id: u64) {
        let fd = registration.fd;
        let matches = self
            .always_poll
            .get(&fd)
            .is_some_and(|(current, id)| *id == sub_id && Arc::ptr_eq(current, registration));
        if matches {
            self.always_poll.remove(&fd);
        }
    }

    fn remove_deadline_poll(&mut self, registration: &Arc<EpollRegistration>) {
        let fd = registration.fd;
        let matches = self
            .deadline_poll
            .get(&fd)
            .is_some_and(|(current, _)| Arc::ptr_eq(current, registration));
        if matches {
            self.deadline_poll.remove(&fd);
        }
    }

    fn remove_deadline_poll_version(&mut self, registration: &Arc<EpollRegistration>, sub_id: u64) {
        let fd = registration.fd;
        let matches = self
            .deadline_poll
            .get(&fd)
            .is_some_and(|(current, id)| *id == sub_id && Arc::ptr_eq(current, registration));
        if matches {
            self.deadline_poll.remove(&fd);
        }
    }

    fn link_node(&mut self, registration: &Arc<EpollRegistration>) {
        debug_assert_eq!(registration.ready_state.load(Ordering::Relaxed), READY_IDLE);
        let node = Arc::into_raw(Arc::clone(registration)) as *mut EpollRegistration;
        let tail = self.tail.load(Ordering::Relaxed);
        registration.ready_prev.store(tail, Ordering::Relaxed);
        registration
            .ready_next
            .store(core::ptr::null_mut(), Ordering::Relaxed);
        if tail.is_null() {
            self.head.store(node, Ordering::Relaxed);
        } else {
            // SAFETY: a non-null tail is linked and kept alive by the ready
            // queue's raw Arc reference. This lock is the only link writer.
            unsafe { (&*tail).ready_next.store(node, Ordering::Relaxed) };
        }
        self.tail.store(node, Ordering::Relaxed);
        self.len += 1;
        // Publish membership only after both neighboring links are complete.
        registration
            .ready_state
            .store(READY_QUEUED, Ordering::Release);
    }

    fn list(&mut self, registration: &Arc<EpollRegistration>) -> bool {
        if !registration.active.load(Ordering::Acquire) {
            return false;
        }
        match registration.ready_state.load(Ordering::Relaxed) {
            READY_IDLE => self.link_node(registration),
            READY_POLLING => registration
                .ready_state
                .store(READY_PENDING, Ordering::Release),
            READY_QUEUED | READY_PENDING => {}
            _ => unreachable!("invalid epoll ready state"),
        }
        true
    }

    /// Detach `node` and transfer the queue's raw strong reference to a normal
    /// `Arc`. The caller holds the ready lock and `node` is linked here.
    unsafe fn unlink_node(
        &mut self,
        node: *mut EpollRegistration,
        next_state: u8,
    ) -> Arc<EpollRegistration> {
        // SAFETY: the queue's raw Arc reference keeps `node` live.
        let registration = unsafe { &*node };
        let prev = registration.ready_prev.load(Ordering::Relaxed);
        let next = registration.ready_next.load(Ordering::Relaxed);
        if prev.is_null() {
            self.head.store(next, Ordering::Relaxed);
        } else {
            // SAFETY: every non-null neighbor is linked in this same queue.
            unsafe { (&*prev).ready_next.store(next, Ordering::Relaxed) };
        }
        if next.is_null() {
            self.tail.store(prev, Ordering::Relaxed);
        } else {
            // SAFETY: every non-null neighbor is linked in this same queue.
            unsafe { (&*next).ready_prev.store(prev, Ordering::Relaxed) };
        }
        registration
            .ready_prev
            .store(core::ptr::null_mut(), Ordering::Relaxed);
        registration
            .ready_next
            .store(core::ptr::null_mut(), Ordering::Relaxed);
        registration
            .ready_state
            .store(next_state, Ordering::Release);
        self.len -= 1;
        // SAFETY: `list` created exactly one raw strong reference for this
        // membership; unlinking consumes that membership exactly once.
        unsafe { Arc::from_raw(node) }
    }

    fn pop_front(&mut self) -> Option<Arc<EpollRegistration>> {
        let node = self.head.load(Ordering::Relaxed);
        if node.is_null() {
            None
        } else {
            // SAFETY: `head` is linked in this locked queue.
            Some(unsafe { self.unlink_node(node, READY_POLLING) })
        }
    }

    fn unlink(&mut self, registration: &Arc<EpollRegistration>) {
        if registration.ready_state.load(Ordering::Relaxed) != READY_QUEUED {
            return;
        }
        let node = Arc::as_ptr(registration) as *mut EpollRegistration;
        // SAFETY: each registration belongs to one epoll instance, and queued
        // membership therefore identifies this locked ready list.
        drop(unsafe { self.unlink_node(node, READY_IDLE) });
    }

    /// Complete one unlocked provider poll. A callback racing the poll changes
    /// POLLING to PENDING; that occurrence wins over the sampled level and is
    /// appended exactly once for a later collector. This is the compact
    /// per-node equivalent of Linux's scan-list/overflow-list handoff.
    fn finish_poll(&mut self, registration: &Arc<EpollRegistration>, keep_ready: bool) {
        let state = registration.ready_state.load(Ordering::Relaxed);
        if !registration.active.load(Ordering::Acquire) {
            registration
                .ready_state
                .store(READY_IDLE, Ordering::Release);
            return;
        }
        match state {
            READY_POLLING if !keep_ready => registration
                .ready_state
                .store(READY_IDLE, Ordering::Release),
            READY_POLLING | READY_PENDING => {
                registration
                    .ready_state
                    .store(READY_IDLE, Ordering::Relaxed);
                self.link_node(registration);
            }
            READY_IDLE => {
                if keep_ready {
                    self.link_node(registration);
                }
            }
            READY_QUEUED => {
                // A queued node is a newer occurrence and must never be removed
                // by completion of an older poll.
            }
            _ => unreachable!("invalid epoll ready state"),
        }
    }

    fn is_empty(&self) -> bool {
        let empty = self.head.load(Ordering::Relaxed).is_null();
        debug_assert_eq!(empty, self.len == 0);
        empty
    }
}

impl Drop for EpollReady {
    fn drop(&mut self) {
        // Convert and drop every raw queue-owned Arc reference.
        while !self.head.load(Ordering::Relaxed).is_null() {
            let node = self.head.load(Ordering::Relaxed);
            // SAFETY: `node` is the locked queue head.
            drop(unsafe { self.unlink_node(node, READY_IDLE) });
        }
    }
}

#[derive(Debug)]
struct EpollWaiters {
    /// Wakers of every task currently parked in `epoll_wait` on THIS instance,
    /// Linux puts these sleepers on an exclusive FIFO wait queue:
    /// each readiness wake removes and wakes one waiter, while later events
    /// advance through the remaining waiters. A task that re-parks joins the
    /// tail instead of starving higher task ids. Keeping every waiter avoids
    /// the old single-slot lost-waiter bug; `pop_front` keeps the readiness hot
    /// path O(1) while many threads share an epoll fd.
    // Eligible nodes occupy the prefix; selected nodes stay in the suffix until
    // task-context cleanup. All operations are intrusive O(1).
    head: *mut EpollWaitNode,
    tail: *mut EpollWaitNode,
    selected_head: *mut EpollWaitNode,
    len: usize,
    eligible: usize,
}

// SAFETY: the raw pointers form an intrusive list protected by the containing
// EpollInstance's IrqSafeSpinLock. Every linked node is held live by a raw Arc
// strong reference until it is unlinked under that lock.
unsafe impl Send for EpollWaiters {}

pub(crate) struct EpollWaitNode {
    owner: core::sync::atomic::AtomicUsize,
    owner_file: IrqSafeSpinLock<Option<Weak<dyn FileOps>>>,
    eligible: AtomicBool,
    prev: core::sync::atomic::AtomicPtr<EpollWaitNode>,
    next: core::sync::atomic::AtomicPtr<EpollWaitNode>,
    waker: core::cell::UnsafeCell<Option<core::task::Waker>>,
}

impl core::fmt::Debug for EpollWaitNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpollWaitNode")
            .field("owner", &self.owner.load(Ordering::Relaxed))
            .field("eligible", &self.eligible.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl EpollWaitNode {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            owner: core::sync::atomic::AtomicUsize::new(0),
            owner_file: IrqSafeSpinLock::new(None),
            eligible: AtomicBool::new(false),
            prev: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            next: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            waker: core::cell::UnsafeCell::new(None),
        })
    }
}

// SAFETY: link fields and `waker` are accessed only under the owning epoll
// instance's `waiters` lock. `owner` publishes which lock owns the node;
// owner_file has its own lock for task-exit cleanup.
unsafe impl Send for EpollWaitNode {}
// SAFETY: same invariant as the Send impl above; all interior mutation is
// serialized by the owning queue lock (or the dedicated owner_file lock).
unsafe impl Sync for EpollWaitNode {}

impl EpollWaiters {
    unsafe fn unlink_links(&mut self, node: *mut EpollWaitNode) {
        // SAFETY: caller holds the queue lock and `node` is linked here.
        let waiter = unsafe { &*node };
        let prev = waiter.prev.load(Ordering::Relaxed);
        let next = waiter.next.load(Ordering::Relaxed);
        if prev.is_null() {
            self.head = next;
        } else {
            // SAFETY: linked neighbors are kept live by queue-owned Arc refs.
            unsafe { (&*prev).next.store(next, Ordering::Relaxed) };
        }
        if next.is_null() {
            self.tail = prev;
        } else {
            // SAFETY: linked neighbors are kept live by queue-owned Arc refs.
            unsafe { (&*next).prev.store(prev, Ordering::Relaxed) };
        }
        if self.selected_head == node {
            self.selected_head = next;
        }
        if waiter.eligible.swap(false, Ordering::Relaxed) {
            self.eligible -= 1;
        }
        waiter.prev.store(core::ptr::null_mut(), Ordering::Relaxed);
        waiter.next.store(core::ptr::null_mut(), Ordering::Relaxed);
        self.len -= 1;
    }

    unsafe fn link_eligible(&mut self, node: *mut EpollWaitNode) {
        // Insert immediately before the selected suffix (or at the tail if no
        // node has been selected), preserving FIFO order for both partitions.
        let next = self.selected_head;
        let prev = if next.is_null() {
            self.tail
        } else {
            // SAFETY: selected_head is linked and live under this lock.
            unsafe { (&*next).prev.load(Ordering::Relaxed) }
        };
        // SAFETY: `node` is owned by a live Arc and is not currently linked.
        let waiter = unsafe { &*node };
        waiter.prev.store(prev, Ordering::Relaxed);
        waiter.next.store(next, Ordering::Relaxed);
        if prev.is_null() {
            self.head = node;
        } else {
            // SAFETY: `prev` is a linked neighbor.
            unsafe { (&*prev).next.store(node, Ordering::Relaxed) };
        }
        if next.is_null() {
            self.tail = node;
        } else {
            // SAFETY: `next` is a linked neighbor.
            unsafe { (&*next).prev.store(node, Ordering::Relaxed) };
        }
        waiter.eligible.store(true, Ordering::Release);
        self.eligible += 1;
        self.len += 1;
    }

    unsafe fn link_selected_tail(&mut self, node: *mut EpollWaitNode) {
        let prev = self.tail;
        // SAFETY: `node` remains owned by its queue raw Arc across the move.
        let waiter = unsafe { &*node };
        waiter.prev.store(prev, Ordering::Relaxed);
        waiter.next.store(core::ptr::null_mut(), Ordering::Relaxed);
        if prev.is_null() {
            self.head = node;
        } else {
            // SAFETY: `prev` is the linked tail.
            unsafe { (&*prev).next.store(node, Ordering::Relaxed) };
        }
        self.tail = node;
        if self.selected_head.is_null() {
            self.selected_head = node;
        }
        self.len += 1;
    }
}

impl Drop for EpollWaiters {
    fn drop(&mut self) {
        while !self.head.is_null() {
            let node = self.head;
            // SAFETY: `node` is the queue head under exclusive drop access.
            unsafe { self.unlink_links(node) };
            // SAFETY: every linked node owns exactly one raw Arc reference.
            let arc = unsafe { Arc::from_raw(node) };
            arc.owner.store(0, Ordering::Release);
            *arc.owner_file.lock() = None;
            // SAFETY: exclusive Drop access replaces the queue lock; epoll
            // destruction runs in task context, so dropping the Waker is safe.
            unsafe { *arc.waker.get() = None };
        }
    }
}

/// Poll one fd's readiness WITHOUT holding the fd-table lock across the
/// `poll_readiness()` call. Clones the `Arc<dyn FileOps>` out from under the
/// (non-reentrant `IrqSafeSpinLock`) fd-table lock, releases it, then polls.
///
/// This matters because a NESTED epoll fd's `poll_readiness`
/// ([`EpollInstance::poll_readiness`]) itself calls `fd::with_table` to poll
/// its children. If the parent polled it while still holding the fd-table
/// lock, that re-entry would spin forever on the same lock — and libwayland
/// nests event loops (an inner `wl_event_loop`'s epoll fd is an event source
/// in the outer loop), so a Wayland compositor blocks on its very first
/// `epoll_wait` with no wakeup, ever. Polling outside the lock fixes it.
fn poll_item_readiness(item: &EpollSnapshot) -> u32 {
    item.file
        .upgrade()
        .map(|o| o.poll_readiness_at(item.offset))
        .unwrap_or(0)
}

// ── Per-fd wake (Linux eppoll_entry / ep_poll_callback) ─────────────
//
// Each interest fd is armed on its durable Readiness cell with its OWN waker.
// A `set` edge on that cell lists THIS fd on the instance ready-list and wakes
// the parked poller, so epoll_wait drains the ready-list (O(ready)) instead of
// rescanning the whole interest set. Owns an Arc<EpollFdWake> refcount through
// the RawWaker vtable; a Weak<dyn FileOps> (the epoll's own open file — the
// instance is only reachable through it) avoids keeping the epoll alive past
// its close.
struct EpollFdWake {
    ep: Weak<dyn FileOps>,
    registration: Arc<EpollRegistration>,
}

fn efw_fire(w: &EpollFdWake) {
    if let Some(ops) = w.ep.upgrade() {
        if let Some(inst) = as_epoll(&ops) {
            inst.push_ready(&w.registration);
        }
    }
}

static EPOLL_FD_VTABLE: core::task::RawWakerVTable =
    core::task::RawWakerVTable::new(efw_clone, efw_wake, efw_wake_by_ref, efw_drop);

unsafe fn efw_clone(p: *const ()) -> core::task::RawWaker {
    // SAFETY: `p` is an `Arc<EpollFdWake>` raw pointer minted by `epoll_fd_waker`
    // (via `Arc::into_raw`) or a prior `efw_clone`; incrementing its strong count
    // balances the `RawWaker` copy returned here.
    unsafe { Arc::increment_strong_count(p as *const EpollFdWake) };
    core::task::RawWaker::new(p, &EPOLL_FD_VTABLE)
}
unsafe fn efw_wake(p: *const ()) {
    // SAFETY: `p` is an `Arc<EpollFdWake>` raw pointer that this call consumes;
    // reconstituting the `Arc` takes ownership of that one strong count and drops
    // it when `arc` falls out of scope.
    let arc = unsafe { Arc::from_raw(p as *const EpollFdWake) };
    efw_fire(&arc);
}
unsafe fn efw_wake_by_ref(p: *const ()) {
    // SAFETY: `p` is a live `Arc<EpollFdWake>` raw pointer; `ManuallyDrop` borrows
    // it WITHOUT consuming the strong count (wake_by_ref must not drop the waker).
    let arc = core::mem::ManuallyDrop::new(unsafe { Arc::from_raw(p as *const EpollFdWake) });
    efw_fire(&arc);
}
unsafe fn efw_drop(p: *const ()) {
    // SAFETY: `p` is an `Arc<EpollFdWake>` raw pointer that this call consumes;
    // reconstituting and dropping the `Arc` releases its one strong count.
    drop(unsafe { Arc::from_raw(p as *const EpollFdWake) });
}

fn epoll_fd_waker(
    epfd_file: &Arc<dyn FileOps>,
    registration: &Arc<EpollRegistration>,
) -> core::task::Waker {
    let arc = Arc::new(EpollFdWake {
        ep: Arc::downgrade(epfd_file),
        registration: Arc::clone(registration),
    });
    let raw = Arc::into_raw(arc) as *const ();
    // SAFETY: `raw` + `EPOLL_FD_VTABLE` form a valid RawWaker over Arc<EpollFdWake>.
    unsafe { core::task::Waker::from_raw(core::task::RawWaker::new(raw, &EPOLL_FD_VTABLE)) }
}

impl EpollInstance {
    fn list_ready(&self, registration: &Arc<EpollRegistration>) -> bool {
        self.ready.lock().list(registration)
    }

    fn ready_list_empty(&self) -> bool {
        self.ready.lock().is_empty()
    }

    /// List `fd` as ready (its per-fd waker fired) and wake the parked poller.
    /// No-op if `fd` left the interest set.
    fn push_ready(&self, registration: &Arc<EpollRegistration>) {
        if !self.list_ready(registration) {
            return;
        }
        // Pair with the barrier after waiter publication: either this side
        // observes `has_parked_waiters`, or the waiter-side readiness recheck
        // observes the listing above. This is Linux's waitqueue_active() memory
        // ordering rule, expressed around our split ready/waiter locks.
        core::sync::atomic::fence(Ordering::SeqCst);
        self.wake_one_waiter();
        // Chain the wake UP to a parent epoll / poll(2) that watches THIS
        // instance as a nested fd: fire our own cell so its persistent per-fd
        // waker (armed via `arm_readiness_persistent`) runs. `set` covers a
        // rising edge (the first ready child) and `notify` covers a same-level
        // event (a further child while we are already readable) — the same
        // set+notify the AF_UNIX listener uses, and what Linux `ep_poll_safewake`
        // does by walking the nested wait-queue. Skipped unless we are actually
        // nested (`has_nested_parent`) so the direct-wait hot path pays only an
        // atomic load, not two cell-lock acquisitions per event. Fired OUTSIDE
        // `self.inner` (the cell has its own lock; `wake_by_ref` under it is
        // alloc- and lock-free). See [`EpollInstance::self_readiness`].
        if self
            .has_nested_parent
            .load(core::sync::atomic::Ordering::Acquire)
        {
            self.self_readiness.set(narf_filesystem::POLL_IN, 0);
            self.self_readiness.notify(narf_filesystem::POLL_IN);
        }
    }

    /// Select one eligible epoll waiter without moving allocation ownership
    /// through the callback path. The Waker remains stored until the selected
    /// task re-enters and disarms/re-arms in task context.
    fn wake_one_waiter(&self) {
        if !self.has_parked_waiters.load(Ordering::Acquire) {
            return;
        }
        let mut waiters = self.waiters.lock();
        if waiters.eligible == 0 {
            self.has_parked_waiters.store(false, Ordering::Release);
            return;
        }
        let selected = waiters.head;
        debug_assert!(!selected.is_null());
        // SAFETY: the eligible prefix begins at head; moving the raw node
        // between intrusive partitions neither changes refcounts nor allocates.
        unsafe {
            debug_assert!((&*selected).eligible.load(Ordering::Relaxed));
            waiters.unlink_links(selected);
            waiters.link_selected_tail(selected);
            if let Some(waker) = (&*(*selected).waker.get()).as_ref() {
                waker.wake_by_ref();
            }
        }
        self.has_parked_waiters
            .store(waiters.eligible != 0, Ordering::Release);
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: IrqSafeSpinLock::new(EpollInner {
                interest: BTreeMap::new(),
            }),
            ready: IrqSafeSpinLock::new(EpollReady {
                head: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                tail: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                len: 0,
                scan_after: None,
                prefer_always_poll: false,
                always_poll: BTreeMap::new(),
                deadline_poll: BTreeMap::new(),
            }),
            waiters: IrqSafeSpinLock::new(EpollWaiters {
                head: core::ptr::null_mut(),
                tail: core::ptr::null_mut(),
                selected_head: core::ptr::null_mut(),
                len: 0,
                eligible: 0,
            }),
            has_parked_waiters: AtomicBool::new(false),
            self_readiness: narf_lib::readiness::Readiness::new(0),
            has_nested_parent: core::sync::atomic::AtomicBool::new(false),
        })
    }

    /// `EPOLL_CTL_ADD` logic. `epfd_file` is this epoll's OWN open file (the
    /// per-fd waker holds a `Weak` to it), needed to arm the persistent
    /// `eppoll_entry` waker.
    fn ctl_add(
        &self,
        fd: i32,
        file: &Arc<dyn FileOps>,
        offset: u64,
        events: u32,
        data: u64,
        epfd_file: &Arc<dyn FileOps>,
    ) -> bool {
        let sub_id = next_sub_id();
        let registration = EpollRegistration::new(fd, sub_id, file, offset, events, data);
        let mut reaped = None;
        {
            let mut g = self.inner.lock();
            if let Some(existing) = g.interest.get(&fd) {
                if existing.registration.file.upgrade().is_some() {
                    return false; // EEXIST
                }
                // Linux removes an epoll interest when the watched open file's
                // last descriptor closes. Lazily reap the equivalent dead Weak
                // entry so a subsequently reused fd number can be added. Its
                // cell (if any) died with the file, so its waiter is already gone.
                reaped = g.interest.remove(&fd);
            }
            g.interest.insert(
                fd,
                EpollItem {
                    registration: Arc::clone(&registration),
                },
            );
        }
        if let Some(old) = reaped {
            self.retire_registration(&old.registration);
        }
        // Arm the persistent per-fd waker OUTSIDE the instance lock (arming a
        // socket takes its state lock; the cell has its own lock) and seed the
        // ready-list if the fd is already ready (Linux ep_insert's initial poll).
        self.arm_item_persistent(&registration, file, epfd_file, sub_id, events);
        true
    }

    /// Retire one exact registration. Pairing the active-state transition with
    /// identity-checked ready/fallback removal prevents a delayed DEL of an old
    /// numeric fd from unlinking its replacement.
    fn retire_registration(&self, registration: &Arc<EpollRegistration>) -> u64 {
        let state = registration.state.lock();
        registration.active.store(false, Ordering::Release);
        let sub_id = state.sub_id;
        let mut ready = self.ready.lock();
        ready.unlink(registration);
        ready.remove_always_poll(registration);
        ready.remove_deadline_poll(registration);
        sub_id
    }

    /// Arm (or re-arm) this exact registration on its provider readiness cell.
    /// Every MOD uses a fresh subscription id. After the provider call, commit
    /// only if that id is still current; a stale ADD/MOD completion disarms its
    /// own id and cannot overwrite a newer arm or a reused numeric fd.
    fn arm_item_persistent(
        &self,
        registration: &Arc<EpollRegistration>,
        file: &Arc<dyn FileOps>,
        epfd_file: &Arc<dyn FileOps>,
        sub_id: u64,
        events: u32,
    ) {
        {
            let state = registration.state.lock();
            if !registration.active.load(Ordering::Acquire)
                || state.sub_id != sub_id
                || state.events != events
            {
                return;
            }
        }
        // A disarmed EPOLLONESHOT (interest bits cleared) has nothing to wait on.
        if (events & EPOLLONESHOT) != 0
            && (events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
        {
            return;
        }
        let want = events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
        let interest = want | EPOLLERR | EPOLLHUP;
        let fd_waker = epoll_fd_waker(epfd_file, registration);
        let armed = if (events & EPOLLEXCLUSIVE) != 0 {
            file.arm_readiness_persistent_exclusive(sub_id, interest, &fd_waker)
        } else {
            file.arm_readiness_persistent(sub_id, interest, &fd_waker)
        };
        let forwards_deadline = as_epoll(file).is_some();
        let (ready_now, seeded) = {
            let mut state = registration.state.lock();
            if !registration.active.load(Ordering::Acquire) || state.sub_id != sub_id {
                drop(state);
                file.disarm_readiness(sub_id);
                return;
            }
            let mut ready = self.ready.lock();
            let mut seeded = false;
            match armed {
                Some(ready_bits) => {
                    state.cell_backed = true;
                    ready.remove_always_poll(registration);
                    if ready_bits != 0 {
                        ready.list(registration);
                        seeded = true;
                    }
                }
                None => {
                    state.cell_backed = false;
                    ready
                        .always_poll
                        .insert(registration.fd, (Arc::clone(registration), sub_id));
                }
            }
            if forwards_deadline {
                ready
                    .deadline_poll
                    .insert(registration.fd, (Arc::clone(registration), sub_id));
            } else {
                ready.remove_deadline_poll(registration);
            }
            (!ready.is_empty(), seeded)
        };
        if seeded {
            // CTL_ADD/MOD can make a watched source immediately ready while an
            // epoll waiter is already asleep. Publish exactly like a provider
            // callback; merely linking the node would strand that waiter.
            core::sync::atomic::fence(Ordering::SeqCst);
            self.wake_one_waiter();
        }
        // Keep our OWN cell level in step with the ready-list so a parent that
        // nests us and arms via `arm_readiness_persistent` right after this ADD
        // seeds an accurate initial edge (a child already ready at ADD time). A
        // rising edge here fires any already-armed parent waker (a re-ADD after
        // the set drained), which is correct; a no-op if already level-high.
        // Only when nested (see `push_ready`).
        if ready_now
            && self
                .has_nested_parent
                .load(core::sync::atomic::Ordering::Acquire)
        {
            self.self_readiness.set(narf_filesystem::POLL_IN, 0);
            if seeded {
                self.self_readiness.notify(narf_filesystem::POLL_IN);
            }
        }
    }

    /// `EPOLL_CTL_DEL` logic. Disarms the persistent per-fd waker so no stale
    /// entry lingers in the fd's Readiness cell after removal.
    fn ctl_del(&self, fd: i32, file: &Arc<dyn FileOps>) -> bool {
        let removed = {
            let mut g = self.inner.lock();
            let matches = g
                .interest
                .get(&fd)
                .and_then(|item| item.registration.file.upgrade())
                .is_some_and(|watched| Arc::ptr_eq(&watched, file));
            if matches {
                g.interest.remove(&fd)
            } else {
                None
            }
        };
        let Some(item) = removed else {
            return false;
        };
        let sub_id = self.retire_registration(&item.registration);
        // Disarm outside both epoll locks.
        file.disarm_readiness(sub_id);
        true
    }

    /// `EPOLL_CTL_MOD` logic.
    fn ctl_mod(
        &self,
        fd: i32,
        file: &Arc<dyn FileOps>,
        events: u32,
        data: u64,
        epfd_file: &Arc<dyn FileOps>,
    ) -> bool {
        let (registration, old_sub_id, new_sub_id) = {
            let g = self.inner.lock();
            let Some(item) = g.interest.get(&fd) else {
                return false; // ENOENT
            };
            let same_file = item
                .registration
                .file
                .upgrade()
                .is_some_and(|watched| Arc::ptr_eq(&watched, file));
            if !same_file {
                return false;
            }
            let registration = Arc::clone(&item.registration);
            let mut state = item.registration.state.lock();
            let old_sub_id = state.sub_id;
            let new_sub_id = next_sub_id();
            state.sub_id = new_sub_id;
            state.events = events;
            state.data = data;
            // Linux re-evaluates the fd against its new mask on every MOD and
            // re-adds it to the ready list if currently ready — so a MOD acts as
            // a fresh edge for EPOLLET (and re-arms EPOLLONESHOT). Reset the
            // rising-mask edge state, exactly as `ctl_add` initializes it, so the
            // next scan treats current readiness as a rising edge.
            state.last_mask = 0;
            (registration, old_sub_id, new_sub_id)
        };
        // The fresh id makes disarm/re-arm order safe against another MOD or
        // DEL: this call can remove only the superseded waiter.
        file.disarm_readiness(old_sub_id);
        // Re-arm the persistent waker with the new interest
        // and re-seed the ready-list, so a still-ready fd fires a fresh edge —
        // dbus-broker's queued-reply flush depends on this MOD-rearm.
        self.arm_item_persistent(&registration, file, epfd_file, new_sub_id, events);
        true
    }

    /// Per-interest-fd EPOLLET edge state for the unbounded-park diagnostic.
    /// Mirrors [`Self::collect_ready`]'s exact delivery decision so a fd that
    /// is level-readable (`ready != 0`) but `would_deliver == false` while the
    /// owner is parked on an infinite timeout is a SWALLOWED edge — the
    /// readiness landed but no rising edge/token change will ever re-report it.
    /// Returns `(fd, events, cur_mask, last_mask, cur_tok0, last_tok0,
    /// would_deliver)`.
    #[cfg(feature = "unix-latency-trace")]
    #[allow(clippy::type_complexity)]
    fn dbg_interest_edge_state(&self) -> Vec<(i32, u32, u32, u32, u64, u64, bool)> {
        let snapshot: Vec<(i32, EpollSnapshot)> = {
            let g = self.inner.lock();
            g.interest
                .iter()
                .map(|(k, v)| (*k, v.registration.snapshot()))
                .collect()
        };
        snapshot
            .into_iter()
            .map(|(fd, item)| {
                let cur_mask = poll_item_readiness(&item);
                let want = item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
                let ready = cur_mask & (want | EPOLLERR | EPOLLHUP);
                let in_ready =
                    item.registration.ready_state.load(Ordering::Acquire) == READY_QUEUED;
                let would_deliver = if ready == 0 {
                    false
                } else if (item.events & EPOLLET) != 0 {
                    let new_bits = ready & !item.last_mask;
                    new_bits != 0 || in_ready
                } else {
                    true
                };
                (
                    fd,
                    item.events,
                    cur_mask,
                    item.last_mask,
                    in_ready as u64,
                    0,
                    would_deliver,
                )
            })
            .collect()
    }

    /// Publish this `epoll_wait`'s task waker so a per-fd ready-list waker firing
    /// (via [`Self::push_ready`]) can unpark it. The per-fd cell wakers
    /// themselves are armed ONCE at `EPOLL_CTL_ADD` (Linux `eppoll_entry`,
    /// [`Self::arm_item_persistent`]) and live for the fd's whole membership —
    /// NOT per-wait — so an event listing a fd on the ready-list is captured even
    /// between non-parking (`timeout==0`) waits, and there is no per-wait O(n)
    /// re-arm on the hot path.
    fn set_parked_waker(
        &self,
        node: &Arc<EpollWaitNode>,
        epfd_file: &Arc<dyn FileOps>,
        waker: &core::task::Waker,
    ) {
        let owner = self as *const Self as usize;
        let mut waiters = self.waiters.lock();
        let previous_owner = node.owner.load(Ordering::Acquire);
        if previous_owner != 0 && previous_owner != owner {
            // A task cannot execute two blocking epoll syscalls at once. If
            // this fires, preserve the earlier live queue rather than corrupt
            // two intrusive lists with one node.
            debug_assert_eq!(previous_owner, owner, "epoll wait node has another owner");
            return;
        }
        let raw = Arc::as_ptr(node) as *mut EpollWaitNode;
        if previous_owner == owner {
            // SAFETY: owner identity proves the node is linked in this queue.
            unsafe { waiters.unlink_links(raw) };
        } else {
            node.owner.store(owner, Ordering::Release);
            *node.owner_file.lock() = Some(Arc::downgrade(epfd_file));
            // The queue owns one strong reference until task-context disarm or
            // instance destruction.
            let queued = Arc::into_raw(Arc::clone(node)) as *mut EpollWaitNode;
            debug_assert_eq!(queued, raw);
        }
        // SAFETY: the waiters lock exclusively owns this node's waker slot;
        // replacement runs here in task context, where dropping the old Waker
        // is permitted.
        unsafe { *node.waker.get() = Some(waker.clone()) };
        // SAFETY: `raw` is unlinked and protected by the queue-owned Arc.
        unsafe { waiters.link_eligible(raw) };
        self.has_parked_waiters.store(true, Ordering::Release);
        // See `push_ready`: forbid the readiness recheck from moving before
        // waiter publication, closing the lockless active-gate lost-wake race.
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    /// End-of-wait cleanup: drop the parked-waker publication. The persistent
    /// per-fd cell wakers stay armed (Linux `eppoll_entry`), disarmed only by
    /// CTL_MOD/DEL or this instance's drop.
    fn disarm_wait_node(&self, node: &Arc<EpollWaitNode>) {
        let owner = self as *const Self as usize;
        let removed = {
            let mut waiters = self.waiters.lock();
            if node.owner.load(Ordering::Acquire) != owner {
                return;
            }
            let raw = Arc::as_ptr(node) as *mut EpollWaitNode;
            // SAFETY: matching owner proves `raw` is linked in this queue.
            unsafe { waiters.unlink_links(raw) };
            node.owner.store(0, Ordering::Release);
            *node.owner_file.lock() = None;
            self.has_parked_waiters
                .store(waiters.eligible != 0, Ordering::Release);
            // SAFETY: matching owner plus the held waiters lock gives exclusive
            // access to the node's waker slot. Move it out so it drops later in
            // task context outside the spin lock.
            let waker = unsafe { (&mut *node.waker.get()).take() };
            // SAFETY: linking minted exactly one raw strong reference.
            let queued_arc = unsafe { Arc::from_raw(raw) };
            (waker, queued_arc)
        };
        drop(removed);
    }

    fn disarm_user_wait_node(&self, uctx: Option<*mut crate::user_task::UserTaskCtx>) {
        let Some(uctx) = uctx else {
            return;
        };
        // SAFETY: epoll_wait captured this pointer from CURRENT for this trap;
        // the task owns its UserTaskCtx through the entire syscall.
        self.disarm_wait_node(unsafe { &(*uctx).epoll_wait_node });
    }

    /// Two-tier delivery: a bounded pass over the ready-list plus one fair
    /// non-cell-backed source, then (only if needed) a scan of the non-cell
    /// fallback set. Durable registrations make the ready-list authoritative
    /// for cell-backed files, so an empty eventfd/socket/pipe wait never scans
    /// the cold interest tree.
    fn collect_ready(&self, task_id: u64, maxevents: usize) -> Vec<(u32, u64)> {
        let fast = self.collect_ready_pass(task_id, maxevents, false);
        if !fast.is_empty() {
            return fast;
        }
        self.collect_ready_pass(task_id, maxevents, true)
    }

    fn finish_ready_cycle_with(&self, ready_remains: bool) {
        if ready_remains {
            self.wake_one_waiter();
            if self
                .has_nested_parent
                .load(core::sync::atomic::Ordering::Acquire)
            {
                self.self_readiness.set(narf_filesystem::POLL_IN, 0);
                self.self_readiness.notify(narf_filesystem::POLL_IN);
            }
        } else if self
            .has_nested_parent
            .load(core::sync::atomic::Ordering::Acquire)
        {
            self.self_readiness.set(0, narf_filesystem::POLL_IN);
        }
    }

    fn collect_ready_pass(&self, _task_id: u64, maxevents: usize, full: bool) -> Vec<(u32, u64)> {
        // Candidate snapshot, taken without holding the lock across the
        // poll_readiness() calls (which may themselves lock). Fast pass polls
        // the ready-list (fds whose per-fd waker fired or that were seeded at
        // arm) plus non-cell-backed fds (timerfd / raw / legacy, which
        // have no edge). The fallback pass scans only that explicit cold set.
        // Each entry carries `dequeued`: the fd was detached from the ready
        // list for this poll — a cell-backed fd is listed iff its
        // persistent per-fd waker fired (a `set`/`notify` event) since the last
        // drain. It IS the EPOLLET edge the per-source token used to carry: an fd
        // that is level-ready but not listed has had no fresh event, so EPOLLET
        // must not re-report it. Detaching under the lock is also the race
        // protocol: dequeue moves the node to POLLING, a concurrent callback
        // changes it to PENDING, and write-back republishes that occurrence.
        // This is the role Linux's private txlist+ovflist pair serves, without a
        // global generation counter.
        let snapshot: Vec<(i32, EpollSnapshot, bool)> = if full {
            let (scan_after, fallback): (Option<i32>, Vec<(i32, Arc<EpollRegistration>)>) = {
                let ready = self.ready.lock();
                (
                    ready.scan_after,
                    ready
                        .always_poll
                        .iter()
                        .map(|(fd, (registration, _))| (*fd, Arc::clone(registration)))
                        .collect(),
                )
            };
            let mut entries: Vec<_> = fallback
                .into_iter()
                .filter_map(|(fd, registration)| {
                    registration
                        .active
                        .load(Ordering::Acquire)
                        .then(|| (fd, registration.snapshot(), false))
                })
                .collect();
            if let Some(after) = scan_after {
                if let Some(start) = entries.iter().position(|(fd, _, _)| *fd > after) {
                    entries.rotate_left(start);
                }
            }
            entries
        } else {
            // Detach no more ready candidates than this wait can return.
            // Different waiters therefore reserve different FIFO nodes in O(1)
            // instead of searching a shared ordered index.
            let limit = maxevents.max(1);
            let candidates: Vec<ReadyCandidate> = {
                let mut ready = self.ready.lock();
                let always = if ready.always_poll.is_empty() {
                    None
                } else {
                    use core::ops::Bound::{Excluded, Unbounded};
                    let next = ready
                        .scan_after
                        .and_then(|after| {
                            ready
                                .always_poll
                                .range((Excluded(after), Unbounded))
                                .next()
                                .map(|(fd, (registration, _))| (*fd, Arc::clone(registration)))
                        })
                        .or_else(|| {
                            ready
                                .always_poll
                                .first_key_value()
                                .map(|(fd, (registration, _))| (*fd, Arc::clone(registration)))
                        });
                    ready.scan_after = next.as_ref().map(|(fd, _)| *fd);
                    next
                };
                let have_ready = !ready.is_empty();
                let always_first = always.is_some() && have_ready && ready.prefer_always_poll;
                if always.is_some() && have_ready {
                    ready.prefer_always_poll = !ready.prefer_always_poll;
                }
                let mut candidates = Vec::with_capacity(limit + usize::from(always.is_some()));
                if always_first {
                    let registration = &always.as_ref().expect("always_first requires entry").1;
                    candidates.push((Arc::clone(registration), false));
                }
                for _ in 0..limit {
                    let Some(registration) = ready.pop_front() else {
                        break;
                    };
                    candidates.push((registration, true));
                }
                if !always_first {
                    if let Some((_, registration)) = always {
                        candidates.push((registration, false));
                    }
                }
                candidates
            };

            candidates
                .into_iter()
                .filter_map(|(registration, was_dequeued)| {
                    if !registration.active.load(Ordering::Acquire) {
                        return None;
                    }
                    let fd = registration.fd;
                    Some((fd, registration.snapshot(), was_dequeued))
                })
                .collect()
        };

        let mut results = Vec::new();
        // Poll providers without epoll locks, then validate the subscription
        // version and commit delivery under the registration-state lock. A
        // concurrent CTL_MOD changes `sub_id`; a concurrent CTL_DEL clears
        // `active`. Either makes this old observation non-deliverable, so it
        // cannot acknowledge provider state, disarm a newly rearmed oneshot, or
        // overwrite the new edge mask.
        // (registration, sampled sub_id, was dequeued, keep ready, disarm cold indexes)
        let mut ready_updates = Vec::new();
        let mut processed = 0usize;
        for (_fd, item, dequeued) in &snapshot {
            // `maxevents` limits acceptance, not merely userspace copying.
            // Do not poll, acknowledge, advance edge state, or disarm a one-shot
            // entry that this wait cannot return.
            // Such entries must remain pending for the next epoll_wait.
            if results.len() == maxevents {
                break;
            }
            processed += 1;
            // Query current readiness — polled outside the fd-table lock so a
            // nested-epoll child can't deadlock on it (see poll_fd_readiness).
            let file = item.file.upgrade();
            let cur_mask = file
                .as_ref()
                .map(|file| file.poll_readiness_at(item.offset))
                .unwrap_or(0);

            let mut keep_ready = false;
            let mut disarm_cold_indexes = false;
            if item.registration.active.load(Ordering::Acquire) {
                let mut state = item.registration.state.lock();
                if item.registration.active.load(Ordering::Acquire) && state.sub_id == item.sub_id {
                    let armed = (state.events & EPOLLONESHOT) == 0
                        || (state.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) != 0;
                    let want = state.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
                    // Linux always reports ERR/HUP even when omitted from the
                    // requested mask.
                    let ready = cur_mask & (want | EPOLLERR | EPOLLHUP);
                    let edge_ok = (state.events & EPOLLET) == 0
                        || (ready & !state.last_mask) != 0
                        || (state.cell_backed && *dequeued);
                    if armed && ready != 0 && edge_ok {
                        // Acknowledge only while the subscription version is
                        // pinned. MOD/DEL therefore cannot turn an observation
                        // under an old mask into consumption under a new one.
                        let consumed = file
                            .as_ref()
                            .map(|file| file.acknowledge_poll_readiness(cur_mask))
                            .unwrap_or(0);
                        state.last_mask = cur_mask & !consumed;
                        results.push((ready, state.data));
                        keep_ready =
                            state.cell_backed && (state.events & (EPOLLET | EPOLLONESHOT)) == 0;
                        if (state.events & EPOLLONESHOT) != 0 {
                            state.events &= EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE;
                            disarm_cold_indexes = true;
                        }
                    } else {
                        state.last_mask &= cur_mask;
                        let still_ready = cur_mask & (want | EPOLLERR | EPOLLHUP) != 0;
                        keep_ready = state.cell_backed
                            && (state.events & EPOLLET) != 0
                            && *dequeued
                            && still_ready;
                    }
                }
            }
            // Even a concurrent CTL_DEL/MOD must complete the POLLING state.
            ready_updates.push((
                Arc::clone(&item.registration),
                item.sub_id,
                *dequeued,
                keep_ready,
                disarm_cold_indexes,
            ));
        }
        // If an always-polled candidate filled the userspace batch first, put
        // any ready nodes detached behind it back at the tail. They were never
        // polled, so their occurrence is still pending.
        let unprocessed: Vec<_> = snapshot[processed..]
            .iter()
            .filter(|(_, _, dequeued)| *dequeued)
            .map(|(_, item, _)| Arc::clone(&item.registration))
            .collect();
        let needs_ready_write = !unprocessed.is_empty()
            || ready_updates
                .iter()
                .any(|(_, _, dequeued, _, disarm_cold_indexes)| *dequeued || *disarm_cold_indexes);
        let ready_remains = if needs_ready_write {
            let mut ready = self.ready.lock();
            for (registration, sub_id, dequeued, keep_ready, disarm_cold_indexes) in ready_updates {
                if disarm_cold_indexes {
                    ready.remove_always_poll_version(&registration, sub_id);
                    ready.remove_deadline_poll_version(&registration, sub_id);
                }
                if dequeued {
                    ready.finish_poll(&registration, keep_ready);
                }
            }
            for registration in unprocessed {
                ready.finish_poll(&registration, true);
            }
            !ready.is_empty()
        } else {
            !self.ready.lock().is_empty()
        };

        // Linux ep_done_scan hands a non-empty rdllist to another exclusive
        // sleeper. This is required for LT readiness: requeueing the node is not
        // itself a provider callback, so without this handoff another task can
        // remain asleep while work is already available.
        self.finish_ready_cycle_with(ready_remains);

        results
    }

    fn fallback_registrations(&self) -> Vec<Arc<EpollRegistration>> {
        self.ready
            .lock()
            .always_poll
            .values()
            .map(|(registration, _)| Arc::clone(registration))
            .collect()
    }

    /// Would `collect_ready` deliver at least one event right now?
    /// Mirrors [`Self::collect_ready_pass`]'s per-fd delivery decision EXACTLY
    /// — same readiness source and EPOLLONESHOT/EPOLLET edge — but takes no
    /// action. A non-empty authoritative ready-list is sufficient; only legacy
    /// non-cell sources require polling.
    ///
    /// This is the correct predicate for the register-then-recheck self-wake at
    /// park. Linux `ep_poll` rechecks with `ep_events_available()` — the SAME
    /// ready-list that `ep_try_send_events` drains (fs/eventpoll.c) — so the
    /// recheck and the delivery agree and a park cannot self-wake forever.
    /// [`Self::poll_readiness`] is the wrong predicate here because a passive
    /// nested-epoll / `poll(2)` query is level-based, while this direct wait must
    /// honor consumed EPOLLET edges. Mixing the predicates can self-wake every
    /// re-execution and create a 100%-CPU `epoll_wait` livelock.
    fn has_deliverable(&self, _task_id: u64) -> bool {
        if !self.ready_list_empty() {
            return true;
        }
        for registration in self.fallback_registrations() {
            let item = registration.snapshot();
            // Disarmed EPOLLONESHOT items deliver nothing.
            if (item.events & EPOLLONESHOT) != 0
                && (item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
            {
                continue;
            }
            let cur = match item.file.upgrade() {
                Some(f) => f.poll_readiness_at(item.offset),
                None => continue,
            };
            let want = item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
            let ready = cur & (want | EPOLLERR | EPOLLHUP);
            if ready == 0 {
                continue;
            }
            // EPOLLET: a fresh edge only — a rising mask bit or ready-list
            // membership (the wait-queue edge), exactly as `collect_ready_pass`.
            if (item.events & EPOLLET) != 0 {
                let new_bits = ready & !item.last_mask;
                if new_bits == 0 {
                    continue;
                }
            }
            return true;
        }
        false
    }

    /// Earliest absolute monotonic-ns deadline at which any fd in the
    /// interest set will become readable on its own timed schedule (a
    /// `timerfd`). Returns `None` when no interest fd is time-driven.
    ///
    /// A parked `epoll_wait` consults this to clamp its scheduler wake-up:
    /// timerfd expiries don't fire a readiness *notify*, so without this a
    /// timerfd armed in an epoll set with an infinite timeout would never
    /// wake the waiter (it parks forever) — the dead-repaint-loop failure.
    fn nearest_poll_deadline(&self, _task_id: u64) -> Option<u64> {
        let registrations: Vec<_> = {
            let ready = self.ready.lock();
            ready
                .always_poll
                .values()
                .chain(ready.deadline_poll.values())
                .map(|(registration, _)| Arc::clone(registration))
                .collect()
        };
        let mut earliest: Option<u64> = None;
        for registration in registrations {
            if let Some(d) = registration.file.upgrade().and_then(|o| o.poll_deadline()) {
                earliest = Some(earliest.map_or(d, |e| e.min(d)));
            }
        }
        earliest
    }
}

impl FileOps for EpollInstance {
    /// Linux `epoll_create1` uses `anon_inode_getfile("[eventpoll]")`: every such file shares the ONE `anon_inodefs` inode
    /// (`fs/anon_inodes.c::anon_inode_inode`), so all of them report the
    /// same `(st_dev, st_ino)`.
    fn ino(&self) -> u64 {
        narf_filesystem::inode_id::anon_inode().ino
    }
    fn anon_name(&self) -> Option<&'static str> {
        Some("[eventpoll]")
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::inode_id::anon_inode().attrs()
    }

    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    /// epoll-readiness for nested epoll / `poll(2)` over an epoll fd.
    /// Returns POLL_IN iff `epoll_wait` would deliver at least one event
    /// — the filters MUST mirror `collect_ready`, or a `poll` that
    /// reports the epoll fd readable pairs with an `epoll_wait` that
    /// returns 0 events and the caller's event loop spins forever
    /// (Linux ep_eventpoll_poll likewise reflects the ready list, so an
    /// already-consumed EPOLLET edge does NOT count as readable).
    fn poll_readiness(&self) -> u32 {
        // Cross-table cycle backstop — see `POLL_NEST_DEPTH`.
        let Some(_nest) = NestGuard::enter() else {
            return 0;
        };
        // Durable providers publish directly into the authoritative ready list,
        // matching Linux's O(1) ep_events_available() query. Only legacy/time-
        // driven fallback sources need an unlocked provider poll.
        if !self.ready_list_empty() {
            if self
                .has_nested_parent
                .load(core::sync::atomic::Ordering::Acquire)
            {
                self.self_readiness.set(narf_filesystem::POLL_IN, 0);
            }
            return narf_filesystem::POLL_IN;
        }
        for registration in self.fallback_registrations() {
            let item = registration.snapshot();
            let events = item.events;
            let last_mask = item.last_mask;
            // Disarmed EPOLLONESHOT items deliver nothing.
            if (events & EPOLLONESHOT) != 0
                && (events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
            {
                continue;
            }
            let cur = poll_item_readiness(&item);
            let want = events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
            let ready = cur & (want | EPOLLERR | EPOLLHUP);
            if ready == 0 {
                continue;
            }
            // EPOLLET: readable only on a fresh edge, same as `collect_ready` —
            // a rising mask bit or ready-list membership (the wait-queue edge).
            if (events & EPOLLET) != 0 && (ready & !last_mask) == 0 {
                continue;
            }
            if self
                .has_nested_parent
                .load(core::sync::atomic::Ordering::Acquire)
            {
                self.self_readiness.set(narf_filesystem::POLL_IN, 0);
            }
            return narf_filesystem::POLL_IN;
        }
        // Reconcile our OWN cell level, now that we have computed the
        // authoritative answer and it is "not readable".
        //
        // `push_ready` RAISES this cell on a child event, but the only place
        // that LOWERED it was `collect_ready` — the direct-wait path — on the
        // reasoning that "for the purely-nested case the parent's
        // `poll_readiness` query is authoritative regardless". `poll(2)`'s
        // park breaks that: it arms this cell and treats `any_ready` as the
        // answer, returning `poll_scan`'s count without consulting the
        // timeout. So an epoll fd whose child went ready and was then DRAINED
        // stayed latched high forever, and every later `poll`/`ppoll` over it
        // returned 0 immediately — before its timeout, which poll(2) may
        // never do.
        //
        // Any loop that polls an epoll fd instead of calling `epoll_wait` on
        // it then spins at 100% of a CPU while behaving correctly, which is
        // why it is invisible to a functional test. That is precisely GLib
        // over PipeWire's loop fd (`wp_loop_source_new`, lib/wp/core.c):
        // WirePlumber's main thread was measured in `ppoll` 1,654,732 times
        // in 35 seconds, every call returning nothing ready.
        //
        // Clearing is a FALLING edge — `set` fires no waker for it — so no
        // parent is spuriously woken, and `push_ready` re-raises it on the
        // next child event. The lost-wake window between this query and the
        // parent's `arm` is closed by `arm` returning the cell's level: a
        // child that goes ready in the window re-raises the cell and the arm
        // reports it.
        if self
            .has_nested_parent
            .load(core::sync::atomic::Ordering::Acquire)
        {
            // Serialize the final empty observation with push_ready's list
            // operation. Clearing is a falling edge and invokes no callbacks;
            // a provider callback waiting on `ready` lists first and raises the
            // cell after this lock is released.
            let ready = self.ready.lock();
            if !ready.is_empty() {
                drop(ready);
                self.self_readiness.set(narf_filesystem::POLL_IN, 0);
                return narf_filesystem::POLL_IN;
            }
            self.self_readiness.set(0, narf_filesystem::POLL_IN);
        }
        0
    }

    /// This epoll fd's own durable readiness cell — how a PARENT epoll /
    /// `poll(2)` arms a persistent per-fd waker on this instance when it is
    /// nested. The wake is chained from [`EpollInstance::push_ready`];
    /// [`EpollInstance::poll_readiness`] remains the authoritative level query.
    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        Some(&self.self_readiness)
    }

    /// A parent epoll arming its persistent per-fd waker (Linux `eppoll_entry`)
    /// on this nested instance: latch [`Self::has_nested_parent`] so `push_ready`
    /// starts chaining the wake up, then arm on our own cell.
    fn arm_readiness_persistent(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        self.has_nested_parent
            .store(true, core::sync::atomic::Ordering::Release);
        // Reconcile before arming. Once the latch above is visible, any
        // concurrent push raises this cell; `arm_persistent` then either sees
        // that level or remains installed for the notification.
        let _ = self.poll_readiness();
        Some(self.self_readiness.arm_persistent(id, interest, waker))
    }

    fn arm_readiness_persistent_exclusive(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        self.has_nested_parent
            .store(true, core::sync::atomic::Ordering::Release);
        let _ = self.poll_readiness();
        Some(
            self.self_readiness
                .arm_persistent_exclusive(id, interest, waker),
        )
    }

    /// `poll(2)` over this epoll fd (the non-persistent arm). Same latch as
    /// [`Self::arm_readiness_persistent`] so a nested `poll` also gets the wake.
    fn arm_readiness(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        self.has_nested_parent
            .store(true, core::sync::atomic::Ordering::Release);
        let _ = self.poll_readiness();
        Some(self.self_readiness.arm(id, interest, waker))
    }

    /// Forward the nearest child timerfd deadline so a `poll(2)` over
    /// this epoll fd clamps its park to it. A timerfd expiry fires no
    /// readiness notify, and `poll_nearest_deadline` only queries the
    /// DIRECT fds in the poll set — without this forwarding, a
    /// `poll(-1)` over an epoll whose only wake source is a nested
    /// timerfd parks forever (the ~10 ms backstop re-checks the park
    /// condition but never re-runs the readiness scan).
    fn poll_deadline(&self) -> Option<u64> {
        // Cross-table cycle backstop — see `POLL_NEST_DEPTH`.
        let _nest = NestGuard::enter()?;
        self.nearest_poll_deadline(current_task_id())
    }

    /// Recover the concrete instance from an `Arc<dyn FileOps>` — how
    /// `epoll_ctl`/`epoll_wait` resolve an epfd via the fd table.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

impl Drop for EpollInstance {
    /// Disarm every interest fd's persistent `eppoll_entry` waker so no stale
    /// entry lingers in a still-live shared Readiness cell after the epoll fd
    /// closes (Linux `ep_free` walks the rbtree calling `ep_remove` →
    /// `ep_unregister_pollwait`). A fired stale waker would already be a no-op
    /// (its `Weak<epoll file>` no longer upgrades), but leaving the map entry
    /// would leak a slot on a long-lived socket watched by short-lived epolls.
    fn drop(&mut self) {
        let items = core::mem::take(&mut self.inner.lock().interest);
        for item in items.values() {
            let state = item.registration.state.lock();
            item.registration.active.store(false, Ordering::Release);
            if let Some(file) = item.registration.file.upgrade() {
                file.disarm_readiness(state.sub_id);
            }
        }
    }
}

// ── Instance resolution — through the fd table, like Linux ──────────
// The instance IS the fd's `FileOps` object, so resolve `epfd` through
// the caller's fd table and downcast — exactly how Linux recovers the
// `eventpoll` from the `struct file`. An earlier design kept a global
// registry keyed by `(creating task id, epfd)`; that key is wrong for
// every path where the fd outlives or escapes its creating thread:
// a CLONE_FILES sibling (kwin_wayland waits on an epoll another thread
// created — the registry miss made `epoll_wait` fail -1 while `poll`
// on the same fd reported it readable via the shared fd table, so the
// caller span ppoll↔epoll_pwait at 100% CPU and wedged the whole
// cooperative session at PSTEP-WAYLAND), a dup'd epfd, and a
// fork-inherited one. Resolving through the table fixes all four and
// drops the instance with its last fd reference instead of leaking it.

/// Clone `epfd`'s `Arc<dyn FileOps>` out of `task`'s fd table.
fn epoll_ops(task: u64, epfd: u32) -> Option<Arc<dyn FileOps>> {
    fd::lookup(task, epfd).map(|file| file.ops)
}

/// Passive post-registration readiness probe for the epoll park handshake.
/// `FileOps::poll_readiness` mirrors what `collect_ready` would deliver but
/// does not acknowledge sources, consume EPOLLET tokens, or disarm oneshots.
pub fn epoll_fd_has_ready(task: u64, epfd: u32) -> bool {
    // The own-stack park recheck (`park_should_block`) asks this to decide
    // whether an about-to-park `epoll_wait` should instead re-execute. It MUST
    // use the same ET-aware delivery decision as `collect_ready` — i.e.
    // `has_deliverable` — NOT the level predicate `poll_readiness()`.
    //
    // `poll_readiness()` reports POLL_IN whenever ANY interest fd is level-ready,
    // including an EPOLLET fd whose edge was already consumed (readable, but
    // last_mask already holds the bit). `collect_ready` correctly delivers
    // nothing for those, so the level
    // predicate made the recheck answer "ready, don't park" while the re-executed
    // `epoll_wait` delivered zero events — park_should_block returns false, the
    // task never yields, and it re-scans forever: a 100%-CPU `epoll_wait` livelock
    // that needed NO wake to sustain (every readiness wake path stays quiet). On
    // the CachyOS desktop this pinned dbus-broker / systemd event loops and the
    // greeter never presented. `has_deliverable` mirrors `collect_ready`'s per-fd
    // ET decision, so the recheck and the delivery agree and the
    // park either delivers or genuinely blocks. (Invariant pinned by
    // `smoke_epoll_has_deliverable_matches_collect_ready`.)
    epoll_ops(task, epfd)
        .as_ref()
        .and_then(as_epoll)
        .is_some_and(|inst| inst.has_deliverable(task))
}

/// View an fd's ops as an `EpollInstance`, if it is one.
fn as_epoll(ops: &Arc<dyn FileOps>) -> Option<&EpollInstance> {
    ops.as_any()?.downcast_ref::<EpollInstance>()
}

/// Forced-task-exit cleanup for the task-owned intrusive wait node. The weak
/// file reference avoids a raw-instance lifetime dependency: either the epoll
/// file still exists and removes the node in O(1), or its Drop already drained
/// the queue and cleared the weak owner.
pub(crate) fn detach_task_wait_node(node: &Arc<EpollWaitNode>) {
    if node.owner.load(Ordering::Acquire) == 0 {
        return;
    }
    let owner = node.owner_file.lock().clone();
    if let Some(ops) = owner.and_then(|weak| weak.upgrade()) {
        if let Some(instance) = as_epoll(&ops) {
            instance.disarm_wait_node(node);
        }
    }
}

// ── Nested-epoll bounds ──────────────────────────────────────────────

/// Maximum epoll-inside-epoll nesting depth, matching Linux's cap
/// (`fs/eventpoll.c` ep_loop_check rejects paths 5 deep with ELOOP).
/// libwayland/libinput legitimately nest 2-3 levels; 5 leaves headroom.
const EP_MAX_NESTS: u32 = 5;

/// Per-CPU recursion depth for the poll-time child walks
/// (`poll_readiness` / `poll_deadline`). `epoll_ctl` already refuses to
/// build a same-table cycle (see `epoll_reaches`), but a cycle stitched
/// together through two DIFFERENT fd tables (fork-shared or
/// SCM_RIGHTS-passed epoll fds whose interest fds only resolve in the
/// peer's table) is invisible to that check — without this backstop it
/// would recurse until the kernel stack overflows. Safe as a per-CPU
/// counter: the walk is synchronous (no await/park inside) and no IRQ
/// path calls `poll_readiness`.
static POLL_NEST_DEPTH: [core::sync::atomic::AtomicU32; narf_lib::percpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; narf_lib::percpu::MAX_CPUS];

/// Scope guard for one level of `POLL_NEST_DEPTH`. `enter` refuses
/// (returns `None`) beyond `EP_MAX_NESTS` levels.
struct NestGuard {
    cpu: usize,
}

impl NestGuard {
    fn enter() -> Option<Self> {
        let cpu = narf_lib::percpu::current_cpu();
        let d = &POLL_NEST_DEPTH[cpu];
        if d.load(Ordering::Relaxed) >= EP_MAX_NESTS {
            return None;
        }
        d.fetch_add(1, Ordering::Relaxed);
        Some(Self { cpu })
    }
}

impl Drop for NestGuard {
    fn drop(&mut self) {
        POLL_NEST_DEPTH[self.cpu].fetch_sub(1, Ordering::Relaxed);
    }
}

/// DFS from `from`'s interest set looking for `needle` (a cycle back to
/// the containing epoll) or nesting deeper than [`EP_MAX_NESTS`].
/// Mirrors Linux `fs/eventpoll.c`:ep_loop_check_proc. Child fds are
/// resolved through the CALLER's fd table (interest records store fd
/// numbers, not file refs — LINUX-GAP: an epoll passed via SCM_RIGHTS
/// re-resolves against the receiver's table); non-epoll children are
/// leaves. Snapshots each interest set so no epoll lock is held across
/// the recursive step.
fn epoll_reaches(
    _task: u64,
    from: &EpollInstance,
    needle: *const EpollInstance,
    depth: u32,
) -> bool {
    if depth >= EP_MAX_NESTS {
        return true;
    }
    let items: Vec<EpollItem> = from.inner.lock().interest.values().cloned().collect();
    for item in items {
        let Some(ops) = item.registration.file.upgrade() else {
            continue;
        };
        let Some(child) = as_epoll(&ops) else {
            continue;
        };
        if core::ptr::eq(child, needle) || epoll_reaches(_task, child, needle, depth + 1) {
            return true;
        }
    }
    false
}

// ── sys_epoll_create / wait / ctl handlers ───────────────────────────

/// Shared body for both epoll-creating entry points.
fn create_epoll(ctx: &mut dyn TrapContext, cloexec: bool) {
    let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };

    // The fd entry's ops Arc is the ONLY owner handle: every later
    // epoll_ctl/epoll_wait recovers the instance from the fd table
    // (`epoll_ops` + `as_epoll`), and closing the last fd drops it.
    let ops = EpollInstance::new() as Arc<dyn FileOps>;

    let task = current_task_id();
    let new_fd = fd::install(
        task,
        crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: install_flags,
            // `do_epoll_create` opens the anon inode with
            // `O_RDWR | (flags & O_CLOEXEC)`. The access mode is observable:
            // a caller that probes `fcntl(epfd, F_GETFL)` — glibc's stdio
            // does this on any fd handed to fdopen — saw O_RDONLY here and
            // concluded the descriptor was not writable.
            status_flags: crate::fd::O_RDWR,
        },
    );

    match new_fd {
        Some(fd) => ctx.set_return(SyscallReturn::ok(fd as u64)),
        // A full descriptor table is -EMFILE. The note here used to call
        // this arm unreachable "because NARF's fd table grows without
        // bound" — no longer true since RLIMIT_NOFILE enforcement, and
        // `smoke_abi_ioerrno_epoll_create_reports_emfile` covers it.
        //
        // LINUX-GAP: `ep_alloc` failing separately is -ENOMEM; NARF has no
        // distinct allocation-failure path here, so that half stands.
        None => ctx.set_return(to_ret(EMFILE)),
    }
}

/// `epoll_create1(flags)` — x86_64 291, aarch64 20.
///
/// `fs/eventpoll.c::do_epoll_create` opens with
/// `if (flags & ~EPOLL_CLOEXEC) return -EINVAL;`. Ignoring the unknown bits
/// (which this handler did while it also served `epoll_create`) hands back a
/// descriptor without the property the caller asked for — most consequentially
/// a non-CLOEXEC epoll fd leaking through every exec in the process tree.
pub fn sys_epoll_create1(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0 as u32;
    if flags & !crate::fd::O_CLOEXEC != 0 {
        ctx.set_return(to_ret(EINVAL));
        return;
    }
    create_epoll(ctx, flags & crate::fd::O_CLOEXEC != 0);
}

/// `epoll_create(size)` — the pre-2.6.27 entry point, x86_64 213 only.
///
/// ```text
/// SYSCALL_DEFINE1(epoll_create, int, size)
/// {
///         if (size <= 0)
///                 return -EINVAL;
///         return do_epoll_create(0);
/// }
/// ```
///
/// `size` stopped meaning anything when the interest list stopped being a
/// hash table, but the check outlived it and callers still rely on it. arg0
/// is a COUNT here, not a flag word — sharing an implementation with
/// `epoll_create1` made `epoll_create(0)` succeed and, in the other
/// direction, would have read a size of 524288 as EPOLL_CLOEXEC.
pub fn sys_epoll_create(ctx: &mut dyn TrapContext) {
    let size = ctx.args().arg0 as i32;
    if size <= 0 {
        ctx.set_return(to_ret(EINVAL));
        return;
    }
    create_epoll(ctx, false);
}

pub fn sys_epoll_ctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let op = args.arg1 as u32;
    let tfd = args.arg2 as i32;
    let ev_ptr = args.arg3 as *const u8;
    let task = current_task_id();

    // `SYSCALL_DEFINE4(epoll_ctl)` imports the event word before anything
    // else, so a faulting `event` outranks even a closed epfd.
    let event = if op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD {
        if ev_ptr.is_null() {
            ctx.set_return(to_ret(EFAULT));
            return;
        }
        match read_epoll_event(ev_ptr as u64) {
            Ok(v) => Some(v),
            Err(_) => {
                ctx.set_return(to_ret(EFAULT));
                return;
            }
        }
    } else {
        None
    };

    let ops = match epoll_ops(task, epfd) {
        Some(o) => o,
        None => {
            ctx.set_return(to_ret(EBADF));
            return;
        }
    };
    let target = if tfd >= 0 {
        fd::with_table(task, |t| {
            let entry = t.get(tfd as u32)?;
            Some((entry.ops.clone(), t.offset(tfd as u32)?))
        })
        .flatten()
    } else {
        None
    };
    let (target_ops, target_offset) = match target {
        Some(target) => target,
        None => {
            ctx.set_return(to_ret(EBADF));
            return;
        }
    };
    // `if (!file_can_poll(fd_file(tf))) return -EPERM;`
    //
    // Position matters: this sits after BOTH descriptors resolve and before
    // the -EINVAL arms below, so a call that is wrong in two ways at once —
    // an epfd that is not an epoll AND a target that cannot be polled —
    // reports EPERM, not EINVAL. Moving it after the EINVAL checks would
    // report the wrong one of the two.
    //
    // `FileOps::can_poll` carries the answer because file TYPE cannot: an
    // inotify descriptor and `/proc/self/mountinfo` are both `FileType::File`
    // here and both must stay addable. It defaults to true, so only backends
    // that positively declare themselves unpollable are refused.
    if !target_ops.can_poll() {
        ctx.set_return(to_ret(EPERM));
        return;
    }
    // Both "epfd names itself" and "epfd is not an epoll" are -EINVAL, and
    // Linux checks them only after both descriptors resolve. The comparison
    // is on the open file description (`fd_file(f) == fd_file(tf)`), not the
    // descriptor number, so a dup() of epfd is caught too.
    if Arc::ptr_eq(&ops, &target_ops) {
        ctx.set_return(to_ret(EINVAL));
        return;
    }
    let instance = match as_epoll(&ops) {
        Some(i) => i,
        None => {
            ctx.set_return(to_ret(EINVAL));
            return;
        }
    };

    match op {
        EPOLL_CTL_ADD => {
            let (events, data) = event.expect("ADD imported its event above");
            // Nested-epoll hardening, mirroring Linux ep_loop_check:
            // refuse an ADD that would make this epoll reachable from
            // itself (a cycle turns the recursive readiness poll into
            // unbounded kernel recursion) or nest epolls deeper than
            // EP_MAX_NESTS.
            if let Some(target) = as_epoll(&target_ops) {
                if core::ptr::eq(target, instance) || epoll_reaches(task, target, instance, 1) {
                    ctx.set_return(to_ret(ELOOP));
                    return;
                }
            }
            if instance.ctl_add(tfd, &target_ops, target_offset, events, data, &ops) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(to_ret(EEXIST));
            }
        }
        EPOLL_CTL_MOD => {
            let (events, data) = event.expect("MOD imported its event above");
            if instance.ctl_mod(tfd, &target_ops, events, data, &ops) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(to_ret(ENOENT));
            }
        }
        EPOLL_CTL_DEL => {
            if instance.ctl_del(tfd, &target_ops) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(to_ret(ENOENT));
            }
        }
        _ => ctx.set_return(to_ret(EINVAL)),
    }
}

pub fn sys_epoll_pwait(ctx: &mut dyn TrapContext) {
    epoll_wait_common(ctx, true, None);
}

#[allow(clippy::never_loop)]
pub fn sys_epoll_wait(ctx: &mut dyn TrapContext) {
    epoll_wait_common(ctx, false, None);
}

/// `epoll_pwait2(epfd, events, maxevents, const timespec *timeout, sigmask,
/// sigsetsize)` — Linux x86_64 441 / aarch64 441.
///
/// The Linux-5.11-era nanosecond-resolution twin of [[sys_epoll_pwait]]. The
/// only wire difference is arg3: instead of an `int timeout_ms`, it is a
/// `const struct timespec *` (16 bytes, `{ i64 tv_sec; i64 tv_nsec }`). A
/// NULL pointer means "block indefinitely" — the `epoll_wait` core takes
/// `-1` ms for that; a non-NULL timespec is converted to a clamped `i32` ms.
///
/// We ROUND ANY SUB-MS REMAINDER UP so a `{0, 1}` (1 ns) timeout does not
/// truncate to `0` ms (which the core would treat as a non-blocking poll) —
/// mirroring Linux's `ep_timeout_to_timespec`/`schedule_hrtimeout` behaviour
/// where a tiny but non-zero timeout still yields a real (bounded) wait
/// rather than a zero-timeout return. The value saturates to `i32::MAX` ms.
///
/// Everything else — the sigmask save/restore, the readiness/park loop — is
/// the SAME common path as `epoll_pwait`; this is a thin timeout adapter that
/// hands the computed ms into [[epoll_wait_common]] as an override.
#[allow(clippy::never_loop)]
pub fn sys_epoll_pwait2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ts_ptr = args.arg3;
    let timeout_ms: i32 = if ts_ptr == 0 {
        // NULL timeout → block forever (the core takes -1 ms for that).
        -1
    } else {
        // SAFETY: `ts_ptr` is a user `timespec*` in-pointer; copy_from_user_vec
        // range-validates the 16-byte read and SMAP-brackets it.
        match unsafe { crate::handlers::copy_from_user_vec(ts_ptr, 16) } {
            Ok(b) => {
                let secs = u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                let nsec =
                    u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
                // poll_select_set_timeout(): a negative field or tv_nsec
                // outside [0, 1e9) is -EINVAL, not a clamped timeout.
                if (secs as i64) < 0 || nsec >= 1_000_000_000 {
                    ctx.set_return(to_ret(EINVAL));
                    return;
                }
                // sec*1000 + ceil(nsec / 1e6): round the sub-ms remainder UP so a
                // 1 ns timeout stays a (tiny) blocking wait, not a 0-ms poll.
                let sub_ms = nsec / 1_000_000;
                let round_up = u64::from(nsec % 1_000_000 != 0);
                let ms = secs
                    .saturating_mul(1000)
                    .saturating_add(sub_ms)
                    .saturating_add(round_up);
                ms.min(i32::MAX as u64) as i32
            }
            Err(_) => {
                // `SYSCALL_DEFINE6(epoll_pwait2)`:
                // `if (get_timespec64(&ts, timeout)) return -EFAULT;`
                ctx.set_return(to_ret(EFAULT));
                return;
            }
        }
    };
    epoll_wait_common(ctx, true, Some(timeout_ms));
}

/// A live user task can park through either execution model. The legacy model
/// needs its longjmp hook; the own-stack model instead switches directly back
/// to the executor and deliberately has no such hook.
#[inline]
pub(crate) fn can_park_with_task_context(
    own_stack_enabled: bool,
    legacy_yield_hook_present: bool,
) -> bool {
    own_stack_enabled || legacy_yield_hook_present
}

/// `is_pwait` selects the sigmask save/restore (epoll_pwait / epoll_pwait2).
/// `timeout_override` supplies a pre-computed ms timeout for callers whose
/// arg3 is NOT already an `int` ms (epoll_pwait2's `timespec*`); `None` reads
/// the ms directly from arg3 (epoll_wait / epoll_pwait).
#[allow(clippy::never_loop)]
fn epoll_wait_common(ctx: &mut dyn TrapContext, is_pwait: bool, timeout_override: Option<i32>) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let events_ptr = args.arg1 as *mut u8;
    let maxevents = args.arg2 as u32 as i32 as i64;
    let timeout_ms = timeout_override.unwrap_or(args.arg3 as i32);
    let sigmask_ptr = args.arg4;
    let sigsetsize = args.arg5;
    // `fs/eventpoll.c`: `EP_MAX_EVENTS = INT_MAX / sizeof(struct epoll_event)`.
    const EP_MAX_EVENTS: i64 = i32::MAX as i64 / EPOLL_EVENT_SIZE as i64;
    let task = current_task_id();

    // `SYSCALL_DEFINE6(epoll_pwait)` runs `set_user_sigmask` BEFORE
    // `do_epoll_wait`, so a malformed sigmask outranks even a closed epfd:
    //
    //     if (!umask)                          return 0;
    //     if (sigsetsize != sizeof(sigset_t))  return -EINVAL;
    //     if (copy_from_user(...))             return -EFAULT;
    //
    // The old code gated on `sigsetsize == 8` and silently IGNORED any other
    // size — so a caller passing the wrong sigset width had its mask quietly
    // not applied and still got its events, which is the worst outcome: the
    // signal it was blocking could be delivered inside the wait.
    let mut mask_active = false;
    if is_pwait && sigmask_ptr != 0 {
        if sigsetsize != 8 {
            ctx.set_return(to_ret(EINVAL));
            return;
        }
        let mut buf = [0u8; 8];
        // SAFETY: sigsetsize == 8 checked above; copy_from_user range-validates
        // `sigmask_ptr` and SMAP-brackets the read into `buf`.
        if unsafe { crate::handlers::copy_from_user(&mut buf, sigmask_ptr) }.is_ok() {
            // `set_user_sigmask`: the caller's mask is saved for the return
            // (`restore_saved_sigmask_unless`), and the wait — park included —
            // runs under this one. A re-execution after a park finds it
            // installed and keeps the saved original.
            let mask = u64::from_ne_bytes(buf); // user sigset_t == NARF N-1 layout
            crate::handlers::install_temporary_signal_mask(task, mask);
            mask_active = true;
        } else {
            ctx.set_return(to_ret(EFAULT));
            return;
        }
    }

    // Everything below is `do_epoll_wait` order, which is NOT the order this
    // handler used to apply:
    //
    //     CLASS(fd, f)(epfd); if (fd_empty(f)) return -EBADF;
    //     ep_check_params():
    //         maxevents <= 0 || maxevents > EP_MAX_EVENTS -> -EINVAL
    //         !access_ok(evs, maxevents * sizeof(ev))     -> -EFAULT
    //         !is_file_epoll(file)                        -> -EINVAL
    //
    // The descriptor is resolved FIRST, and the buffer and count are separate
    // answers. The old code tested `events_ptr.is_null() || maxevents == 0`
    // ahead of the fd lookup and collapsed all four into one `-1`, so an event
    // loop that closed its epfd saw "Operation not permitted" rather than the
    // EBADF that tells it to rebuild the loop.
    // Put the caller's mask back on a return that delivers no signal; when
    // one was delivered, the handler frame took the saved mask over and
    // sigreturn restores it (`restore_saved_sigmask_unless(error == -EINTR)`).
    let restore = |task: u64, mask_active: bool| {
        if mask_active {
            crate::handlers::restore_temporary_signal_mask(task);
        }
    };

    // Resolve through the fd table (NOT a creating-thread registry) so a
    // CLONE_FILES sibling, a dup'd fd, or a fork-inherited epfd all wait
    // on the same instance `poll(2)` sees — see `epoll_ops`.
    let ops = match epoll_ops(task, epfd) {
        Some(o) => o,
        None => {
            restore(task, mask_active);
            ctx.set_return(to_ret(EBADF));
            return;
        }
    };
    // `maxevents` is an `int`; the register's upper half is not part of it.
    if maxevents <= 0 || maxevents > EP_MAX_EVENTS {
        restore(task, mask_active);
        ctx.set_return(to_ret(EINVAL));
        return;
    }
    // access_ok over the WHOLE output array, before any of it is written.
    let span = (maxevents as usize).saturating_mul(EPOLL_EVENT_SIZE);
    if crate::handlers::validate_user_range(events_ptr as u64, span).is_err() {
        restore(task, mask_active);
        ctx.set_return(to_ret(EFAULT));
        return;
    }
    let instance = match as_epoll(&ops) {
        Some(i) => i,
        None => {
            restore(task, mask_active);
            ctx.set_return(to_ret(EINVAL)); // not an epoll fd
            return;
        }
    };

    // Without a polling task context (the in-kernel test harness has
    // no user task to park), epoll_wait can't block — fall back to a
    // single non-blocking readiness poll. `uctx` is therefore an
    // Option; `None` forces the `timeout == 0` (non-blocking) path.
    let uctx_opt = crate::user_task::current_user_task();
    // Reset the net-I/O-wait *flag* on every (re-)entry (the syscall
    // re-executes via RIP-rewind each park cycle). We deliberately do
    // NOT drop the io-waiter here: the readiness wake `take()`s the
    // whole table, so a registered waker self-clears when it fires;
    // dropping it on re-entry created a window where inbound data's
    // `notify` found an empty table and fell back to the deadline.
    if let Some(uctx_ptr) = uctx_opt {
        // SAFETY: `uctx_ptr` is the in-flight task's `UserTaskCtx`,
        // live for this trap; both are atomic fields.
        unsafe {
            (*uctx_ptr).net_io_wait.store(false, Ordering::Release);
            (*uctx_ptr).epoll_wait_fd.store(0, Ordering::Release);
            // Snapshot the net readiness generation BEFORE the
            // readiness check below, so the poll routine can detect a
            // notify that races our check→park window.
            (*uctx_ptr)
                .epoll_park_gen
                .store(narf_net::readiness::generation(), Ordering::Release);
            // signalfd lost-wake guard snapshot (see UserTaskCtx::signal_park_gen).
            (*uctx_ptr).signal_park_gen.store(
                crate::handlers::signal_raise_generation(task),
                Ordering::Release,
            );
        }
    }

    let deadline_ns: Option<u64> = match uctx_opt {
        None => Some(0),
        Some(uctx_ptr) => {
            // SAFETY: `uctx_ptr` is the in-flight task's `UserTaskCtx`, published
            // in `CURRENT` for exactly this trap; it stays live for the whole
            // syscall and the borrow does not escape this match arm.
            // SAFETY: Valid memory or trusted environment
            let uctx = unsafe { &*uctx_ptr };
            if timeout_ms == 0 {
                Some(0)
            } else if timeout_ms > 0 {
                // Reuse the deadline from a prior re-execution of THIS call if
                // one is in flight. `blocking_deadline_ns` (unlike
                // `sleep_deadline_ns`) survives the scheduler clearing the wake
                // signal on timeout expiry, so a pure-timeout wait re-executed
                // past its deadline detects expiry below instead of computing a
                // fresh `now + timeout` and re-arming forever.
                let persisted = uctx.blocking_deadline_ns.load(Ordering::Acquire);
                let d = if persisted != 0 {
                    persisted
                } else {
                    let d = narf_scheduler::narf_time::monotonic_ns()
                        .saturating_add((timeout_ms as u64) * 1_000_000);
                    uctx.blocking_deadline_ns.store(d, Ordering::Release);
                    d
                };
                // Re-publish the scheduler wake signal (cleared on each expiry).
                uctx.sleep_deadline_ns.store(d, Ordering::Release);
                Some(d)
            } else {
                uctx.sleep_deadline_ns.store(u64::MAX, Ordering::Release);
                None
            }
        }
    };

    loop {
        // `maxevents` is validated as a positive `int` above, so the cast
        // back to a count cannot truncate or go negative.
        let ready = instance.collect_ready(task, maxevents as usize);
        let n = ready.len();
        if n > 0 {
            if let Some(uctx_ptr) = uctx_opt {
                // SAFETY: `uctx_ptr` is the in-flight task's `UserTaskCtx` from
                // `CURRENT`, live for this trap; `sleep_deadline_ns` is an atomic
                // field, so the store needs only a valid pointer.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release);
                    (*uctx_ptr).blocking_deadline_ns.store(0, Ordering::Release);
                };
            }
            let write_failed = ready.iter().enumerate().any(|(i, (events, data))| {
                write_epoll_event(
                    events_ptr as u64 + (i * EPOLL_EVENT_SIZE) as u64,
                    *events,
                    *data,
                )
                .is_err()
            });
            if write_failed {
                restore(task, mask_active);
                // The array was access_ok'd above; a fault here is a
                // racing unmap, and `ep_send_events` reports it as -EFAULT.
                ctx.set_return(to_ret(EFAULT));
                return;
            }
            restore(task, mask_active);
            instance.disarm_user_wait_node(uctx_opt);
            ctx.set_return(SyscallReturn::ok(n as u64));
            return;
        }

        match deadline_ns {
            Some(0) => {
                restore(task, mask_active);
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            Some(d) if d != u64::MAX && narf_scheduler::narf_time::monotonic_ns() >= d => {
                instance.disarm_user_wait_node(uctx_opt);
                if let Some(uctx_ptr) = uctx_opt {
                    // SAFETY: `uctx_ptr` is the in-flight task's `UserTaskCtx` from
                    // `CURRENT`, live for this trap; `sleep_deadline_ns` is an
                    // atomic field, so the store needs only a valid pointer.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release);
                        (*uctx_ptr).blocking_deadline_ns.store(0, Ordering::Release);
                    };
                }
                restore(task, mask_active);
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            _ => {
                if let Some(uctx_ptr) = uctx_opt {
                    let own_stack = narf_scheduler::stackful::user_own_stack_enabled();
                    let hook = crate::user_task::yield_hook();
                    if !can_park_with_task_context(own_stack, hook.is_some()) {
                        // A task context exists, but this execution mode has no
                        // route back to an executor. Fall through to the
                        // non-blocking fallback below rather than spinning.
                    } else {
                        // A pending signal ends the wait with -EINTR. The
                        // return value goes in BEFORE delivery: the handler
                        // frame saves the registers as they are now and
                        // sigreturn restores exactly those — set after, the
                        // caller got the syscall number back instead.
                        if crate::handlers::has_interrupting_signal(task) {
                            ctx.set_return(to_ret(EINTR));
                            if let Some(h) = crate::signal_delivery_hook() {
                                let _ = h(ctx, crate::Syscall::EpollWait.raw());
                            }
                            instance.disarm_user_wait_node(uctx_opt);
                            restore(task, mask_active);
                            // SAFETY: `uctx_ptr` is the in-flight task's
                            // `UserTaskCtx` from `CURRENT`, live for this trap;
                            // `sleep_deadline_ns` is an atomic field, so the
                            // store needs only a valid pointer.
                            unsafe {
                                (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release);
                                (*uctx_ptr).blocking_deadline_ns.store(0, Ordering::Release);
                            };
                            return;
                        }

                        // epoll_pwait parks under its own mask, as Linux sleeps
                        // with it: a signal it unblocks ends the wait.
                        // Debug-feature only: what the interest set looked
                        // like at the instant we committed to a park. Covers
                        // BOTH finite and infinite timeouts — systemd/PID 1's
                        // event loop uses a FINITE-timeout epoll_wait, and a
                        // finite park that re-arms every backstop tick with a
                        // readable-but-undelivered fd in its set is just as
                        // stranded as an unbounded one (the accept edge is lost
                        // on every re-scan). Printing the set is the difference
                        // between "epoll never saw the fd" and "the fd really
                        // was not ready", which no amount of outside
                        // observation distinguishes. Throttled to ~4 lines/s so
                        // a persistent strand can't re-flood the serial line
                        // (that flood is itself an observer effect that
                        // manufactures the accept pile-up under investigation).
                        #[cfg(feature = "unix-latency-trace")]
                        {
                            use core::fmt::Write as _;
                            static SHOWN: core::sync::atomic::AtomicU32 =
                                core::sync::atomic::AtomicU32::new(0);
                            static LAST_NS: core::sync::atomic::AtomicU64 =
                                core::sync::atomic::AtomicU64::new(0);
                            // Budget generously: an earlier 48-line cap was
                            // spent entirely by PID 1 and systemd-tmpfiles
                            // before the task under investigation had even
                            // started, and a probe that goes silent early
                            // looks exactly like a task that never parked.
                            // Committing to an infinite park with a fd already
                            // readable-for-a-requested-bit in the set is the
                            // strand signature: the owner should have been
                            // delivered that fd (LT) or a rising edge for it (ET)
                            // and is nonetheless sleeping. Printing ONLY then —
                            // instead of on every park — keeps this probe from
                            // flooding the serial line (thousands of lines/boot),
                            // which itself perturbs scheduling and back-pressures
                            // journald enough to manufacture the very accept
                            // pile-up under investigation.
                            let edge = instance.dbg_interest_edge_state();
                            let suspicious = edge.iter().any(|&(_, ev, cur, _, _, _, _)| {
                                let want = ev & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
                                // Gate on the READ side only. POLLOUT is
                                // level-writable on an idle socket almost always,
                                // so an always-registered EPOLLOUT|ET fd reads as
                                // a permanent "swallowed" edge that is in fact
                                // benign ET steady state (dbus-broker keeps
                                // EPOLLOUT armed on every connection). A
                                // readable/acceptable fd (IN/ERR/HUP) left
                                // undelivered to a parked owner is the real
                                // accept/read strand worth printing.
                                (cur & ((want & EPOLLIN) | EPOLLERR | EPOLLHUP)) != 0
                            });
                            let now_ns = narf_scheduler::narf_time::monotonic_ns();
                            let throttled = now_ns.saturating_sub(LAST_NS.load(Ordering::Relaxed))
                                < 250_000_000;
                            if suspicious
                                && !throttled
                                && SHOWN.fetch_add(1, Ordering::Relaxed) < 2000
                            {
                                LAST_NS.store(now_ns, Ordering::Relaxed);
                                let comm = crate::handlers::proc_comm_of_task(task)
                                    .unwrap_or_else(|| alloc::string::String::from("?"));
                                let _ = write!(
                                    narf_console::Writer,
                                    "  epoll-park: tid={task} comm={comm} epfd={epfd} set=[",
                                );
                                for (wfd, ev, cur, last, ctok, ltok, deliv) in edge {
                                    // SWALLOW: level-readable for a requested bit
                                    // but the ET delivery decision says no — a lost
                                    // edge that an infinite park will never re-see.
                                    // STRAND: ready and WOULD deliver, yet the owner
                                    // parked — a lost wake, not a lost edge.
                                    let want = ev & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
                                    let readable = (cur & (want | EPOLLERR | EPOLLHUP)) != 0;
                                    let mark = if readable && !deliv {
                                        "SWALLOW"
                                    } else if readable && deliv {
                                        "STRAND"
                                    } else {
                                        "-"
                                    };
                                    let et = if (ev & EPOLLET) != 0 { "ET" } else { "LT" };
                                    let _ = write!(
                                        narf_console::Writer,
                                        "{wfd}:{et}:cur={cur:#x}:last={last:#x}:tok={ctok}/{ltok}:{mark} ",
                                    );
                                }
                                let _ = writeln!(narf_console::Writer, "]");
                            }
                        }
                        // SAFETY: `uctx_ptr` is the in-flight task's `UserTaskCtx`
                        // from `CURRENT`, live for this trap; `state`/`exit_reason`
                        // are its own `UnsafeCell` fields and the `hook` consumes
                        // the same pointer to park exactly this task.
                        // Publish this task's waker so a per-fd ready-list waker
                        // (armed persistently at CTL_ADD) can unpark it. The cells
                        // are already armed for the fd's lifetime, so this is O(1),
                        // not a per-wait O(n) re-arm.
                        if let Some(w) = narf_scheduler::stackful::current_stackful_waker() {
                            // SAFETY: `uctx_ptr` is CURRENT for this trap and
                            // remains owned by the live task while it parks.
                            let wait_node = unsafe { &(*uctx_ptr).epoll_wait_node };
                            instance.set_parked_waker(wait_node, &ops, &w);
                            // Register-then-recheck — closes the collect_ready ->
                            // park lost-wake window. A fd whose persistent waker
                            // fired push_ready AFTER the top collect_ready but
                            // BEFORE set_parked_waker listed it on the ready-list
                            // with no parked waker to wake; without this recheck
                            // the park would STRAND. `has_deliverable(task)`
                            // non-destructively mirrors collect_ready's exact
                            // delivery decision;
                            // if it now reports deliverable, self-wake so the park
                            // re-executes and delivers. It must be `has_deliverable`
                            // and not `poll_readiness()`: the latter is a passive
                            // level query, so an already-consumed ET source could
                            // report ready while collect_ready delivers nothing —
                            // a park self-wake livelock (100%-CPU epoll_wait). Because
                            // this mirrors collect_ready, a benign always-writable
                            // EPOLLOUT or an already-consumed EPOLLET edge does NOT
                            // trigger, so it cannot spin.
                            if instance.has_deliverable(task) {
                                w.wake_by_ref();
                            }
                        }
                        // SAFETY: Valid memory or trusted environment
                        unsafe {
                            let uc = &*uctx_ptr;
                            // Flag this park as a net-I/O wait so the poll
                            // routine registers our waker for inbound-data
                            // wakeups (immediate re-poll on TCP data instead
                            // of waiting out the deadline).
                            uc.net_io_wait.store(true, Ordering::Release);
                            uc.epoll_wait_fd.store((epfd as u64) + 1, Ordering::Release);
                            // Clamp the scheduler wake-up to the nearest armed
                            // timerfd in the interest set. A timerfd expiry does
                            // NOT fire a readiness notify (unlike socket data), so
                            // without this clamp a timerfd-driven wait sleeps until
                            // the full timeout — or, with an infinite timeout (the
                            // Wayland repaint loop), forever. On wake the syscall
                            // re-executes from the top and re-polls, finding the
                            // timer ready. (For a finite timeout this replaces the
                            // persisted timeout deadline with the earlier timer one;
                            // since the timer is readable at that instant the re-poll
                            // returns its event before the timeout path is reached.
                            // The only lost case is a timer disarmed from another
                            // thread mid-park, which no single-threaded waiter hits.)
                            // Only clamp to a FUTURE timer deadline. A deadline
                            // already in the past means the timer is ready now;
                            // `collect_ready` above would have delivered it, so
                            // reaching here means it is not deliverable (an
                            // EPOLLET edge already consumed). Clamping
                            // `sleep_deadline` to a past instant would make the
                            // scheduler wake this task immediately, only to
                            // re-park and re-clamp to the same past instant — a
                            // 100%-CPU spin. Leave the existing deadline (the
                            // user timeout, or unbounded) and rely on the fd's
                            // own readiness wake / the backstop instead.
                            if let Some(timer_dl) = instance.nearest_poll_deadline(task) {
                                let now = narf_scheduler::narf_time::monotonic_ns();
                                if timer_dl > now {
                                    let cur = uc.sleep_deadline_ns.load(Ordering::Acquire);
                                    let clamped = if cur == 0 {
                                        timer_dl
                                    } else {
                                        cur.min(timer_dl)
                                    };
                                    uc.sleep_deadline_ns.store(clamped, Ordering::Release);
                                }
                            }
                            // Rewind RIP so we re-execute epoll_wait on resume.
                            ctx.set_rip(ctx.rip().wrapping_sub(2));
                            ctx.save_user_state(uc.state.get() as *mut u8);
                            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                            if own_stack {
                                crate::handlers::own_stack_block(ctx);
                                // `ep_poll`: a signal ends the wait with a
                                // plain -EINTR — not a restart code, so a
                                // stop/continue or a SA_RESTART handler still
                                // sees EINTR (signal(7)) — after one more
                                // look for events and the timeout, which
                                // win over it. Run that pass now rather than
                                // handing the exit trap a restart-pending
                                // frame, which would restart the wait.
                                if crate::handlers::has_interrupting_signal(task) {
                                    ctx.set_rip(ctx.rip().wrapping_add(2));
                                    uc.syscall_parked_restarting.store(false, Ordering::Release);
                                    continue;
                                }
                                return;
                            }
                            // `can_park_with_task_context` above established that
                            // the legacy execution path has its mandatory hook.
                            hook.expect("legacy epoll park requires yield hook")(uctx_ptr);
                        }
                    }
                }

                // No task context or execution-model park route (the
                // in-kernel test harness, or an early-boot caller):
                // there is no cooperative way to block, so report no
                // events ready rather than spinning forever. A real
                // task always took the park path above.
                restore(task, mask_active);
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
        }
    }
}

// ── Test reset ───────────────────────────────────────────────────────

/// Test hook retained for callers that reset all userspace test globals.
#[doc(hidden)]
pub fn __test_reset() {}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;
    use narf_filesystem::{POLL_IN, POLL_OUT};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A `FileOps` whose readiness mask is settable, to drive an epoll interest
    /// fd to any exact readiness state.
    struct MaskFile {
        mask: AtomicU32,
    }
    impl MaskFile {
        fn new(m: u32) -> Arc<Self> {
            Arc::new(Self {
                mask: AtomicU32::new(m),
            })
        }
    }
    impl FileOps for MaskFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
        fn poll_readiness(&self) -> u32 {
            self.mask.load(Ordering::Relaxed)
        }
    }

    struct DeadlineFile {
        deadline: u64,
    }

    impl FileOps for DeadlineFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }

        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }

        fn poll_deadline(&self) -> Option<u64> {
            Some(self.deadline)
        }
    }

    /// Provider with deterministic interleaving hooks. Mutating the
    /// subscription from inside `arm` or `poll_readiness` models CTL_MOD winning
    /// exactly across epoll's unlocked provider calls, without a timing-based
    /// SMP test.
    struct RaceFile {
        mask: AtomicU32,
        readiness: narf_lib::readiness::Readiness,
        registration: IrqSafeSpinLock<Option<Weak<EpollRegistration>>>,
        mutate_on_arm: AtomicBool,
        mutate_on_poll: AtomicBool,
        acknowledgements: AtomicU32,
    }

    impl RaceFile {
        fn new(mask: u32, mutate_on_arm: bool, mutate_on_poll: bool) -> Arc<Self> {
            Arc::new(Self {
                mask: AtomicU32::new(mask),
                readiness: narf_lib::readiness::Readiness::new(mask),
                registration: IrqSafeSpinLock::new(None),
                mutate_on_arm: AtomicBool::new(mutate_on_arm),
                mutate_on_poll: AtomicBool::new(mutate_on_poll),
                acknowledgements: AtomicU32::new(0),
            })
        }

        fn attach(&self, registration: &Arc<EpollRegistration>) {
            *self.registration.lock() = Some(Arc::downgrade(registration));
        }

        fn replace_subscription(&self) {
            let registration = self.registration.lock().as_ref().and_then(Weak::upgrade);
            if let Some(registration) = registration {
                let mut state = registration.state.lock();
                state.sub_id = next_sub_id();
                state.events = EPOLLOUT;
                state.data = 0xBEEF;
                state.last_mask = 0;
            }
        }
    }

    impl FileOps for RaceFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }

        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }

        fn poll_readiness(&self) -> u32 {
            if self.mutate_on_poll.swap(false, Ordering::AcqRel) {
                self.replace_subscription();
            }
            self.mask.load(Ordering::Acquire)
        }

        fn acknowledge_poll_readiness(&self, _observed: u32) -> u32 {
            self.acknowledgements.fetch_add(1, Ordering::AcqRel);
            0
        }

        fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
            Some(&self.readiness)
        }

        fn arm_readiness_persistent(
            &self,
            id: u64,
            interest: u32,
            waker: &core::task::Waker,
        ) -> Option<u32> {
            let ready = self.readiness.arm_persistent(id, interest, waker);
            if self.mutate_on_arm.swap(false, Ordering::AcqRel) {
                self.replace_subscription();
            }
            Some(ready)
        }
    }

    const FD: i32 = 7;
    const TASK: u64 = 0xE9_01;

    /// A one-fd epoll instance in an exact state. Returns the instance and the
    /// backing file, kept alive so the interest `Weak` upgrades.
    fn one_fd(
        events: u32,
        mask: u32,
        last_mask: u32,
        cell_backed: bool,
        in_ready: bool,
    ) -> (Arc<EpollInstance>, Arc<MaskFile>) {
        let file = MaskFile::new(mask);
        let ep = EpollInstance::new();
        let file_ops = file.clone() as Arc<dyn FileOps>;
        let registration = EpollRegistration::new(FD, 1, &file_ops, 0, events, 0);
        {
            let mut state = registration.state.lock();
            state.last_mask = last_mask;
            state.cell_backed = cell_backed;
        }
        {
            let mut g = ep.inner.lock();
            g.interest.insert(
                FD,
                EpollItem {
                    registration: Arc::clone(&registration),
                },
            );
        }
        if !cell_backed {
            ep.ready
                .lock()
                .always_poll
                .insert(FD, (Arc::clone(&registration), 1));
        }
        if in_ready {
            ep.list_ready(&registration);
        }
        (ep, file)
    }

    fn smoke_epoll_stale_arm_cannot_overwrite_mod() -> TestResult {
        let ep = EpollInstance::new();
        let ep_ops = ep.clone() as Arc<dyn FileOps>;
        let file = RaceFile::new(0, true, false);
        let file_ops = file.clone() as Arc<dyn FileOps>;
        let registration = EpollRegistration::new(FD, 0x101, &file_ops, 0, EPOLLIN, 0);
        file.attach(&registration);

        ep.arm_item_persistent(&registration, &file_ops, &ep_ops, 0x101, EPOLLIN);

        if file.readiness.waiter_count() != 0 {
            return TestResult::Fail("stale arm completion must disarm only its old subscription");
        }
        if registration.state.lock().cell_backed || !ep.ready.lock().always_poll.is_empty() {
            return TestResult::Fail("stale arm completion must not commit provider metadata");
        }

        // Also cover an operation delayed before its provider call. It must not
        // snapshot and arm the newer MOD's id on behalf of stale work.
        file.mutate_on_arm.store(false, Ordering::Release);
        let current = *registration.state.lock();
        ep.arm_item_persistent(&registration, &file_ops, &ep_ops, 0x101, EPOLLIN);
        if file.readiness.waiter_count() != 0 || *registration.state.lock() != current {
            return TestResult::Fail(
                "a pre-provider stale arm must not arm the newer subscription",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_epoll_stale_arm_cannot_overwrite_mod
    );

    fn smoke_epoll_mod_during_poll_cannot_deliver_old_mask() -> TestResult {
        let ep = EpollInstance::new();
        let file = RaceFile::new(POLL_IN, false, true);
        let file_ops = file.clone() as Arc<dyn FileOps>;
        let registration = EpollRegistration::new(FD, 0x201, &file_ops, 0, EPOLLIN, 0xCAFE);
        file.attach(&registration);
        registration.state.lock().cell_backed = true;
        ep.inner.lock().interest.insert(
            FD,
            EpollItem {
                registration: Arc::clone(&registration),
            },
        );
        ep.list_ready(&registration);

        if !ep.collect_ready(TASK, 1).is_empty() {
            return TestResult::Fail("an observation from before MOD must not be delivered");
        }
        if file.acknowledgements.load(Ordering::Acquire) != 0 {
            return TestResult::Fail("an observation from before MOD must not be acknowledged");
        }
        let state = registration.state.lock();
        if state.events != EPOLLOUT || state.data != 0xBEEF || state.last_mask != 0 {
            return TestResult::Fail("old poll write-back must not overwrite MOD state");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_epoll_mod_during_poll_cannot_deliver_old_mask
    );

    fn smoke_epoll_mod_del_replace_subscription_without_leak() -> TestResult {
        let ep = EpollInstance::new();
        let ep_ops = ep.clone() as Arc<dyn FileOps>;
        let file = RaceFile::new(0, false, false);
        let file_ops = file.clone() as Arc<dyn FileOps>;
        if !ep.ctl_add(FD, &file_ops, 0, EPOLLIN, 1, &ep_ops) {
            return TestResult::Fail("CTL_ADD failed");
        }
        let registration = Arc::clone(&ep.inner.lock().interest[&FD].registration);
        let first_id = registration.state.lock().sub_id;
        if file.readiness.waiter_count() != 1 {
            return TestResult::Fail("CTL_ADD must install one persistent waiter");
        }
        if !ep.ctl_mod(FD, &file_ops, EPOLLOUT, 2, &ep_ops) {
            return TestResult::Fail("CTL_MOD failed");
        }
        if registration.state.lock().sub_id == first_id || file.readiness.waiter_count() != 1 {
            return TestResult::Fail("CTL_MOD must atomically replace, not duplicate, its waiter");
        }
        if !ep.ctl_del(FD, &file_ops) || file.readiness.waiter_count() != 0 {
            return TestResult::Fail("CTL_DEL must remove the current persistent waiter");
        }

        // A delayed old-fd cleanup must not remove a fallback record belonging
        // to a replacement registration with the same numeric descriptor.
        let old = EpollRegistration::new(FD, 0x301, &file_ops, 0, EPOLLIN, 0);
        let replacement = EpollRegistration::new(FD, 0x302, &file_ops, 0, EPOLLIN, 0);
        ep.ready
            .lock()
            .always_poll
            .insert(FD, (Arc::clone(&replacement), 0x302));
        ep.retire_registration(&old);
        let replacement_survived = ep
            .ready
            .lock()
            .always_poll
            .get(&FD)
            .is_some_and(|(current, id)| *id == 0x302 && Arc::ptr_eq(current, &replacement));
        if !replacement_survived {
            return TestResult::Fail("old fd cleanup must not remove its replacement");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_epoll_mod_del_replace_subscription_without_leak
    );

    /// The park-time recheck (`has_deliverable`) MUST agree with what
    /// `collect_ready` actually delivers. If it ever reports deliverable while
    /// `collect_ready` returns nothing, the parked `epoll_wait` self-wakes and
    /// re-parks forever — a 100%-CPU livelock (kwin's greeter never presented).
    /// Check the spin-prone configurations; `has_deliverable` is non-mutating so
    /// it is queried before the (mutating) `collect_ready` on the same state.
    fn smoke_epoll_has_deliverable_matches_collect_ready() -> TestResult {
        __test_reset();

        // (1) Level-triggered readable -> deliverable both ways.
        {
            let (ep, _f) = one_fd(EPOLLIN, POLL_IN, 0, false, false);
            if !ep.has_deliverable(TASK) {
                return TestResult::Fail("LT readable: has_deliverable should be true");
            }
            if ep.collect_ready(TASK, 8).is_empty() {
                return TestResult::Fail("LT readable: collect_ready should deliver");
            }
        }

        // (2) EPOLLIN|ET with the edge already consumed (mask==last_mask) and not
        //     on the ready-list -> NOT deliverable. Both must agree (no self-wake).
        {
            let (ep, _f) = one_fd(EPOLLIN | EPOLLET, POLL_IN, POLL_IN, true, false);
            if ep.has_deliverable(TASK) {
                return TestResult::Fail("ET-consumed IN: has_deliverable must be false");
            }
            if !ep.collect_ready(TASK, 8).is_empty() {
                return TestResult::Fail("ET-consumed IN: collect_ready must be empty");
            }
        }

        // (3) EPOLLOUT|ET steadily writable, edge consumed -> NOT deliverable.
        //     The greeter-spin shape: a permanently-writable OUT|ET fd must not
        //     drive the park recheck to self-wake.
        {
            let (ep, _f) = one_fd(EPOLLOUT | EPOLLET, POLL_OUT, POLL_OUT, true, false);
            if ep.has_deliverable(TASK) {
                return TestResult::Fail("ET-consumed OUT: has_deliverable must be false");
            }
            if !ep.collect_ready(TASK, 8).is_empty() {
                return TestResult::Fail("ET-consumed OUT: collect_ready must be empty");
            }
        }

        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_epoll_has_deliverable_matches_collect_ready
    );

    // Test waker: its data pointer is an index into `TEST_WOKE`; `wake` sets
    // that slot. `clone` preserves the index and drop is a no-op (the
    // "resource" is just an integer).
    static TEST_WOKE: [core::sync::atomic::AtomicBool; 4] =
        [const { core::sync::atomic::AtomicBool::new(false) }; 4];
    unsafe fn tw_clone(p: *const ()) -> core::task::RawWaker {
        core::task::RawWaker::new(p, &TEST_WAKER_VTABLE)
    }
    unsafe fn tw_wake(p: *const ()) {
        let i = p as usize;
        if i < TEST_WOKE.len() {
            TEST_WOKE[i].store(true, Ordering::Relaxed);
        }
    }
    unsafe fn tw_drop(_p: *const ()) {}
    static TEST_WAKER_VTABLE: core::task::RawWakerVTable =
        core::task::RawWakerVTable::new(tw_clone, tw_wake, tw_wake, tw_drop);
    fn test_waker(i: usize) -> core::task::Waker {
        // SAFETY: `i` is a small integer sentinel, never dereferenced; the
        // vtable only ever reads it back as `p as usize`.
        unsafe {
            core::task::Waker::from_raw(core::task::RawWaker::new(
                i as *const (),
                &TEST_WAKER_VTABLE,
            ))
        }
    }

    fn smoke_epoll_ctl_seed_wakes_existing_waiter() -> TestResult {
        TEST_WOKE[0].store(false, Ordering::Relaxed);
        let ep = EpollInstance::new();
        let ep_ops = ep.clone() as Arc<dyn FileOps>;
        let node = EpollWaitNode::new();
        ep.set_parked_waker(&node, &ep_ops, &test_waker(0));

        let file = RaceFile::new(POLL_IN, false, false);
        let file_ops = file.clone() as Arc<dyn FileOps>;
        if !ep.ctl_add(FD, &file_ops, 0, EPOLLIN, 0, &ep_ops) {
            return TestResult::Fail("CTL_ADD failed");
        }
        if !TEST_WOKE[0].load(Ordering::Relaxed) {
            return TestResult::Fail("ready-at-CTL_ADD must wake an existing epoll waiter");
        }
        ep.disarm_wait_node(&node);
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_epoll_ctl_seed_wakes_existing_waiter
    );

    fn smoke_nested_epoll_arm_sees_existing_ready_child() -> TestResult {
        let (child, _file) = one_fd(EPOLLIN, POLL_IN, 0, true, true);
        let child_ops = child.clone() as Arc<dyn FileOps>;
        let parent = EpollInstance::new();
        let parent_ops = parent.clone() as Arc<dyn FileOps>;

        if !parent.ctl_add(FD + 1, &child_ops, 0, EPOLLIN, 0x44, &parent_ops) {
            return TestResult::Fail("parent CTL_ADD failed");
        }
        match parent.collect_ready(TASK, 1).as_slice() {
            [(events, data)] if events & EPOLLIN != 0 && *data == 0x44 => {}
            _ => {
                return TestResult::Fail(
                    "nesting an already-ready epoll must seed the parent ready list",
                )
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_nested_epoll_arm_sees_existing_ready_child
    );

    fn smoke_nested_epoll_forwards_fallback_deadline() -> TestResult {
        const DEADLINE: u64 = 0x1234_5678;
        let child = EpollInstance::new();
        let child_ops = child.clone() as Arc<dyn FileOps>;
        let timer = Arc::new(DeadlineFile { deadline: DEADLINE });
        let timer_ops = timer as Arc<dyn FileOps>;
        if !child.ctl_add(FD, &timer_ops, 0, EPOLLIN, 0, &child_ops) {
            return TestResult::Fail("child CTL_ADD failed");
        }

        let parent = EpollInstance::new();
        let parent_ops = parent.clone() as Arc<dyn FileOps>;
        if !parent.ctl_add(FD + 1, &child_ops, 0, EPOLLIN, 0, &parent_ops) {
            return TestResult::Fail("parent CTL_ADD failed");
        }
        if parent.nearest_poll_deadline(TASK) != Some(DEADLINE) {
            return TestResult::Fail(
                "cell-backed nested epoll must remain in the deadline-forwarding index",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_nested_epoll_forwards_fallback_deadline
    );

    /// Linux queues shared-epoll sleepers as exclusive, auto-removing waiters:
    /// one readiness event wakes one task, and a later event advances to the
    /// next. This preserves all waiters without waking N threads to race for
    /// one event (the default perf-bench epoll topology).
    fn smoke_epoll_push_ready_wakes_one_parked_waiter_per_event() -> TestResult {
        __test_reset();
        let reset = || {
            for w in &TEST_WOKE {
                w.store(false, Ordering::Relaxed);
            }
        };
        reset();
        // One readable fd, three tasks parked on the SAME instance.
        let (ep, _f) = one_fd(EPOLLIN, POLL_IN, 0, false, false);
        let ep_ops = ep.clone() as Arc<dyn FileOps>;
        let nodes = [
            EpollWaitNode::new(),
            EpollWaitNode::new(),
            EpollWaitNode::new(),
        ];
        ep.set_parked_waker(&nodes[0], &ep_ops, &test_waker(0));
        ep.set_parked_waker(&nodes[1], &ep_ops, &test_waker(1));
        ep.set_parked_waker(&nodes[2], &ep_ops, &test_waker(2));

        // Re-parking a task replaces only its own slot and moves it to the
        // queue tail, just like Linux removing and re-adding a wait entry.
        ep.set_parked_waker(&nodes[0], &ep_ops, &test_waker(0));
        if ep.waiters.lock().len != 3 {
            return TestResult::Fail("re-park must replace the task's own waker, not grow the map");
        }

        ep.push_ready(&ep.inner.lock().interest[&FD].registration);
        if TEST_WOKE[0].load(Ordering::Relaxed)
            || !TEST_WOKE[1].load(Ordering::Relaxed)
            || TEST_WOKE[2].load(Ordering::Relaxed)
        {
            return TestResult::Fail("one event must wake only one exclusive epoll waiter");
        }

        reset();
        ep.push_ready(&ep.inner.lock().interest[&FD].registration);
        if TEST_WOKE[0].load(Ordering::Relaxed)
            || TEST_WOKE[1].load(Ordering::Relaxed)
            || !TEST_WOKE[2].load(Ordering::Relaxed)
        {
            return TestResult::Fail("a later event must advance to the next epoll waiter");
        }

        reset();
        ep.push_ready(&ep.inner.lock().interest[&FD].registration);
        if !TEST_WOKE[0].load(Ordering::Relaxed)
            || TEST_WOKE[1].load(Ordering::Relaxed)
            || TEST_WOKE[2].load(Ordering::Relaxed)
        {
            return TestResult::Fail("every parked waiter must eventually receive an event");
        }
        {
            let waiters = ep.waiters.lock();
            if waiters.eligible != 0 || waiters.len != 3 {
                return TestResult::Fail(
                    "selected waiters must remain stored but ineligible until task cleanup",
                );
            }
        }
        ep.disarm_wait_node(&nodes[0]);
        ep.disarm_wait_node(&nodes[1]);
        ep.disarm_wait_node(&nodes[2]);
        if ep.waiters.lock().len != 0 {
            return TestResult::Fail("task-context disarm must remove selected waiters");
        }
        __test_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_epoll_push_ready_wakes_one_parked_waiter_per_event
    );

    /// Detaching a ready node transfers the queue's strong reference to the
    /// collector. A callback racing that unlocked poll may immediately append
    /// the same stable node again; queue membership must remain singular.
    fn smoke_epoll_intrusive_ready_detach_requeue() -> TestResult {
        __test_reset();
        let (ep, file) = one_fd(EPOLLIN, POLL_IN, 0, true, true);
        let registration = Arc::clone(&ep.inner.lock().interest[&FD].registration);

        let detached = {
            let mut ready = ep.ready.lock();
            if ready.len != 1 {
                return TestResult::Fail("seeded ready registration must be linked once");
            }
            match ready.pop_front() {
                Some(registration) => registration,
                None => return TestResult::Fail("ready pop must detach the head"),
            }
        };
        if registration.ready_state.load(Ordering::Acquire) != READY_POLLING {
            return TestResult::Fail("detached registration must publish POLLING ownership");
        }

        // Model ep_poll_callback firing while the collector polls `detached`.
        if !ep.list_ready(&registration) {
            return TestResult::Fail("racing callback must requeue an active registration");
        }
        {
            let mut ready = ep.ready.lock();
            if ready.len != 0 || registration.ready_state.load(Ordering::Acquire) != READY_PENDING {
                return TestResult::Fail("racing callback must mark the detached node PENDING");
            }
            ready.finish_poll(&detached, false);
        }
        let raced = {
            let mut ready = ep.ready.lock();
            if ready.len != 1 {
                return TestResult::Fail("poll completion must publish one pending occurrence");
            }
            match ready.pop_front() {
                Some(registration) => registration,
                None => return TestResult::Fail("racing occurrence must remain dequeueable"),
            }
        };
        if !Arc::ptr_eq(&detached, &raced) || !Arc::ptr_eq(&registration, &raced) {
            return TestResult::Fail("detach/requeue must preserve the stable registration node");
        }
        {
            let mut ready = ep.ready.lock();
            ready.finish_poll(&raced, false);
            if !ready.is_empty() || registration.ready_state.load(Ordering::Acquire) != READY_IDLE {
                return TestResult::Fail("second poll completion must retire the occurrence");
            }
        }

        // CTL_DEL must unlink an arbitrary node without scanning the FIFO.
        let file_ops = file as Arc<dyn FileOps>;
        let first = EpollRegistration::new(FD + 1, 2, &file_ops, 0, EPOLLIN, 0);
        let middle = EpollRegistration::new(FD + 2, 3, &file_ops, 0, EPOLLIN, 0);
        let last = EpollRegistration::new(FD + 3, 4, &file_ops, 0, EPOLLIN, 0);
        {
            let mut ready = ep.ready.lock();
            ready.list(&first);
            ready.list(&middle);
            ready.list(&last);
            ready.unlink(&middle);
            if ready.len != 2 || middle.ready_state.load(Ordering::Acquire) != READY_IDLE {
                return TestResult::Fail("middle unlink must remove exactly one node");
            }
            let popped_first = ready.pop_front();
            let popped_last = ready.pop_front();
            if !popped_first
                .as_ref()
                .is_some_and(|item| Arc::ptr_eq(item, &first))
                || !popped_last
                    .as_ref()
                    .is_some_and(|item| Arc::ptr_eq(item, &last))
                || !ready.is_empty()
            {
                return TestResult::Fail("middle unlink must preserve neighboring FIFO links");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_epoll_intrusive_ready_detach_requeue
    );

    /// The scheduler's park recheck calls `epoll_fd_has_ready(task, epfd)` — it
    /// resolves the epoll fd through the task's fd table and must return the
    /// ET-aware `has_deliverable` verdict, NOT the old `poll_readiness() &
    /// POLL_IN` level probe. Those disagree exactly on the two spin-prone shapes
    /// below: the level probe reports "ready", so the recheck answered "don't
    /// park", the re-executed `epoll_wait` delivered nothing, and the task spun
    /// at 100% CPU (the greeter never presented). This pins the CALL SITE, so a
    /// revert back to the level predicate fails here even though the oracle test
    /// above still passes. Installs a real epoll fd because that is the only path
    /// `epoll_fd_has_ready` takes.
    fn smoke_epoll_fd_has_ready_is_et_aware() -> TestResult {
        __test_reset();
        // A task id distinct from the oracle test's TASK so the fd table is
        // fresh; `with_table` seeds stdio at 0/1/2, so installs land at fd 3.
        let task: u64 = 0xE9_02;

        let install = |ep: Arc<EpollInstance>| -> Option<u32> {
            fd::install(
                task,
                crate::fd::FdEntry {
                    ops: ep as Arc<dyn FileOps>,
                    offset: 0,
                    flags: 0,
                    status_flags: crate::fd::O_RDWR,
                },
            )
        };

        // (1) EPOLLIN|ET, edge already consumed (level-readable, last_mask holds
        //     POLL_IN, not on the ready list). `collect_ready` delivers nothing,
        //     so the recheck must say "park". The old predicate returned
        //     `POLL_IN & POLL_IN != 0` == true here → the self-wake spin.
        {
            let (ep, _f) = one_fd(EPOLLIN | EPOLLET, POLL_IN, POLL_IN, true, false);
            let epfd = match install(ep) {
                Some(fd) => fd,
                None => return TestResult::Fail("could not install epoll fd (ET-consumed case)"),
            };
            let ready = epoll_fd_has_ready(task, epfd);
            let _ = fd::with_table(task, |t| t.close(epfd));
            if ready {
                return TestResult::Fail(
                    "ET-consumed IN: epoll_fd_has_ready must be false (level predicate regressed)",
                );
            }
        }

        // (2) Positive control: a level-triggered readable fd IS deliverable, so
        //     the recheck reports ready (re-exec delivers the event, no wasted
        //     park). Guards against over-correcting to "always park".
        {
            let (ep, _f) = one_fd(EPOLLIN, POLL_IN, 0, false, false);
            let epfd = match install(ep) {
                Some(fd) => fd,
                None => return TestResult::Fail("could not install epoll fd (LT case)"),
            };
            let ready = epoll_fd_has_ready(task, epfd);
            let _ = fd::with_table(task, |t| t.close(epfd));
            if !ready {
                return TestResult::Fail("LT readable: epoll_fd_has_ready must be true");
            }
        }

        TestResult::Pass
    }
    kernel_test_in!("userspace/epoll", smoke_epoll_fd_has_ready_is_et_aware);
}
