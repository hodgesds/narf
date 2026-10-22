//! `epoll_create1(2)`, `epoll_ctl(2)`, `epoll_wait(2)` — interest-set
//! based I/O event notification.
//!
//! Linux refs:
//!   `fs/eventpoll.c`:ep_insert / ep_modify / ep_remove / ep_poll
//!   (GPL-2.0-or-later, kernel.org).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};
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
    /// User-requested interest bits.
    events: u32,
    /// Opaque user data echoed back in every event notification.
    data: u64,
    /// Last readiness mask observed — for EPOLLET rising-mask edge detection.
    last_mask: u32,
    /// True once this fd was armed on a durable Readiness cell (its
    /// `arm_readiness_persistent` returned `Some`). Cell-backed fds report
    /// readiness by pushing themselves onto the ready-list via their PERSISTENT
    /// per-fd waker (Linux `eppoll_entry`), armed at `EPOLL_CTL_ADD` and live for
    /// the fd's whole membership, so the fast path polls them only when listed.
    /// Non-cell-backed fds (timerfd / nested epoll / raw / legacy netlink) have
    /// no cell and are always polled (rising-mask edge only).
    cell_backed: bool,
}

impl core::fmt::Debug for EpollSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpollSnapshot")
            .field("fd", &self.registration.fd)
            .field("file_live", &self.file.strong_count().ne(&0))
            .field("offset", &self.offset)
            .field("events", &self.events)
            .field("data", &self.data)
            .field("last_mask", &self.last_mask)
            .finish()
    }
}

/// Hot per-registration state, corresponding to Linux's `struct epitem`
/// readiness linkage. `active` invalidates delayed callbacks after DEL/fd reuse;
/// `queued` is the intrusive-list membership bit. Both are changed while the
/// instance ready lock is held, but atomics let passive readiness queries
/// observe membership without cloning or searching the queue.
#[derive(Debug)]
struct EpollRegistration {
    fd: i32,
    sub_id: u64,
    active: AtomicBool,
    queued: AtomicBool,
    file: Weak<dyn FileOps>,
    offset: u64,
    state: IrqSafeSpinLock<EpollItemState>,
}

#[derive(Copy, Clone, Debug)]
struct EpollItemState {
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
            sub_id,
            active: AtomicBool::new(true),
            queued: AtomicBool::new(false),
            file: Arc::downgrade(file),
            offset,
            state: IrqSafeSpinLock::new(EpollItemState {
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
            events: state.events,
            data: state.data,
            last_mask: state.last_mask,
            cell_backed: state.cell_backed,
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
    /// Last entry returned by a wait. Level-triggered entries remain ready,
    /// so begin the next scan after this fd to match Linux ready-list
    /// round-robin behavior when readiness exceeds `maxevents`.
    scan_after: Option<i32>,
    /// Ready registrations indexed by fd. The sequence changes on every
    /// callback, including callbacks for an already-listed item, so write-back
    /// cannot erase an event that raced the readiness poll.
    ready: BTreeMap<i32, ReadyListing>,
    ready_seq: u64,
    /// Interest fds without a durable readiness cell. These cannot list
    /// themselves, so fast passes merge them with the ready index.
    always_poll: BTreeSet<i32>,
}

#[derive(Clone, Debug)]
struct ReadyListing {
    registration: Arc<EpollRegistration>,
    seq: u64,
}

type ReadyCandidate = (i32, Option<(Arc<EpollRegistration>, u64)>);

impl EpollReady {
    fn list(&mut self, registration: &Arc<EpollRegistration>) -> bool {
        if !registration.active.load(Ordering::Acquire) {
            return false;
        }
        self.ready_seq = self.ready_seq.wrapping_add(1);
        if let Some(listing) = self.ready.get_mut(&registration.fd) {
            if Arc::ptr_eq(&listing.registration, registration) {
                // Already linked: refresh only the race generation. Replacing
                // the whole value would do two contended Arc refcount updates
                // and a needless B-tree value move on every same-level event.
                listing.seq = self.ready_seq;
                registration.queued.store(true, Ordering::Release);
                return true;
            }
        }
        self.ready.insert(
            registration.fd,
            ReadyListing {
                registration: Arc::clone(registration),
                seq: self.ready_seq,
            },
        );
        registration.queued.store(true, Ordering::Release);
        true
    }

    fn unlink(&mut self, registration: &Arc<EpollRegistration>) {
        let matches = self
            .ready
            .get(&registration.fd)
            .is_some_and(|listing| Arc::ptr_eq(&listing.registration, registration));
        if matches {
            self.ready.remove(&registration.fd);
        }
        registration.queued.store(false, Ordering::Release);
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
    parked_wakers: VecDeque<(u64, core::task::Waker)>,
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

    fn unlink_ready(&self, registration: &Arc<EpollRegistration>) {
        self.ready.lock().unlink(registration);
    }

    fn ready_list_empty(&self) -> bool {
        self.ready.lock().ready.is_empty()
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
        // Mirror ep_poll's exclusive, auto-removing wait entry: one event wakes
        // one waiter and takes it off the queue. Move the waker out so wake()
        // runs without either epoll lock held.
        let waiter = if self.has_parked_waiters.load(Ordering::Acquire) {
            let mut waiters = self.waiters.lock();
            let waiter = waiters.parked_wakers.pop_front();
            self.has_parked_waiters
                .store(!waiters.parked_wakers.is_empty(), Ordering::Release);
            waiter
        } else {
            None
        };
        // Chain the wake UP to a parent epoll / poll(2) that watches THIS
        // instance as a nested fd: fire our own cell so its persistent per-fd
        // waker (armed via `arm_readiness_persistent`) runs. `set` covers a
        // rising edge (the first ready child) and `notify` covers a same-level
        // event (a further child while we are already readable) — the same
        // set+notify the AF_UNIX listener uses, and what Linux `ep_poll_safewake`
        // does by walking the nested wait-queue. Skipped unless we are actually
        // nested (`has_nested_parent`) so the direct-wait hot path pays only a
        // relaxed load, not two cell-lock acquisitions per event. Fired OUTSIDE
        // `self.inner` (the cell has its own lock; `wake_by_ref` under it is
        // alloc- and lock-free). See [`EpollInstance::self_readiness`].
        if self
            .has_nested_parent
            .load(core::sync::atomic::Ordering::Relaxed)
        {
            self.self_readiness.set(narf_filesystem::POLL_IN, 0);
            self.self_readiness.notify(narf_filesystem::POLL_IN);
        }
        if let Some((_, waker)) = waiter {
            waker.wake();
        }
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: IrqSafeSpinLock::new(EpollInner {
                interest: BTreeMap::new(),
            }),
            ready: IrqSafeSpinLock::new(EpollReady {
                scan_after: None,
                ready: BTreeMap::new(),
                ready_seq: 0,
                always_poll: BTreeSet::new(),
            }),
            waiters: IrqSafeSpinLock::new(EpollWaiters {
                parked_wakers: VecDeque::new(),
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
                if let Some(item) = &reaped {
                    item.registration.active.store(false, Ordering::Release);
                }
            }
            g.interest.insert(
                fd,
                EpollItem {
                    registration: Arc::clone(&registration),
                },
            );
        }
        if let Some(old) = reaped {
            self.unlink_ready(&old.registration);
            self.ready.lock().always_poll.remove(&fd);
        }
        // Arm the persistent per-fd waker OUTSIDE the instance lock (arming a
        // socket takes its state lock; the cell has its own lock) and seed the
        // ready-list if the fd is already ready (Linux ep_insert's initial poll).
        self.arm_item_persistent(fd, file, epfd_file);
        true
    }

    /// Arm (or re-arm) the persistent per-fd ready-list waker for `fd` on its
    /// Readiness cell, keyed by the item's `sub_id`. Records `cell_backed` and
    /// seeds the ready-list from the returned currently-ready bits. Must be
    /// called with the instance lock NOT held.
    fn arm_item_persistent(&self, fd: i32, file: &Arc<dyn FileOps>, epfd_file: &Arc<dyn FileOps>) {
        let (registration, events) = {
            let g = self.inner.lock();
            match g.interest.get(&fd) {
                Some(it) => {
                    let registration = Arc::clone(&it.registration);
                    let events = registration.state.lock().events;
                    (registration, events)
                }
                None => return,
            }
        };
        let sub_id = registration.sub_id;
        // A disarmed EPOLLONESHOT (interest bits cleared) has nothing to wait on.
        if (events & EPOLLONESHOT) != 0
            && (events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
        {
            return;
        }
        let want = events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
        let interest = want | EPOLLERR | EPOLLHUP;
        let fd_waker = epoll_fd_waker(epfd_file, &registration);
        let armed = file.arm_readiness_persistent(sub_id, interest, &fd_waker);
        let mut seed = false;
        let mut cell_backed = None;
        if registration.active.load(Ordering::Acquire) {
            let mut state = registration.state.lock();
            match armed {
                Some(ready_bits) => {
                    state.cell_backed = true;
                    seed = ready_bits != 0;
                    cell_backed = Some(true);
                }
                None => {
                    state.cell_backed = false;
                    cell_backed = Some(false);
                }
            }
        }
        {
            let mut ready = self.ready.lock();
            match cell_backed {
                Some(true) => {
                    ready.always_poll.remove(&fd);
                }
                Some(false) => {
                    ready.always_poll.insert(fd);
                }
                None => {}
            }
        }
        if seed {
            self.list_ready(&registration);
        }
        let ready_now = !self.ready_list_empty();
        // Keep our OWN cell level in step with the ready-list so a parent that
        // nests us and arms via `arm_readiness_persistent` right after this ADD
        // seeds an accurate initial edge (a child already ready at ADD time). A
        // rising edge here fires any already-armed parent waker (a re-ADD after
        // the set drained), which is correct; a no-op if already level-high.
        // Only when nested (see `push_ready`).
        if ready_now
            && self
                .has_nested_parent
                .load(core::sync::atomic::Ordering::Relaxed)
        {
            self.self_readiness.set(narf_filesystem::POLL_IN, 0);
        }
    }

    /// `EPOLL_CTL_DEL` logic. Disarms the persistent per-fd waker so no stale
    /// entry lingers in the fd's Readiness cell after removal.
    fn ctl_del(&self, fd: i32, file: &Arc<dyn FileOps>, owner_id: u64) -> bool {
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
        item.registration.active.store(false, Ordering::Release);
        self.unlink_ready(&item.registration);
        self.ready.lock().always_poll.remove(&fd);
        exclusive_release(fd, owner_id);
        // Disarm outside both epoll locks.
        file.disarm_readiness(item.registration.sub_id);
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
        {
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
            let mut state = item.registration.state.lock();
            state.events = events;
            state.data = data;
            // Linux re-evaluates the fd against its new mask on every MOD and
            // re-adds it to the ready list if currently ready — so a MOD acts as
            // a fresh edge for EPOLLET (and re-arms EPOLLONESHOT). Reset the
            // rising-mask edge state, exactly as `ctl_add` initializes it, so the
            // next scan treats current readiness as a rising edge.
            state.last_mask = 0;
        }
        // Re-arm the persistent waker with the new interest (replaces by sub_id)
        // and re-seed the ready-list, so a still-ready fd fires a fresh edge —
        // dbus-broker's queued-reply flush depends on this MOD-rearm.
        self.arm_item_persistent(fd, file, epfd_file);
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
                let in_ready = item.cell_backed && item.registration.queued.load(Ordering::Acquire);
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
    fn set_parked_waker(&self, task_id: u64, waker: &core::task::Waker) {
        let mut waiters = self.waiters.lock();
        if let Some(pos) = waiters
            .parked_wakers
            .iter()
            .position(|(parked_task, _)| *parked_task == task_id)
        {
            waiters.parked_wakers.remove(pos);
        }
        waiters.parked_wakers.push_back((task_id, waker.clone()));
        self.has_parked_waiters.store(true, Ordering::Release);
        // See `push_ready`: forbid the readiness recheck from moving before
        // waiter publication, closing the lockless active-gate lost-wake race.
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    /// End-of-wait cleanup: drop the parked-waker publication. The persistent
    /// per-fd cell wakers stay armed (Linux `eppoll_entry`), disarmed only by
    /// CTL_MOD/DEL or this instance's drop.
    fn disarm_readiness_cells(&self, task_id: u64) {
        let mut waiters = self.waiters.lock();
        if let Some(pos) = waiters
            .parked_wakers
            .iter()
            .position(|(parked_task, _)| *parked_task == task_id)
        {
            waiters.parked_wakers.remove(pos);
        }
        self.has_parked_waiters
            .store(!waiters.parked_wakers.is_empty(), Ordering::Release);
    }

    /// Two-tier delivery: a bounded fast pass over the ready-list (+ non-cell
    /// fds), falling back to a full O(n) scan whenever the fast pass delivers
    /// nothing — so an incomplete ready-list can only cost a rescan, never
    /// strand a wake. Persistent per-fd registrations make the ready-list
    /// edge-complete; unlike the old one-shot `arm` scheme, they are never
    /// consumed merely because an fd was already ready.
    fn collect_ready(&self, task_id: u64, maxevents: usize) -> Vec<(u32, u64)> {
        let fast = self.collect_ready_pass(task_id, maxevents, false);
        if !fast.is_empty() {
            return fast;
        }
        self.collect_ready_pass(task_id, maxevents, true)
    }

    fn collect_ready_pass(&self, task_id: u64, maxevents: usize, full: bool) -> Vec<(u32, u64)> {
        let owner_id = task_id; // simplified owner model

        // Candidate snapshot, taken without holding the lock across the
        // poll_readiness() calls (which may themselves lock). Fast pass polls
        // the ready-list (fds whose per-fd waker fired or that were seeded at
        // arm) plus non-cell-backed fds (timerfd / nested / raw / legacy, which
        // have no edge). Full pass (fallback, or before any fd is cell-backed)
        // scans the whole interest set and reseeds the ready-list.
        // Each entry carries `in_ready`: the fd's ready-list (Linux rdllist)
        // membership at snapshot time — a cell-backed fd is listed iff its
        // persistent per-fd waker fired (a `set`/`notify` event) since the last
        // drain. It IS the EPOLLET edge the per-source token used to carry: an fd
        // that is level-ready but not listed has had no fresh event, so EPOLLET
        // must not re-report it. Captured per-entry UNDER the lock. The fast
        // path snapshots only a small maxevents-sized window in ready-list
        // order; later entries stay listed for the next wait, matching Linux's
        // bounded ready-index drain. Each snapshot carries its listing sequence;
        // a callback racing the poll refreshes that sequence, so write-back
        // cannot erase the new event (the role Linux's `ovflist` serves).
        let snapshot: Vec<(i32, EpollSnapshot, Option<u64>)> = if full {
            let (listings, scan_after) = {
                let ready = self.ready.lock();
                (ready.ready.clone(), ready.scan_after)
            };
            let registrations: Vec<_> = self
                .inner
                .lock()
                .interest
                .values()
                .map(|item| Arc::clone(&item.registration))
                .collect();
            let mut entries: Vec<_> = registrations
                .into_iter()
                .filter(|registration| registration.active.load(Ordering::Acquire))
                .map(|registration| {
                    let fd = registration.fd;
                    let listed = listings.get(&fd).and_then(|listing| {
                        Arc::ptr_eq(&listing.registration, &registration).then_some(listing.seq)
                    });
                    (fd, registration.snapshot(), listed)
                })
                .collect();
            if let Some(after) = scan_after {
                if let Some(start) = entries.iter().position(|(fd, _, _)| *fd > after) {
                    entries.rotate_left(start);
                }
            }
            entries
        } else {
            // Snapshot no more candidates than this wait can return. A stale
            // candidate makes the fast pass empty and takes the full fallback.
            let limit = maxevents.max(1);
            let candidates: Vec<ReadyCandidate> = {
                let mut ready = self.ready.lock();
                let mut candidates = Vec::with_capacity(limit);
                let mut append_range = |mut listed: alloc::collections::btree_map::Range<
                    '_,
                    i32,
                    ReadyListing,
                >,
                                        mut always: alloc::collections::btree_set::Range<
                    '_,
                    i32,
                >| {
                    let mut listed_fd = listed.next().map(|(fd, _)| *fd);
                    let mut always_fd = always.next().copied();
                    while candidates.len() < limit && (listed_fd.is_some() || always_fd.is_some()) {
                        let fd = match (listed_fd, always_fd) {
                            (Some(r), Some(a)) if r < a => {
                                listed_fd = listed.next().map(|(fd, _)| *fd);
                                r
                            }
                            (Some(r), Some(a)) if a < r => {
                                always_fd = always.next().copied();
                                a
                            }
                            (Some(r), Some(_)) => {
                                listed_fd = listed.next().map(|(fd, _)| *fd);
                                always_fd = always.next().copied();
                                r
                            }
                            (Some(r), None) => {
                                listed_fd = listed.next().map(|(fd, _)| *fd);
                                r
                            }
                            (None, Some(a)) => {
                                always_fd = always.next().copied();
                                a
                            }
                            (None, None) => break,
                        };
                        let listing = ready
                            .ready
                            .get(&fd)
                            .map(|listing| (Arc::clone(&listing.registration), listing.seq));
                        candidates.push((fd, listing));
                    }
                };
                if let Some(after) = ready.scan_after {
                    use core::ops::Bound::{Excluded, Unbounded};
                    append_range(
                        ready.ready.range((Excluded(after), Unbounded)),
                        ready.always_poll.range((Excluded(after), Unbounded)),
                    );
                    append_range(
                        ready.ready.range(..=after),
                        ready.always_poll.range(..=after),
                    );
                } else {
                    append_range(ready.ready.range(..), ready.always_poll.range(..));
                }
                // Reserve this bounded window before polling it. Linux obtains
                // the same property by splicing rdllist into a private txlist:
                // concurrent harvesters cannot all select the same head item.
                // The entries remain indexed here so callbacks can refresh
                // their sequence while polling runs without this lock.
                if let Some((fd, _)) = candidates.last() {
                    ready.scan_after = Some(*fd);
                }
                candidates
            };

            candidates
                .into_iter()
                .filter_map(|(fd, listing)| {
                    let (registration, seq) = match listing {
                        Some((registration, seq)) => (registration, Some(seq)),
                        None => {
                            let interest = self.inner.lock();
                            (Arc::clone(&interest.interest.get(&fd)?.registration), None)
                        }
                    };
                    if !registration.active.load(Ordering::Acquire) {
                        return None;
                    }
                    let fd = registration.fd;
                    Some((fd, registration.snapshot(), seq))
                })
                .collect()
        };

        let mut results = Vec::new();
        // Preserve the masks from the lock-free poll pass for the state
        // write-back below. Re-polling while holding `self.inner` recursively
        // enters nested epoll instances and permits cross-instance lock-order
        // inversions under concurrent event-loop updates.
        let mut observed = Vec::new();
        let mut delivered_fds = Vec::new();
        for (fd, item, listing) in &snapshot {
            let in_ready = listing.is_some();
            // `maxevents` limits acceptance, not merely userspace copying.
            // Do not poll, acknowledge, advance edge state, take an exclusive
            // claim, or disarm a one-shot entry that this wait cannot return.
            // Such entries must remain pending for the next epoll_wait.
            if results.len() == maxevents {
                break;
            }
            // Disarmed EPOLLONESHOT items (events bitmask zeroed below)
            // are skipped immediately.
            if (item.events & EPOLLONESHOT) != 0
                && (item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
            {
                continue;
            }
            // Query current readiness — polled outside the fd-table lock so a
            // nested-epoll child can't deadlock on it (see poll_fd_readiness).
            // Snapshot the source token before readiness. If I/O races this
            // poll, the token remains pending for the re-poll forced by the
            // global readiness-generation park guard.
            // Single Weak→Arc upgrade per interest fd, reused for the token,
            // readiness, and acknowledge below. Previously each of those did its
            // own `item.file.upgrade()` (2–3 refcount round-trips) plus separate
            // socket-lock acquisitions — the collect_ready O(N) hot path under a
            // large interest set (200-conn redis: poll_readiness + poll_edge_token
            // + Weak::upgrade + irq_restore dominated the kernel profile).
            let file = match item.file.upgrade() {
                Some(f) => f,
                None => {
                    // Backing open file dropped → not ready; record a zero
                    // observation so the write-back clears any stale readiness,
                    // exactly as the previous per-call upgrades did.
                    observed.push((*fd, 0, *listing, Arc::clone(&item.registration)));
                    continue;
                }
            };
            // One provider-lock acquisition per fd for the mask. The EPOLLET edge
            // no longer needs a second (token) lock: the wait-queue edge is the
            // fd's `in_ready` membership, captured under the lock in the snapshot
            // above (Linux ep_send_events drains the rdllist; ep_item_poll only
            // re-confirms the mask).
            let cur_mask = file.poll_readiness_at(item.offset);
            observed.push((*fd, cur_mask, *listing, Arc::clone(&item.registration)));
            // Only report events the caller asked for.
            let want = item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
            // Linux always reports ERR/HUP even when the caller omitted them
            // from the interest mask. D-Bus and other event loops commonly
            // request only EPOLLIN|EPOLLOUT and rely on this rule to classify
            // a disconnected transport instead of treating it as ordinary
            // readable data.
            let ready = cur_mask & (want | EPOLLERR | EPOLLHUP);
            if ready == 0 {
                continue;
            }

            // EPOLLET: report only on a fresh edge. Two edge sources, matching
            // Linux: (1) a rising mask bit (`ready & !last_mask`) covers a level
            // transition and every non-cell-backed source (timerfd / nested epoll
            // / legacy netlink, always full-scanned); (2) ready-list membership
            // covers a same-level event on a cell-backed source (a second
            // datagram / accept / RX byte while the mask stays POLL_IN — the
            // persistent wait-queue waker listed it). Level-ready but neither
            // newly-risen nor listed = no event since last drain, so not
            // re-reported.
            if (item.events & EPOLLET) != 0 {
                let new_bits = ready & !item.last_mask;
                let listed = item.cell_backed && in_ready;
                if new_bits == 0 && !listed {
                    continue;
                }
            }

            // EPOLLEXCLUSIVE: claim or skip.
            if (item.events & EPOLLEXCLUSIVE) != 0 && !exclusive_try_claim(*fd, owner_id) {
                continue;
            }

            // Some readiness sources carry a per-open-file change edge.
            // Consume it only after this epoll has accepted the event for
            // delivery. `EpollInstance::poll_readiness()` is intentionally a
            // passive query for nested epolls and therefore never performs
            // this acknowledgement; otherwise systemd's manager epoll can
            // steal libmount's mountinfo event before libmount drains it.
            //
            // The edge bits the acknowledgement retired are no longer part of
            // the level this item has seen: record the post-delivery mask
            // (Linux's `mounts_poll` likewise consumes the namespace event as
            // it reports it). Otherwise a second change landing before any
            // undelivered rescan finds PRI|ERR already in `last_mask`, the
            // EPOLLET rising-bit test never fires again, and libmount's
            // mountinfo monitor (EPOLLIN|EPOLLET) goes deaf for the rest of
            // the boot — systemd then fails every later mount unit with
            // "Mount process finished, but there is no mount."
            let consumed = file.acknowledge_poll_readiness(cur_mask);
            if consumed != 0 {
                if let Some(entry) = observed.last_mut() {
                    entry.1 &= !consumed;
                }
            }
            results.push((ready, item.data));
            delivered_fds.push(*fd);
        }

        // Write back the masks observed above; never invoke FileOps callbacks
        // while holding this instance's non-reentrant spin lock.
        let ready_updates = {
            let mut updates = Vec::with_capacity(observed.len());
            for (fd, cur_mask, in_ready, registration) in observed {
                // Ready-list bookkeeping (Linux rdllist): a level-triggered fd
                // that was delivered stays a candidate so the next wait
                // re-reports it until the app drains (its next poll then shows
                // not-ready and drops it). Edge-triggered / oneshot consume the
                // edge, and an observed-but-not-delivered fd (no edge / drained)
                // is no longer live — both drop from the list.
                let keep_ready;
                let mut disarm_always_poll = false;
                if registration.active.load(Ordering::Acquire) {
                    let mut state = registration.state.lock();
                    if !registration.active.load(Ordering::Acquire) {
                        continue;
                    }
                    if delivered_fds.contains(&fd) {
                        // Delivered to the caller — the EPOLLET edge (ready-list
                        // listing) is now consumed, so advance the recorded mask
                        // and drop the listing for ET/oneshot.
                        state.last_mask = cur_mask;
                        keep_ready =
                            state.cell_backed && (state.events & (EPOLLET | EPOLLONESHOT)) == 0;
                        if (state.events & EPOLLONESHOT) != 0 {
                            // Clear all event-interest bits; keep flags.
                            state.events &= EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE;
                            disarm_always_poll = !state.cell_backed;
                        }
                    } else {
                        // Observed but NOT delivered (an EPOLLET item with no
                        // fresh edge, a not-ready fd, or an EPOLLEXCLUSIVE claim
                        // lost to another epoll). Re-arm by clearing readiness
                        // bits that have dropped so a later rising edge still
                        // fires. A cell-backed EPOLLET fd that WAS listed (had a
                        // wait-queue edge) but lost an exclusive claim keeps its
                        // listing so the still-pending edge is delivered on the
                        // next scan — this preserves the AF_UNIX socket-activation
                        // acceptor (dbus-broker / journald) whose accept thread
                        // races its epoll thread; the token used to hold that edge.
                        state.last_mask &= cur_mask;
                        keep_ready = state.cell_backed
                            && (state.events & EPOLLET) != 0
                            && in_ready.is_some();
                    }
                    updates.push((
                        fd,
                        Arc::clone(&registration),
                        in_ready,
                        keep_ready,
                        disarm_always_poll,
                    ));
                }
            }
            updates
        };
        let needs_full_cursor = full && !delivered_fds.is_empty();
        let needs_ready_write = needs_full_cursor
            || ready_updates.iter().any(
                |(_, registration, listing, keep_ready, disarm_always_poll)| {
                    *disarm_always_poll
                        || (*keep_ready && !registration.queued.load(Ordering::Acquire))
                        || (!*keep_ready && listing.is_some())
                },
            );
        if needs_ready_write {
            let mut ready = self.ready.lock();
            for (fd, registration, listing, keep_ready, disarm_always_poll) in ready_updates {
                if disarm_always_poll {
                    ready.always_poll.remove(&fd);
                }
                // The dominant level-triggered case stays linked. It already
                // advanced per-registration state above and needs no ready-tree
                // mutation, so do not bounce the global ready lock's cache line
                // merely to rediscover the existing entry.
                if keep_ready && registration.queued.load(Ordering::Acquire) {
                    continue;
                }
                let current = ready
                    .ready
                    .get(&fd)
                    .filter(|current| Arc::ptr_eq(&current.registration, &registration));
                if keep_ready {
                    if current.is_none() {
                        ready.list(&registration);
                    }
                } else if listing.is_some() && current.map(|current| current.seq) == listing {
                    ready.ready.remove(&fd);
                    registration.queued.store(false, Ordering::Release);
                }
            }
            // Fast passes reserve their position at snapshot time so another
            // waiter selects a different window. A full fallback has no such
            // reservation and advances from the last event actually returned.
            if needs_full_cursor {
                if let Some(fd) = delivered_fds.last() {
                    ready.scan_after = Some(*fd);
                }
            }
        }

        // Reconcile our OWN cell level for a parent that nests us: once the
        // ready-list has drained we are no longer level-readable, so clear the
        // cell. Clearing is a falling edge — wake-free (`set` ignores it) — so a
        // parent is never spuriously woken; a still-non-empty ready-list leaves
        // the cell high so a freshly-arming parent seeds an accurate initial
        // edge. `push_ready` re-raises it on the next child event. This runs
        // only when THIS instance is waited on directly; for the purely-nested
        // case the parent's `poll_readiness` query is authoritative regardless.
        if self
            .has_nested_parent
            .load(core::sync::atomic::Ordering::Relaxed)
            && self.ready_list_empty()
        {
            self.self_readiness.set(0, narf_filesystem::POLL_IN);
        }

        results
    }

    /// Would `collect_ready` deliver at least one event to `task_id` right now?
    /// Mirrors [`Self::collect_ready_pass`]'s per-fd delivery decision EXACTLY
    /// — same readiness source, EPOLLONESHOT/EPOLLET edge, and EPOLLEXCLUSIVE
    /// ownership — but takes NO action: no `last_mask` advance, no ready-list
    /// drain, no exclusive claim. A full scan (the superset of the fast pass),
    /// so it is true iff either `collect_ready` pass would deliver.
    ///
    /// This is the correct predicate for the register-then-recheck self-wake at
    /// park. Linux `ep_poll` rechecks with `ep_events_available()` — the SAME
    /// ready-list that `ep_try_send_events` drains (fs/eventpoll.c) — so the
    /// recheck and the delivery agree and a park cannot self-wake forever.
    /// [`Self::poll_readiness`] is the WRONG predicate here: it deliberately
    /// omits the EPOLLEXCLUSIVE claim (a passive nested-epoll / `poll(2)` query
    /// must not claim), so a readable EPOLLEXCLUSIVE fd owned by another epoll
    /// makes `poll_readiness` report ready while `collect_ready` delivers
    /// nothing — the park recheck then self-wakes on every re-execution, a
    /// 100%-CPU `epoll_wait` livelock (kwin's greeter never presented).
    fn has_deliverable(&self, task_id: u64) -> bool {
        let snapshot: Vec<(i32, EpollSnapshot, bool)> = {
            let g = self.inner.lock();
            g.interest
                .iter()
                .map(|(k, v)| {
                    (
                        *k,
                        v.registration.snapshot(),
                        v.registration.queued.load(Ordering::Acquire),
                    )
                })
                .collect()
        };
        for (fd, item, in_ready) in snapshot {
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
                let listed = item.cell_backed && in_ready;
                if new_bits == 0 && !listed {
                    continue;
                }
            }
            // EPOLLEXCLUSIVE: `collect_ready` skips an fd this task cannot claim
            // (held by another epoll). Mirror that as a non-claiming query so
            // the recheck never self-wakes on an fd that would not deliver here.
            if (item.events & EPOLLEXCLUSIVE) != 0 && exclusive_owned_by_other(fd, task_id) {
                continue;
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
        let registrations: Vec<_> = self
            .inner
            .lock()
            .interest
            .values()
            .map(|item| Arc::clone(&item.registration))
            .collect();
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
        // Snapshot the interest set and release our own lock BEFORE
        // polling the children: a child poll re-enters `fd::with_table`
        // (and, if epolls are nested deeper, another
        // `EpollInstance::poll_readiness`), so holding any lock across
        // it risks the same re-entrant deadlock the outer epoll path
        // hit. See `poll_fd_readiness`.
        // Per-entry ready-list membership is carried by the registration, so
        // the passive nested-epoll query never clones or searches the queue.
        let snapshot: Vec<(EpollSnapshot, bool)> = {
            let g = self.inner.lock();
            g.interest
                .values()
                .map(|v| {
                    (
                        v.registration.snapshot(),
                        v.registration.queued.load(Ordering::Acquire),
                    )
                })
                .collect()
        };
        for (item, in_ready) in snapshot {
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
            // (The EPOLLEXCLUSIVE claim is deliberately NOT mirrored — a
            // readiness QUERY must not claim the fd.)
            if (events & EPOLLET) != 0
                && (ready & !last_mask) == 0
                && !(item.cell_backed && in_ready)
            {
                continue;
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
            .load(core::sync::atomic::Ordering::Relaxed)
        {
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
            .store(true, core::sync::atomic::Ordering::Relaxed);
        Some(self.self_readiness.arm_persistent(id, interest, waker))
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
            .store(true, core::sync::atomic::Ordering::Relaxed);
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
            item.registration.active.store(false, Ordering::Release);
            if let Some(file) = item.registration.file.upgrade() {
                file.disarm_readiness(item.registration.sub_id);
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
    fd::with_table(task, |t| t.get(epfd).map(|e| e.ops.clone())).flatten()
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
    // last_mask already holds the bit) or an EPOLLEXCLUSIVE fd this task cannot
    // claim. `collect_ready` correctly delivers nothing for those, so the level
    // predicate made the recheck answer "ready, don't park" while the re-executed
    // `epoll_wait` delivered zero events — park_should_block returns false, the
    // task never yields, and it re-scans forever: a 100%-CPU `epoll_wait` livelock
    // that needed NO wake to sustain (every readiness wake path stays quiet). On
    // the CachyOS desktop this pinned dbus-broker / systemd event loops and the
    // greeter never presented. `has_deliverable` mirrors `collect_ready`'s per-fd
    // ET / EPOLLEXCLUSIVE decision, so the recheck and the delivery agree and the
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

// ── Exclusive wakeup registry ────────────────────────────────────────

static EXCLUSIVE_HOLDERS: IrqSafeSpinLock<Option<BTreeMap<i32, u64>>> = IrqSafeSpinLock::new(None);

fn exclusive_try_claim(fd: i32, owner: u64) -> bool {
    let mut g = EXCLUSIVE_HOLDERS.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    if let Some(h) = map.get(&fd) {
        if *h == owner {
            return true;
        }
        return false;
    }
    map.insert(fd, owner);
    true
}

fn exclusive_release(fd: i32, owner: u64) {
    let mut g = EXCLUSIVE_HOLDERS.lock();
    if let Some(map) = g.as_mut() {
        if let Some(h) = map.get(&fd) {
            if *h == owner {
                map.remove(&fd);
            }
        }
    }
}

/// Non-claiming query: is `fd`'s EPOLLEXCLUSIVE claim held by an owner OTHER
/// than `owner`? `collect_ready` skips such an fd (its `exclusive_try_claim`
/// fails), so the park-time deliverability recheck must skip it too — without
/// taking the claim (a readiness *query* must not claim). Distinct from
/// [`exclusive_try_claim`], which claims an unheld fd.
fn exclusive_owned_by_other(fd: i32, owner: u64) -> bool {
    let g = EXCLUSIVE_HOLDERS.lock();
    match g.as_ref().and_then(|m| m.get(&fd)) {
        Some(h) => *h != owner,
        None => false,
    }
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
            if instance.ctl_del(tfd, &target_ops, task) {
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
            for (i, (events, data)) in ready[..n].iter().enumerate() {
                if write_epoll_event(
                    events_ptr as u64 + (i * EPOLL_EVENT_SIZE) as u64,
                    *events,
                    *data,
                )
                .is_err()
                {
                    restore(task, mask_active);
                    // The array was access_ok'd above; a fault here is a
                    // racing unmap, and `ep_send_events` reports it as -EFAULT.
                    ctx.set_return(to_ret(EFAULT));
                    return;
                }
            }
            restore(task, mask_active);
            instance.disarm_readiness_cells(task);
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
                instance.disarm_readiness_cells(task);
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
                            instance.disarm_readiness_cells(task);
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
                            instance.set_parked_waker(task, &w);
                            // Register-then-recheck — closes the collect_ready ->
                            // park lost-wake window. A fd whose persistent waker
                            // fired push_ready AFTER the top collect_ready but
                            // BEFORE set_parked_waker listed it on the ready-list
                            // with no parked waker to wake; without this recheck
                            // the park would STRAND. `has_deliverable(task)`
                            // non-destructively mirrors collect_ready's EXACT
                            // delivery decision (owner-aware for EPOLLEXCLUSIVE);
                            // if it now reports deliverable, self-wake so the park
                            // re-executes and delivers. It must be `has_deliverable`
                            // and NOT `poll_readiness()`: the latter omits the
                            // EPOLLEXCLUSIVE claim (correct for a passive nested
                            // query, wrong here), so a readable exclusive fd owned
                            // by another epoll would make poll_readiness report
                            // ready while collect_ready delivers nothing — a park
                            // self-wake livelock (100%-CPU epoll_wait). Because
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

/// Clear the exclusive-wakeup holders. Test hook. (Instances need no
/// reset — they live and die with their fd-table entries.)
#[doc(hidden)]
pub fn __test_reset() {
    *EXCLUSIVE_HOLDERS.lock() = Some(BTreeMap::new());
}

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
            ep.ready.lock().always_poll.insert(FD);
        }
        if in_ready {
            ep.list_ready(&registration);
        }
        (ep, file)
    }

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

        // (4) EPOLLEXCLUSIVE|IN readable but the claim is held by ANOTHER owner:
        //     collect_ready skips it, so the recheck must too. This is the exact
        //     `poll_readiness` divergence that caused the exclusive self-wake spin
        //     (poll_readiness omits the claim and would report ready here).
        {
            let (ep, _f) = one_fd(EPOLLIN | EPOLLEXCLUSIVE, POLL_IN, 0, false, false);
            if !exclusive_try_claim(FD, TASK ^ 0xFF) {
                return TestResult::Fail("could not seed a foreign exclusive claim");
            }
            if ep.has_deliverable(TASK) {
                return TestResult::Fail("exclusive-owned-by-other: has_deliverable must be false");
            }
            if !ep.collect_ready(TASK, 8).is_empty() {
                return TestResult::Fail("exclusive-owned-by-other: collect_ready must be empty");
            }
            __test_reset();
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
        ep.set_parked_waker(0xA0, &test_waker(0));
        ep.set_parked_waker(0xA1, &test_waker(1));
        ep.set_parked_waker(0xA2, &test_waker(2));

        // Re-parking a task replaces only its own slot and moves it to the
        // queue tail, just like Linux removing and re-adding a wait entry.
        ep.set_parked_waker(0xA0, &test_waker(0));
        if ep.waiters.lock().parked_wakers.len() != 3 {
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
        if !ep.waiters.lock().parked_wakers.is_empty() {
            return TestResult::Fail("woken epoll waiters must be auto-removed");
        }
        __test_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/epoll",
        smoke_epoll_push_ready_wakes_one_parked_waiter_per_event
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

        // (2) EPOLLEXCLUSIVE|IN readable but the claim is held by ANOTHER owner:
        //     `collect_ready` skips it, so the recheck must too. `poll_readiness`
        //     omits the claim and would report POLL_IN here → the exclusive spin.
        {
            let (ep, _f) = one_fd(EPOLLIN | EPOLLEXCLUSIVE, POLL_IN, 0, false, false);
            if !exclusive_try_claim(FD, task ^ 0xFF) {
                return TestResult::Fail("could not seed a foreign exclusive claim");
            }
            let epfd = match install(ep) {
                Some(fd) => fd,
                None => return TestResult::Fail("could not install epoll fd (exclusive case)"),
            };
            let ready = epoll_fd_has_ready(task, epfd);
            let _ = fd::with_table(task, |t| t.close(epfd));
            __test_reset();
            if ready {
                return TestResult::Fail(
                    "exclusive-owned-by-other: epoll_fd_has_ready must be false",
                );
            }
        }

        // (3) Positive control: a level-triggered readable fd IS deliverable, so
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
