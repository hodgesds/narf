//! `epoll_create1(2)`, `epoll_ctl(2)`, `epoll_wait(2)` — interest-set
//! based I/O event notification.
//!
//! Linux refs:
//!   `fs/eventpoll.c`:ep_insert / ep_modify / ep_remove / ep_poll
//!   (GPL-2.0-or-later, kernel.org).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::Ordering;
use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

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
    fd: i32,
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
    /// Globally-unique key of this subscription's persistent waiter in the fd's
    /// Readiness cell (top bit set to never collide with a task-id-keyed poll(2)
    /// waiter). Used to `disarm` exactly this epoll's waker on CTL_MOD/DEL/close
    /// without disturbing another epoll or a blocking poll on the same fd.
    sub_id: u64,
}

impl core::fmt::Debug for EpollItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpollItem")
            .field("fd", &self.fd)
            .field("file_live", &self.file.strong_count().ne(&0))
            .field("offset", &self.offset)
            .field("events", &self.events)
            .field("data", &self.data)
            .field("last_mask", &self.last_mask)
            .finish()
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
    inner: IrqSafeSpinLock<EpollInner>,
}

#[derive(Debug)]
struct EpollInner {
    /// fd → interest record.
    interest: BTreeMap<i32, EpollItem>,
    /// Last entry returned by a wait. Level-triggered entries remain ready,
    /// so begin the next scan after this fd to match Linux ready-list
    /// round-robin behavior when readiness exceeds `maxevents`.
    scan_after: Option<i32>,
    /// Fds whose durable cell fired an edge since the last drain (Linux
    /// `ep->rdllist`). Populated by the per-fd wakers and by arm-time seeding.
    /// The fast path polls these (plus non-cell-backed fds); a full O(n) scan is
    /// the fallback whenever the fast pass delivers nothing, so an incomplete
    /// list is only ever a missed optimization, never a stranded wake.
    ready: BTreeSet<i32>,
    /// The currently-parked poller's waker, woken when a per-fd waker lists a
    /// ready fd. Set at park, cleared on return.
    parked_waker: Option<core::task::Waker>,
    /// collect_ready call counter for the periodic full-scan floor. The
    /// ready-list can under-report a cell-backed fd that became ready while the
    /// poller was between waits (the Readiness cell removes a waiter when `arm`
    /// returns Ready, so a busy poller that rarely re-arms can miss a later
    /// edge). The fast-then-full fallback only rescans when the fast pass is
    /// EMPTY; under saturating load some fd is always ready, so the fast pass
    /// never empties and a starved connection would never be revisited. Forcing
    /// a full O(n) scan every `FULL_SCAN_EVERY` waits bounds that starvation to
    /// a few waits — O(ready) amortized, O(n) worst-case, never worse.
    scan_ctr: u32,
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
fn poll_item_readiness(item: &EpollItem) -> u32 {
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
    fd: i32,
}

fn efw_fire(w: &EpollFdWake) {
    if let Some(ops) = w.ep.upgrade() {
        if let Some(inst) = as_epoll(&ops) {
            inst.push_ready(w.fd);
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

fn epoll_fd_waker(epfd_file: &Arc<dyn FileOps>, fd: i32) -> core::task::Waker {
    let arc = Arc::new(EpollFdWake {
        ep: Arc::downgrade(epfd_file),
        fd,
    });
    let raw = Arc::into_raw(arc) as *const ();
    // SAFETY: `raw` + `EPOLL_FD_VTABLE` form a valid RawWaker over Arc<EpollFdWake>.
    unsafe { core::task::Waker::from_raw(core::task::RawWaker::new(raw, &EPOLL_FD_VTABLE)) }
}

impl EpollInstance {
    /// List `fd` as ready (its per-fd waker fired) and wake the parked poller.
    /// No-op if `fd` left the interest set.
    fn push_ready(&self, fd: i32) {
        let waker = {
            let mut g = self.inner.lock();
            if !g.interest.contains_key(&fd) {
                return;
            }
            g.ready.insert(fd);
            g.parked_waker.clone()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: IrqSafeSpinLock::new(EpollInner {
                interest: BTreeMap::new(),
                scan_after: None,
                ready: BTreeSet::new(),
                parked_waker: None,
                scan_ctr: 0,
            }),
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
        {
            let mut g = self.inner.lock();
            if let Some(existing) = g.interest.get(&fd) {
                if existing.file.upgrade().is_some() {
                    return false; // EEXIST
                }
                // Linux removes an epoll interest when the watched open file's
                // last descriptor closes. Lazily reap the equivalent dead Weak
                // entry so a subsequently reused fd number can be added. Its
                // cell (if any) died with the file, so its waiter is already gone.
                g.interest.remove(&fd);
            }
            g.interest.insert(
                fd,
                EpollItem {
                    fd,
                    file: Arc::downgrade(file),
                    offset,
                    events,
                    data,
                    last_mask: 0,
                    cell_backed: false,
                    sub_id: next_sub_id(),
                },
            );
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
        let (sub_id, events) = {
            let g = self.inner.lock();
            match g.interest.get(&fd) {
                Some(it) => (it.sub_id, it.events),
                None => return,
            }
        };
        // A disarmed EPOLLONESHOT (interest bits cleared) has nothing to wait on.
        if (events & EPOLLONESHOT) != 0
            && (events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
        {
            return;
        }
        let want = events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
        let interest = want | EPOLLERR | EPOLLHUP;
        let fd_waker = epoll_fd_waker(epfd_file, fd);
        let armed = file.arm_readiness_persistent(sub_id, interest, &fd_waker);
        let mut g = self.inner.lock();
        let mut seed = false;
        if let Some(it) = g.interest.get_mut(&fd) {
            match armed {
                Some(ready_bits) => {
                    it.cell_backed = true;
                    seed = ready_bits != 0;
                }
                None => it.cell_backed = false,
            }
        }
        if seed {
            g.ready.insert(fd);
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
                .and_then(|item| item.file.upgrade())
                .is_some_and(|watched| Arc::ptr_eq(&watched, file));
            let removed = if matches {
                g.interest.remove(&fd)
            } else {
                None
            };
            if let Some(item) = &removed {
                g.ready.remove(&fd);
                exclusive_release(fd, owner_id);
                let sub = item.sub_id;
                drop(g);
                // Disarm the persistent waiter outside the instance lock.
                file.disarm_readiness(sub);
            }
            removed.is_some()
        };
        removed
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
            let mut g = self.inner.lock();
            let Some(item) = g.interest.get_mut(&fd) else {
                return false; // ENOENT
            };
            let same_file = item
                .file
                .upgrade()
                .is_some_and(|watched| Arc::ptr_eq(&watched, file));
            if !same_file {
                return false;
            }
            item.events = events;
            item.data = data;
            // Linux re-evaluates the fd against its new mask on every MOD and
            // re-adds it to the ready list if currently ready — so a MOD acts as
            // a fresh edge for EPOLLET (and re-arms EPOLLONESHOT). Reset the
            // rising-mask edge state, exactly as `ctl_add` initializes it, so the
            // next scan treats current readiness as a rising edge.
            item.last_mask = 0;
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
        let (snapshot, ready_set): (Vec<(i32, EpollItem)>, alloc::collections::BTreeSet<i32>) = {
            let g = self.inner.lock();
            (
                g.interest.iter().map(|(k, v)| (*k, v.clone())).collect(),
                g.ready.clone(),
            )
        };
        snapshot
            .into_iter()
            .map(|(fd, item)| {
                let cur_mask = poll_item_readiness(&item);
                let want = item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
                let ready = cur_mask & (want | EPOLLERR | EPOLLHUP);
                let in_ready = item.cell_backed && ready_set.contains(&fd);
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
    fn set_parked_waker(&self, waker: &core::task::Waker) {
        self.inner.lock().parked_waker = Some(waker.clone());
    }

    /// End-of-wait cleanup: drop the parked-waker publication. The persistent
    /// per-fd cell wakers stay armed (Linux `eppoll_entry`), disarmed only by
    /// CTL_MOD/DEL or this instance's drop.
    fn disarm_readiness_cells(&self, _task_id: u64) {
        self.inner.lock().parked_waker = None;
    }

    /// Two-tier delivery: a fast O(ready) pass over the ready-list (+ non-cell
    /// fds), falling back to a full O(n) scan whenever the fast pass delivers
    /// nothing — so an incomplete ready-list can only cost a rescan, never
    /// strand a wake. Under load the fast pass delivers and the full scan is
    /// never reached; worst case is O(n), never worse.
    fn collect_ready(&self, task_id: u64, maxevents: usize) -> Vec<(u32, u64)> {
        // Periodic full-scan floor: every FULL_SCAN_EVERY-th wait, scan the
        // whole interest set so a cell-backed fd the ready-list under-reported
        // (a later edge lost after `arm` removed its waiter under saturating
        // load) is revisited within a bounded number of waits — no connection
        // can starve. Cheap under load (1-in-N is O(n); the rest O(ready)).
        const FULL_SCAN_EVERY: u32 = 8;
        let force_full = {
            let mut g = self.inner.lock();
            g.scan_ctr = g.scan_ctr.wrapping_add(1);
            g.scan_ctr % FULL_SCAN_EVERY == 0
        };
        if !force_full {
            let fast = self.collect_ready_pass(task_id, maxevents, false);
            if !fast.is_empty() {
                return fast;
            }
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
        // `ready_set` is the ready-list (Linux rdllist) membership at snapshot
        // time: a cell-backed fd is listed iff its persistent per-fd waker fired
        // (a `set`/`notify` event) since the last drain. It IS the EPOLLET edge
        // the per-source token used to carry — an fd that is level-ready but not
        // listed has had no fresh event, so EPOLLET must not re-report it.
        let (snapshot, ready_set): (Vec<(i32, EpollItem)>, alloc::collections::BTreeSet<i32>) = {
            let g = self.inner.lock();
            let any_cell = g.interest.values().any(|it| it.cell_backed);
            let mut entries: Vec<_> = if full || !any_cell {
                g.interest.iter().map(|(k, v)| (*k, v.clone())).collect()
            } else {
                g.interest
                    .iter()
                    .filter(|(fd, it)| g.ready.contains(fd) || !it.cell_backed)
                    .map(|(k, v)| (*k, v.clone()))
                    .collect()
            };
            if let Some(after) = g.scan_after {
                // Linux moves a delivered level-triggered item to the tail of
                // its ready list. Rotating this rescan has the same observable
                // fairness: successive short waits visit later ready fds.
                if let Some(start) = entries.iter().position(|(fd, _)| *fd > after) {
                    entries.rotate_left(start);
                }
            }
            (entries, g.ready.clone())
        };

        let mut results = Vec::new();
        // Preserve the masks from the lock-free poll pass for the state
        // write-back below. Re-polling while holding `self.inner` recursively
        // enters nested epoll instances and permits cross-instance lock-order
        // inversions under concurrent event-loop updates.
        let mut observed = Vec::new();
        let mut delivered_fds = Vec::new();
        for (fd, item) in &snapshot {
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
                    observed.push((*fd, 0));
                    continue;
                }
            };
            // One provider-lock acquisition per fd for the mask. The EPOLLET edge
            // no longer needs a second (token) lock: the wait-queue edge is the
            // fd's membership in `ready_set`, captured lock-free from the snapshot
            // above (Linux ep_send_events drains the rdllist; ep_item_poll only
            // re-confirms the mask).
            let cur_mask = file.poll_readiness_at(item.offset);
            observed.push((*fd, cur_mask));
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
                let listed = item.cell_backed && ready_set.contains(fd);
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
            file.acknowledge_poll_readiness(cur_mask);
            results.push((ready, item.data));
            delivered_fds.push(*fd);
        }

        // Write back the masks observed above; never invoke FileOps callbacks
        // while holding this instance's non-reentrant spin lock.
        {
            let mut g = self.inner.lock();
            for (fd, cur_mask) in observed {
                // Ready-list bookkeeping (Linux rdllist): a level-triggered fd
                // that was delivered stays a candidate so the next wait
                // re-reports it until the app drains (its next poll then shows
                // not-ready and drops it). Edge-triggered / oneshot consume the
                // edge, and an observed-but-not-delivered fd (no edge / drained)
                // is no longer live — both drop from the list.
                let mut keep_ready = false;
                if let Some(item) = g.interest.get_mut(&fd) {
                    if delivered_fds.contains(&fd) {
                        // Delivered to the caller — the EPOLLET edge (ready-list
                        // listing) is now consumed, so advance the recorded mask
                        // and drop the listing for ET/oneshot.
                        item.last_mask = cur_mask;
                        keep_ready =
                            item.cell_backed && (item.events & (EPOLLET | EPOLLONESHOT)) == 0;
                        if (item.events & EPOLLONESHOT) != 0 {
                            // Clear all event-interest bits; keep flags.
                            item.events &= EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE;
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
                        item.last_mask &= cur_mask;
                        keep_ready = item.cell_backed
                            && (item.events & EPOLLET) != 0
                            && ready_set.contains(&fd);
                    }
                }
                if keep_ready {
                    g.ready.insert(fd);
                } else {
                    g.ready.remove(&fd);
                }
            }
            if let Some(fd) = delivered_fds.last() {
                g.scan_after = Some(*fd);
            }
        }

        results
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
        let items: Vec<EpollItem> = self.inner.lock().interest.values().cloned().collect();
        let mut earliest: Option<u64> = None;
        for item in items {
            if let Some(d) = item.file.upgrade().and_then(|o| o.poll_deadline()) {
                earliest = Some(earliest.map_or(d, |e| e.min(d)));
            }
        }
        earliest
    }
}

impl FileOps for EpollInstance {
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
        let (snapshot, ready_set): (Vec<EpollItem>, alloc::collections::BTreeSet<i32>) = {
            let g = self.inner.lock();
            (g.interest.values().cloned().collect(), g.ready.clone())
        };
        for item in snapshot {
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
                && !(item.cell_backed && ready_set.contains(&item.fd))
            {
                continue;
            }
            return narf_filesystem::POLL_IN;
        }
        0
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
            if let Some(file) = item.file.upgrade() {
                file.disarm_readiness(item.sub_id);
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
    epoll_ops(task, epfd).is_some_and(|ops| ops.poll_readiness() & narf_filesystem::POLL_IN != 0)
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
        let Some(ops) = item.file.upgrade() else {
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
        None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
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
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
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
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
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
    const EBADF: SyscallReturn = SyscallReturn::ok((-9i64) as u64);
    const EFAULT: SyscallReturn = SyscallReturn::ok((-14i64) as u64);
    const EEXIST: SyscallReturn = SyscallReturn::ok((-17i64) as u64);
    const EINVAL: SyscallReturn = SyscallReturn::ok((-22i64) as u64);
    const EPERM: SyscallReturn = SyscallReturn::ok((-1i64) as u64);
    const ENOENT: SyscallReturn = SyscallReturn::ok((-2i64) as u64);
    const ELOOP: SyscallReturn = SyscallReturn::ok((-40i64) as u64);
    let task = current_task_id();

    // `SYSCALL_DEFINE4(epoll_ctl)` imports the event word before anything
    // else, so a faulting `event` outranks even a closed epfd.
    let event = if op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD {
        if ev_ptr.is_null() {
            ctx.set_return(EFAULT);
            return;
        }
        match read_epoll_event(ev_ptr as u64) {
            Ok(v) => Some(v),
            Err(_) => {
                ctx.set_return(EFAULT);
                return;
            }
        }
    } else {
        None
    };

    let ops = match epoll_ops(task, epfd) {
        Some(o) => o,
        None => {
            ctx.set_return(EBADF);
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
            ctx.set_return(EBADF);
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
        ctx.set_return(EPERM);
        return;
    }
    // Both "epfd names itself" and "epfd is not an epoll" are -EINVAL, and
    // Linux checks them only after both descriptors resolve. The comparison
    // is on the open file description (`fd_file(f) == fd_file(tf)`), not the
    // descriptor number, so a dup() of epfd is caught too.
    if Arc::ptr_eq(&ops, &target_ops) {
        ctx.set_return(EINVAL);
        return;
    }
    let instance = match as_epoll(&ops) {
        Some(i) => i,
        None => {
            ctx.set_return(EINVAL);
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
                    ctx.set_return(ELOOP);
                    return;
                }
            }
            if instance.ctl_add(tfd, &target_ops, target_offset, events, data, &ops) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(EEXIST);
            }
        }
        EPOLL_CTL_MOD => {
            let (events, data) = event.expect("MOD imported its event above");
            if instance.ctl_mod(tfd, &target_ops, events, data, &ops) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(ENOENT);
            }
        }
        EPOLL_CTL_DEL => {
            if instance.ctl_del(tfd, &target_ops, task) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(ENOENT);
            }
        }
        _ => ctx.set_return(EINVAL),
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
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
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
    const EBADF: SyscallReturn = SyscallReturn::ok((-9i64) as u64);
    const EFAULT: SyscallReturn = SyscallReturn::ok((-14i64) as u64);
    const EINVAL: SyscallReturn = SyscallReturn::ok((-22i64) as u64);
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
    let mut old_mask = None;
    if is_pwait && sigmask_ptr != 0 {
        if sigsetsize != 8 {
            ctx.set_return(EINVAL);
            return;
        }
        let mut buf = [0u8; 8];
        // SAFETY: sigsetsize == 8 checked above; copy_from_user range-validates
        // `sigmask_ptr` and SMAP-brackets the read into `buf`.
        if unsafe { crate::handlers::copy_from_user(&mut buf, sigmask_ptr) }.is_ok() {
            let mask = u64::from_ne_bytes(buf); // user sigset_t == NARF N-1 layout
            old_mask = Some(crate::handlers::set_signal_mask_for_task(task, mask));
        } else {
            ctx.set_return(EFAULT);
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
    let restore = |task: u64, old_mask: Option<u64>| {
        if let Some(old) = old_mask {
            crate::handlers::set_signal_mask_for_task(task, old);
        }
    };

    // Resolve through the fd table (NOT a creating-thread registry) so a
    // CLONE_FILES sibling, a dup'd fd, or a fork-inherited epfd all wait
    // on the same instance `poll(2)` sees — see `epoll_ops`.
    let ops = match epoll_ops(task, epfd) {
        Some(o) => o,
        None => {
            restore(task, old_mask);
            ctx.set_return(EBADF);
            return;
        }
    };
    // `maxevents` is an `int`; the register's upper half is not part of it.
    if maxevents <= 0 || maxevents > EP_MAX_EVENTS {
        restore(task, old_mask);
        ctx.set_return(EINVAL);
        return;
    }
    // access_ok over the WHOLE output array, before any of it is written.
    let span = (maxevents as usize).saturating_mul(EPOLL_EVENT_SIZE);
    if crate::handlers::validate_user_range(events_ptr as u64, span).is_err() {
        restore(task, old_mask);
        ctx.set_return(EFAULT);
        return;
    }
    let instance = match as_epoll(&ops) {
        Some(i) => i,
        None => {
            restore(task, old_mask);
            ctx.set_return(EINVAL); // not an epoll fd
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
                    restore(task, old_mask);
                    // The array was access_ok'd above; a fault here is a
                    // racing unmap, and `ep_send_events` reports it as -EFAULT.
                    ctx.set_return(EFAULT);
                    return;
                }
            }
            if let Some(old) = old_mask {
                crate::handlers::set_signal_mask_for_task(task, old);
            }
            instance.disarm_readiness_cells(task);
            ctx.set_return(SyscallReturn::ok(n as u64));
            return;
        }

        match deadline_ns {
            Some(0) => {
                if let Some(old) = old_mask {
                    crate::handlers::set_signal_mask_for_task(task, old);
                }
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
                if let Some(old) = old_mask {
                    crate::handlers::set_signal_mask_for_task(task, old);
                }
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
                        // Check for signals. If delivered, return -EINTR.
                        if let Some(h) = crate::signal_delivery_hook() {
                            if h(ctx, crate::Syscall::EpollWait.raw()) {
                                // Signal delivered. Interrupt syscall with EINTR.
                                instance.disarm_readiness_cells(task);
                                if let Some(old) = old_mask {
                                    crate::handlers::set_signal_mask_for_task(task, old);
                                }
                                ctx.set_return(SyscallReturn::ok((-4i64) as u64));
                                // SAFETY: `uctx_ptr` is the in-flight task's
                                // `UserTaskCtx` from `CURRENT`, live for this trap;
                                // `sleep_deadline_ns` is an atomic field, so the
                                // store needs only a valid pointer.
                                // SAFETY: Valid memory or trusted environment
                                unsafe {
                                    (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release);
                                    (*uctx_ptr).blocking_deadline_ns.store(0, Ordering::Release);
                                };
                                return;
                            }
                        }

                        // epoll_pwait: restore the caller's signal mask before we
                        // park. This syscall re-executes from the top on resume
                        // (RIP rewind below), which re-applies the pwait sigmask and
                        // re-snapshots the "old" mask. If we left the pwait mask
                        // applied across the park, that re-snapshot would capture
                        // the ALREADY-modified mask and the caller's original would
                        // be lost permanently. (The pre-park signal check above
                        // already ran with the pwait mask applied.)
                        if let Some(old) = old_mask {
                            crate::handlers::set_signal_mask_for_task(task, old);
                        }
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
                            instance.set_parked_waker(&w);
                            // Register-then-recheck — closes the collect_ready ->
                            // park lost-wake window. A fd whose persistent waker
                            // fired push_ready AFTER the top collect_ready but
                            // BEFORE set_parked_waker listed it on the ready-list
                            // with no parked waker to wake; without this recheck
                            // the park would STRAND. `poll_readiness()`
                            // non-destructively mirrors collect_ready's delivery
                            // filters; if it now reports deliverable, self-wake so
                            // the park re-executes and delivers. Mirrored filters
                            // mean a benign always-writable EPOLLOUT or an
                            // already-consumed EPOLLET edge does NOT trigger, so
                            // this cannot spin.
                            if instance.poll_readiness() != 0 {
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
                            if let Some(timer_dl) = instance.nearest_poll_deadline(task) {
                                let cur = uc.sleep_deadline_ns.load(Ordering::Acquire);
                                let clamped = if cur == 0 {
                                    timer_dl
                                } else {
                                    cur.min(timer_dl)
                                };
                                uc.sleep_deadline_ns.store(clamped, Ordering::Release);
                            }
                            // Rewind RIP so we re-execute epoll_wait on resume.
                            ctx.set_rip(ctx.rip().wrapping_sub(2));
                            ctx.save_user_state(uc.state.get() as *mut u8);
                            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                            if own_stack {
                                crate::handlers::own_stack_block(ctx);
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
