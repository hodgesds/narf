//! `epoll_create1(2)`, `epoll_ctl(2)`, `epoll_wait(2)` — interest-set
//! based I/O event notification.
//!
//! Linux refs:
//!   `fs/eventpoll.c`:ep_insert / ep_modify / ep_remove / ep_poll
//!   (GPL-2.0-or-later, kernel.org).
//!
//! # Architecture
//!
//! An `EpollInstance` is a `FileOps` object that holds:
//!   - an *interest table*: `BTreeMap<i32, EpollItem>` mapping
//!     monitored fds to their desired event mask + opaque user data.
//!
//! `epoll_wait` scans the interest table, computes current readiness
//! for each fd, handles EPOLLET edge detection and EPOLLONESHOT
//! disarming, and copies results out to user space.
//!
//! # Downcast pattern
//!
//! `FileOps` is defined in `narf-filesystem` which we cannot touch.
//! We resolve `epfd → EpollInstance` via a global registry keyed by
//! `(task_id, fd_number)` — set when `epoll_create1` installs the fd
//! and cleared when the fd is closed.  This avoids any need to add
//! `Any`/downcast methods to `FileOps`.
//!
//! # Level vs Edge triggered
//!
//! Level-triggered (default): an fd is reported on every `epoll_wait`
//! that finds it ready.
//!
//! Edge-triggered (`EPOLLET`): an fd is reported only on a transition
//! from not-ready → ready.  We track `last_mask` per item.
//!
//! # EPOLLONESHOT
//!
//! After first delivery the item's events field is cleared; must
//! be re-armed via `epoll_ctl(MOD)`.
//!
//! # EPOLLEXCLUSIVE
//!
//! Only one epoll instance returns an event for a given fd when
//! multiple instances monitor it.  Implemented via a global
//! `EXCLUSIVE_HOLDERS` table.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use crate::fd;
use crate::syscall::{SyscallReturn, TrapContext};
use crate::handlers::current_task_id;

// ── epoll event flag constants ───────────────────────────────────────
// Matches Linux `<sys/epoll.h>` (GPL-2.0-or-later, kernel.org).

/// Data available to read.
pub const EPOLLIN: u32       = 0x00000001;
/// Urgent (out-of-band) data.
pub const EPOLLPRI: u32      = 0x00000002;
/// Ready to write.
pub const EPOLLOUT: u32      = 0x00000004;
/// Stream peer half-closed (read half).
pub const EPOLLRDHUP: u32    = 0x00002000;
/// Error condition.
pub const EPOLLERR: u32      = 0x00000008;
/// Hang-up / peer closed.
pub const EPOLLHUP: u32      = 0x00000010;
/// Edge-triggered: notify only on transitions.
pub const EPOLLET: u32       = 0x80000000;
/// One-shot: disarm after first event.
pub const EPOLLONESHOT: u32  = 0x40000000;
/// Exclusive wakeup (avoid thundering herd on accept).
pub const EPOLLEXCLUSIVE: u32 = 0x10000000;

/// epoll_ctl operations.
pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

/// `EPOLL_CLOEXEC` flag for `epoll_create1`.
pub const EPOLL_CLOEXEC: u32 = 0x80000;

// ── Wire layout: struct epoll_event ─────────────────────────────────
// Packed on Linux x86_64: u32 events + u64 data = 12 bytes.
const EPOLL_EVENT_SIZE: usize = 12;

/// Read a user-supplied `epoll_event` struct (12 bytes).
///
/// # Safety
/// `ptr` must point to at least 12 readable bytes in the current AS.
unsafe fn read_epoll_event(ptr: *const u8) -> (u32, u64) {
    // SAFETY: caller guarantees 12 readable bytes.
    let events = unsafe { core::ptr::read_unaligned(ptr as *const u32) };
    let data   = unsafe { core::ptr::read_unaligned(ptr.add(4) as *const u64) };
    (events, data)
}

/// Write an `epoll_event` struct to user memory.
///
/// # Safety
/// `ptr` must point to at least 12 writable bytes in the current AS.
unsafe fn write_epoll_event(ptr: *mut u8, events: u32, data: u64) {
    // SAFETY: caller guarantees 12 writable bytes.
    unsafe {
        core::ptr::write_unaligned(ptr as *mut u32, events);
        core::ptr::write_unaligned(ptr.add(4) as *mut u64, data);
    }
}

// ── EpollItem — per-fd interest record ──────────────────────────────

#[derive(Clone, Debug)]
struct EpollItem {
    /// Desired event mask (EPOLLIN | EPOLLOUT | …) + flag bits.
    events: u32,
    /// Opaque user data echoed back in every event notification.
    data: u64,
    /// Last readiness mask observed — for EPOLLET edge detection.
    last_mask: u32,
}

// ── EPOLLEXCLUSIVE global holder map ─────────────────────────────────
// Maps monitored fd → owning epoll instance id so only one waiter
// wins per fd when EPOLLEXCLUSIVE is set.

static EXCLUSIVE_HOLDERS: IrqSafeSpinLock<Option<BTreeMap<i32, usize>>> =
    IrqSafeSpinLock::new(None);

fn exclusive_init() {
    let mut g = EXCLUSIVE_HOLDERS.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

fn exclusive_try_claim(fd: i32, owner_id: usize) -> bool {
    let mut g = EXCLUSIVE_HOLDERS.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => return true,
    };
    match m.get(&fd) {
        None    => { m.insert(fd, owner_id); true }
        Some(&id) => id == owner_id,
    }
}

fn exclusive_release(fd: i32, owner_id: usize) {
    let mut g = EXCLUSIVE_HOLDERS.lock();
    if let Some(m) = g.as_mut() {
        if m.get(&fd) == Some(&owner_id) {
            m.remove(&fd);
        }
    }
}

// ── Global epoll instance registry ───────────────────────────────────
//
// Keyed by `(task_id, epfd)`.  Set when `epoll_create1` installs a
// new fd; cleared when `close()` drops the FdEntry (today we clean
// up lazily — if the fd number is re-used we just overwrite the
// old entry in the registry).

static EPOLL_INSTANCES: IrqSafeSpinLock<Option<BTreeMap<(u64, u32), Arc<EpollInstance>>>> =
    IrqSafeSpinLock::new(None);

fn instances_init() {
    let mut g = EPOLL_INSTANCES.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

fn instances_insert(task: u64, epfd: u32, inst: Arc<EpollInstance>) {
    instances_init();
    if let Some(m) = EPOLL_INSTANCES.lock().as_mut() {
        m.insert((task, epfd), inst);
    }
}

fn instances_lookup(task: u64, epfd: u32) -> Option<Arc<EpollInstance>> {
    EPOLL_INSTANCES.lock().as_ref()?.get(&(task, epfd)).cloned()
}

fn instances_remove(task: u64, epfd: u32) {
    if let Some(m) = EPOLL_INSTANCES.lock().as_mut() {
        m.remove(&(task, epfd));
    }
}

// ── EpollInstance ─────────────────────────────────────────────────────

/// The kernel-side object backing an epoll fd.
#[derive(Debug)]
pub struct EpollInstance {
    /// Stable unique id — the Arc raw pointer cast to usize.
    id: usize,
    inner: IrqSafeSpinLock<EpollInner>,
}

#[derive(Debug)]
struct EpollInner {
    interest: BTreeMap<i32, EpollItem>,
}

impl EpollInstance {
    fn new() -> Arc<Self> {
        // Build an initial Arc with id=0, then patch the id field to
        // the Arc's pointer value (stable unique identity).
        let arc = Arc::new(Self {
            id: 0,
            inner: IrqSafeSpinLock::new(EpollInner {
                interest: BTreeMap::new(),
            }),
        });
        let id = Arc::as_ptr(&arc) as usize;
        // SAFETY: the Arc has refcount 1 and is not yet shared.
        // We write the id field via a raw pointer while we hold
        // the only reference to make the object self-describing.
        unsafe {
            let ptr = Arc::as_ptr(&arc) as *mut EpollInstance;
            (*ptr).id = id;
        }
        arc
    }

    fn self_id(self: &Arc<Self>) -> usize {
        Arc::as_ptr(self) as usize
    }

    // ── interest-table ops ──────────────────────────────────────────

    fn ctl_add(&self, fd: i32, events: u32, data: u64) -> bool {
        let mut g = self.inner.lock();
        if g.interest.contains_key(&fd) {
            return false; // EEXIST
        }
        g.interest.insert(fd, EpollItem { events, data, last_mask: 0 });
        true
    }

    fn ctl_mod(&self, fd: i32, events: u32, data: u64) -> bool {
        let mut g = self.inner.lock();
        if let Some(item) = g.interest.get_mut(&fd) {
            item.events    = events;
            item.data      = data;
            item.last_mask = 0; // reset edge-tracking for re-arm
            true
        } else {
            false // ENOENT
        }
    }

    fn ctl_del(&self, fd: i32, owner_id: usize) -> bool {
        let mut g = self.inner.lock();
        if g.interest.remove(&fd).is_some() {
            exclusive_release(fd, owner_id);
            true
        } else {
            false // ENOENT
        }
    }

    // ── readiness scan ──────────────────────────────────────────────

    /// Scan the interest table against the fd table for `task_id`.
    /// Returns ready events as `(revents_u32, user_data_u64)`.
    ///
    /// Handles EPOLLET (edge), EPOLLONESHOT (auto-disarm),
    /// EPOLLEXCLUSIVE (single-winner).
    ///
    /// Linux ref: `fs/eventpoll.c`:ep_send_events_proc
    /// (GPL-2.0-or-later, kernel.org).
    fn collect_ready(self: &Arc<Self>, task_id: u64) -> Vec<(u32, u64)> {
        let mut results = Vec::new();
        let owner_id = self.self_id();

        // Snapshot interest table so we don't hold the lock across
        // the poll_readiness() calls (which may themselves lock).
        let snapshot: Vec<(i32, EpollItem)> = {
            self.inner.lock()
                .interest
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect()
        };

        for (fd, item) in &snapshot {
            // EPOLLONESHOT already fired: skip until re-armed.
            if (item.events & EPOLLONESHOT) != 0
                && (item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
            {
                continue;
            }

            // Query current readiness from the fd table.
            let cur_mask: u32 = fd::with_table(task_id, |t| {
                t.get(*fd as u32)
                    .map(|e| e.ops.poll_readiness())
                    .unwrap_or(0)
            })
            .unwrap_or(0);

            // Only report events the caller asked for.
            let want  = item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
            let ready = cur_mask & want;
            if ready == 0 {
                continue;
            }

            // EPOLLET: only report on rising edge.
            if (item.events & EPOLLET) != 0 {
                let new_bits = ready & !item.last_mask;
                if new_bits == 0 {
                    continue;
                }
            }

            // EPOLLEXCLUSIVE: claim or skip.
            if (item.events & EPOLLEXCLUSIVE) != 0 {
                if !exclusive_try_claim(*fd, owner_id) {
                    continue;
                }
            }

            results.push((ready, item.data));
        }

        // Write back updated last_mask; disarm EPOLLONESHOT items.
        {
            let mut g = self.inner.lock();
            for (fd, item_snap) in &snapshot {
                if let Some(item) = g.interest.get_mut(fd) {
                    let cur_mask: u32 = fd::with_table(task_id, |t| {
                        t.get(*fd as u32)
                            .map(|e| e.ops.poll_readiness())
                            .unwrap_or(0)
                    })
                    .unwrap_or(0);
                    item.last_mask = cur_mask;

                    if (item_snap.events & EPOLLONESHOT) != 0 {
                        let delivered = results.iter().any(|(_, d)| *d == item.data);
                        if delivered {
                            // Clear all event-interest bits; keep flags.
                            item.events &= EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE;
                        }
                    }
                }
            }
        }

        results
    }
}

// ── FileOps for EpollInstance ─────────────────────────────────────────

impl FileOps for EpollInstance {
    fn read<'a>(&'a self, _off: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _off: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }
    fn poll_readiness(&self) -> u32 {
        // epoll fds are themselves "readable" when any watched fd
        // is ready — we don't eagerly compute this to avoid holding
        // locks inside poll_readiness.
        0
    }
}

// ── sys_epoll_create1 ─────────────────────────────────────────────────

/// `epoll_create1(flags)` → fd
///
/// - arg0 = flags (EPOLL_CLOEXEC = 0x80000 sets FD_CLOEXEC on the fd)
///
/// Returns the new epoll fd, or -1 on failure.
///
/// Linux ref: `fs/eventpoll.c`:SYSCALL_DEFINE1(epoll_create1, …)
/// (GPL-2.0-or-later, kernel.org).
pub fn sys_epoll_create1(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0 as u32;
    let fail  = SyscallReturn::ok((-1i64) as u64);
    let task  = current_task_id();

    exclusive_init();
    instances_init();

    let instance = EpollInstance::new();
    let ops: Arc<dyn FileOps> = instance.clone();
    let cloexec = if (flags & EPOLL_CLOEXEC) != 0 { crate::fd::FD_CLOEXEC } else { 0 };

    let new_fd = fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry { ops, offset: 0, flags: cloexec })
    });

    match new_fd {
        Some(fd) => {
            instances_insert(task, fd, instance);
            ctx.set_return(SyscallReturn::ok(fd as u64));
        }
        None => ctx.set_return(fail),
    }
}

// ── sys_epoll_ctl ─────────────────────────────────────────────────────

/// `epoll_ctl(epfd, op, fd, &event)` → 0 or -1
///
/// - arg0 = epfd (the epoll instance fd)
/// - arg1 = op (EPOLL_CTL_ADD=1, EPOLL_CTL_DEL=2, EPOLL_CTL_MOD=3)
/// - arg2 = target fd to add/modify/remove from the interest set
/// - arg3 = ptr to `struct epoll_event` (12 bytes; 0 acceptable for DEL)
///
/// Linux ref: `fs/eventpoll.c`:SYSCALL_DEFINE4(epoll_ctl, …)
/// (GPL-2.0-or-later, kernel.org).
pub fn sys_epoll_ctl(ctx: &mut dyn TrapContext) {
    let args   = *ctx.args();
    let epfd   = args.arg0 as u32;
    let op     = args.arg1 as u32;
    let tfd    = args.arg2 as i32;
    let ev_ptr = args.arg3 as *const u8;
    let fail   = SyscallReturn::ok((-1i64) as u64);
    let task   = current_task_id();

    let instance = match instances_lookup(task, epfd) {
        Some(i) => i,
        None    => { ctx.set_return(fail); return; }
    };

    let owner_id = instance.self_id();

    match op {
        EPOLL_CTL_ADD => {
            if ev_ptr.is_null() { ctx.set_return(fail); return; }
            // SAFETY: user pointer; 12 bytes.
            let (events, data) = unsafe { read_epoll_event(ev_ptr) };
            if instance.ctl_add(tfd, events, data) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(fail); // EEXIST
            }
        }
        EPOLL_CTL_MOD => {
            if ev_ptr.is_null() { ctx.set_return(fail); return; }
            let (events, data) = unsafe { read_epoll_event(ev_ptr) };
            if instance.ctl_mod(tfd, events, data) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(fail); // ENOENT
            }
        }
        EPOLL_CTL_DEL => {
            if instance.ctl_del(tfd, owner_id) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(fail); // ENOENT
            }
        }
        _ => ctx.set_return(fail),
    }
}

// ── sys_epoll_wait ─────────────────────────────────────────────────────

/// `epoll_wait(epfd, events_out, maxevents, timeout_ms)` → n or -1
///
/// - arg0 = epfd
/// - arg1 = ptr to output array of `struct epoll_event` (12 bytes each)
/// - arg2 = maxevents (max results to return in one call)
/// - arg3 = timeout_ms (-1 = block, 0 = nonblock, >0 = bounded wait)
///
/// Returns the number of events placed in the output array,
/// 0 on timeout, or -1 on error.
///
/// Linux ref: `fs/eventpoll.c`:SYSCALL_DEFINE4(epoll_wait, …)
/// (GPL-2.0-or-later, kernel.org).
pub fn sys_epoll_wait(ctx: &mut dyn TrapContext) {
    let args       = *ctx.args();
    let epfd       = args.arg0 as u32;
    let events_ptr = args.arg1 as *mut u8;
    let maxevents  = args.arg2 as usize;
    let timeout_ms = args.arg3 as i64;
    let fail       = SyscallReturn::ok((-1i64) as u64);
    let task       = current_task_id();

    if events_ptr.is_null() || maxevents == 0 {
        ctx.set_return(fail);
        return;
    }

    let instance = match instances_lookup(task, epfd) {
        Some(i) => i,
        None    => { ctx.set_return(fail); return; }
    };

    let deadline_ns: Option<u64> = if timeout_ms == 0 {
        Some(0)
    } else if timeout_ms > 0 {
        Some(
            narf_scheduler::narf_time::monotonic_ns()
                .saturating_add((timeout_ms as u64) * 1_000_000),
        )
    } else {
        None
    };

    loop {
        let ready = instance.collect_ready(task);
        let n = ready.len().min(maxevents);
        if n > 0 {
            // SAFETY: user pointer; n * EPOLL_EVENT_SIZE writable bytes.
            for (i, (events, data)) in ready[..n].iter().enumerate() {
                unsafe {
                    write_epoll_event(
                        events_ptr.add(i * EPOLL_EVENT_SIZE),
                        *events,
                        *data,
                    );
                }
            }
            ctx.set_return(SyscallReturn::ok(n as u64));
            return;
        }

        match deadline_ns {
            Some(0) => {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            Some(d) => {
                let now = narf_scheduler::narf_time::monotonic_ns();
                if now >= d {
                    ctx.set_return(SyscallReturn::ok(0));
                    return;
                }
                narf_scheduler::sleep_pumps::run();
                core::hint::spin_loop();
            }
            None => {
                narf_scheduler::sleep_pumps::run();
                core::hint::spin_loop();
            }
        }
    }
}

// ── Test reset ───────────────────────────────────────────────────────

/// Clear the epoll instance registry + exclusive holders. Test hook.
#[doc(hidden)]
pub fn __test_reset() {
    *EPOLL_INSTANCES.lock()    = Some(BTreeMap::new());
    *EXCLUSIVE_HOLDERS.lock()  = Some(BTreeMap::new());
}
