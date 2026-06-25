//! `epoll_create1(2)`, `epoll_ctl(2)`, `epoll_wait(2)` — interest-set
//! based I/O event notification.
//!
//! Linux refs:
//!   `fs/eventpoll.c`:ep_insert / ep_modify / ep_remove / ep_poll
//!   (GPL-2.0-or-later, kernel.org).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
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

#[derive(Clone, Debug)]
struct EpollItem {
    fd: i32,
    /// User-requested interest bits.
    events: u32,
    /// Opaque user data echoed back in every event notification.
    data: u64,
    /// Last readiness mask observed — for EPOLLET edge detection.
    last_mask: u32,
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
fn poll_fd_readiness(task_id: u64, fd: i32) -> u32 {
    if fd < 0 {
        return 0;
    }
    let ops = fd::with_table(task_id, |t| t.get(fd as u32).map(|e| e.ops.clone())).flatten();
    ops.map(|o| o.poll_readiness()).unwrap_or(0)
}

impl EpollInstance {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: IrqSafeSpinLock::new(EpollInner {
                interest: BTreeMap::new(),
            }),
        })
    }

    /// `EPOLL_CTL_ADD` logic.
    fn ctl_add(&self, fd: i32, events: u32, data: u64) -> bool {
        let mut g = self.inner.lock();
        if g.interest.contains_key(&fd) {
            return false; // EEXIST
        }
        g.interest.insert(
            fd,
            EpollItem {
                fd,
                events,
                data,
                last_mask: 0,
            },
        );
        true
    }

    /// `EPOLL_CTL_DEL` logic.
    fn ctl_del(&self, fd: i32, owner_id: u64) -> bool {
        let mut g = self.inner.lock();
        let removed = g.interest.remove(&fd).is_some();
        if removed {
            exclusive_release(fd, owner_id);
        }
        removed
    }

    /// `EPOLL_CTL_MOD` logic.
    fn ctl_mod(&self, fd: i32, events: u32, data: u64) -> bool {
        let mut g = self.inner.lock();
        if let Some(item) = g.interest.get_mut(&fd) {
            item.events = events;
            item.data = data;
            true
        } else {
            false // ENOENT
        }
    }

    /// Return a vector of (events, data) pairs for ready fds.
    /// Consults the current fd-table for each interest item.
    fn collect_ready(&self, task_id: u64) -> Vec<(u32, u64)> {
        let owner_id = task_id; // simplified owner model

        // Snapshot interest table so we don't hold the lock across
        // the poll_readiness() calls (which may themselves lock).
        let snapshot: Vec<(i32, EpollItem)> = {
            self.inner
                .lock()
                .interest
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect()
        };

        let mut results = Vec::new();
        for (fd, item) in &snapshot {
            // Disarmed EPOLLONESHOT items (events bitmask zeroed below)
            // are skipped immediately.
            if (item.events & EPOLLONESHOT) != 0
                && (item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
            {
                continue;
            }
            // Query current readiness — polled outside the fd-table lock so a
            // nested-epoll child can't deadlock on it (see poll_fd_readiness).
            let cur_mask: u32 = poll_fd_readiness(task_id, *fd);

            // Only report events the caller asked for.
            let want = item.events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
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
            if (item.events & EPOLLEXCLUSIVE) != 0 && !exclusive_try_claim(*fd, owner_id) {
                continue;
            }

            results.push((ready, item.data));
        }

        // Write back updated last_mask; disarm EPOLLONESHOT items.
        {
            let mut g = self.inner.lock();
            for (fd, item_snap) in &snapshot {
                if let Some(item) = g.interest.get_mut(fd) {
                    let cur_mask: u32 = poll_fd_readiness(task_id, *fd);
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

    /// Earliest absolute monotonic-ns deadline at which any fd in the
    /// interest set will become readable on its own timed schedule (a
    /// `timerfd`). Returns `None` when no interest fd is time-driven.
    ///
    /// A parked `epoll_wait` consults this to clamp its scheduler wake-up:
    /// timerfd expiries don't fire a readiness *notify*, so without this a
    /// timerfd armed in an epoll set with an infinite timeout would never
    /// wake the waiter (it parks forever) — the dead-repaint-loop failure.
    fn nearest_poll_deadline(&self, task_id: u64) -> Option<u64> {
        let fds: Vec<i32> = self.inner.lock().interest.keys().copied().collect();
        let mut earliest: Option<u64> = None;
        for fd in fds {
            if fd < 0 {
                continue;
            }
            let dl = fd::with_table(task_id, |t| {
                t.get(fd as u32).and_then(|e| e.ops.poll_deadline())
            })
            .flatten();
            if let Some(d) = dl {
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

    /// epoll-readiness for nested epoll. Returns POLL_IN if any
    /// interests are currently satisfied.
    fn poll_readiness(&self) -> u32 {
        // Snapshot (fd, events) and release our own lock BEFORE polling the
        // children: a child poll re-enters `fd::with_table` (and, if epolls
        // are nested deeper, another `EpollInstance::poll_readiness`), so
        // holding any lock across it risks the same re-entrant deadlock the
        // outer epoll path hit. See `poll_fd_readiness`.
        let snapshot: Vec<(i32, u32)> = {
            let g = self.inner.lock();
            g.interest.values().map(|it| (it.fd, it.events)).collect()
        };
        let task = current_task_id();
        let mut mask = 0;
        for (fd, events) in snapshot {
            if (poll_fd_readiness(task, fd) & events) != 0 {
                mask |= narf_filesystem::POLL_IN;
            }
        }
        mask
    }
}

// ── Registry — (task_id, fd) → instance ──────────────────────────────
// In real Linux the instance is an `anon_inode` file and may be
// shared across fork or sent via SCM_RIGHTS. NARF Stage 4 stubs it
// as a global registry keyed by the creator's task id + the fd
// number.
/// Registry map: `(task_id, epfd)` → epoll instance.
type EpollRegistry = BTreeMap<(u64, u32), Arc<EpollInstance>>;
static EPOLL_INSTANCES: IrqSafeSpinLock<Option<EpollRegistry>> = IrqSafeSpinLock::new(None);

fn instances_lookup(task: u64, epfd: u32) -> Option<Arc<EpollInstance>> {
    EPOLL_INSTANCES.lock().as_ref()?.get(&(task, epfd)).cloned()
}

fn instances_insert(task: u64, epfd: u32, instance: Arc<EpollInstance>) {
    let mut g = EPOLL_INSTANCES.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert((task, epfd), instance);
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

pub fn sys_epoll_create1(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let flags = args.arg0 as u32;
    let cloexec = (flags & crate::fd::O_CLOEXEC) != 0;
    let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
    let fail = SyscallReturn::ok((-1i64) as u64);

    let instance = EpollInstance::new();
    let ops = instance.clone() as Arc<dyn FileOps>;

    let task = current_task_id();
    let new_fd = fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: install_flags,
            status_flags: 0,
        })
    });

    match new_fd {
        Some(fd) => {
            instances_insert(task, fd, instance);
            ctx.set_return(SyscallReturn::ok(fd as u64));
        }
        None => ctx.set_return(fail),
    }
}

pub fn sys_epoll_ctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let op = args.arg1 as u32;
    let tfd = args.arg2 as i32;
    let ev_ptr = args.arg3 as *const u8;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();

    let instance = match instances_lookup(task, epfd) {
        Some(i) => i,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    match op {
        EPOLL_CTL_ADD => {
            if ev_ptr.is_null() {
                ctx.set_return(fail);
                return;
            }
            let (events, data) = match read_epoll_event(ev_ptr as u64) {
                Ok(v) => v,
                Err(_) => {
                    ctx.set_return(fail);
                    return;
                }
            };
            if instance.ctl_add(tfd, events, data) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(fail); // EEXIST
            }
        }
        EPOLL_CTL_MOD => {
            if ev_ptr.is_null() {
                ctx.set_return(fail);
                return;
            }
            let (events, data) = match read_epoll_event(ev_ptr as u64) {
                Ok(v) => v,
                Err(_) => {
                    ctx.set_return(fail);
                    return;
                }
            };
            if instance.ctl_mod(tfd, events, data) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(fail); // ENOENT
            }
        }
        EPOLL_CTL_DEL => {
            if instance.ctl_del(tfd, task) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(fail); // ENOENT
            }
        }
        _ => ctx.set_return(fail),
    }
}

pub fn sys_epoll_pwait(ctx: &mut dyn TrapContext) {
    epoll_wait_common(ctx, true);
}

#[allow(clippy::never_loop)]
pub fn sys_epoll_wait(ctx: &mut dyn TrapContext) {
    epoll_wait_common(ctx, false);
}

#[allow(clippy::never_loop)]
fn epoll_wait_common(ctx: &mut dyn TrapContext, is_pwait: bool) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let events_ptr = args.arg1 as *mut u8;
    let maxevents = args.arg2 as usize;
    let timeout_ms = args.arg3 as i32;
    let sigmask_ptr = args.arg4;
    let sigsetsize = args.arg5;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();

    let mut old_mask = None;
    if is_pwait && sigmask_ptr != 0 && sigsetsize == 8 {
        let mut buf = [0u8; 8];
        // SAFETY: sigsetsize == 8 checked above; copy_from_user range-validates
        // `sigmask_ptr` and SMAP-brackets the read into `buf`.
        if unsafe { crate::handlers::copy_from_user(&mut buf, sigmask_ptr) }.is_ok() {
            let mask = (u64::from_ne_bytes(buf) << 1) as u32;
            old_mask = Some(crate::handlers::set_signal_mask_for_task(task, mask));
        } else {
            ctx.set_return(fail);
            return;
        }
    }

    if events_ptr.is_null() || maxevents == 0 {
        if let Some(old) = old_mask {
            crate::handlers::set_signal_mask_for_task(task, old);
        }
        ctx.set_return(fail);
        return;
    }

    let instance = match instances_lookup(task, epfd) {
        Some(i) => i,
        None => {
            if let Some(old) = old_mask {
                crate::handlers::set_signal_mask_for_task(task, old);
            }
            ctx.set_return(fail);
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
            // Snapshot the net readiness generation BEFORE the
            // readiness check below, so the poll routine can detect a
            // notify that races our check→park window.
            (*uctx_ptr)
                .epoll_park_gen
                .store(narf_net::readiness::generation(), Ordering::Release);
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
                let persisted = uctx.sleep_deadline_ns.load(Ordering::Acquire);
                if persisted != 0 && persisted != u64::MAX {
                    Some(persisted)
                } else {
                    let d = narf_scheduler::narf_time::monotonic_ns()
                        .saturating_add((timeout_ms as u64) * 1_000_000);
                    uctx.sleep_deadline_ns.store(d, Ordering::Release);
                    Some(d)
                }
            } else {
                uctx.sleep_deadline_ns.store(u64::MAX, Ordering::Release);
                None
            }
        }
    };

    loop {
        let ready = instance.collect_ready(task);
        let n = ready.len().min(maxevents);
        if n > 0 {
            if let Some(uctx_ptr) = uctx_opt {
                // SAFETY: `uctx_ptr` is the in-flight task's `UserTaskCtx` from
                // `CURRENT`, live for this trap; `sleep_deadline_ns` is an atomic
                // field, so the store needs only a valid pointer.
                // SAFETY: Valid memory or trusted environment
                unsafe { (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release) };
            }
            for (i, (events, data)) in ready[..n].iter().enumerate() {
                if write_epoll_event(
                    events_ptr as u64 + (i * EPOLL_EVENT_SIZE) as u64,
                    *events,
                    *data,
                )
                .is_err()
                {
                    if let Some(old) = old_mask {
                        crate::handlers::set_signal_mask_for_task(task, old);
                    }
                    ctx.set_return(fail);
                    return;
                }
            }
            if let Some(old) = old_mask {
                crate::handlers::set_signal_mask_for_task(task, old);
            }
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
                if let Some(uctx_ptr) = uctx_opt {
                    // SAFETY: `uctx_ptr` is the in-flight task's `UserTaskCtx` from
                    // `CURRENT`, live for this trap; `sleep_deadline_ns` is an
                    // atomic field, so the store needs only a valid pointer.
                    // SAFETY: Valid memory or trusted environment
                    unsafe { (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release) };
                }
                if let Some(old) = old_mask {
                    crate::handlers::set_signal_mask_for_task(task, old);
                }
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            _ => {
                if let (Some(uctx_ptr), Some(hook)) = (uctx_opt, crate::user_task::yield_hook()) {
                    // Check for signals. If delivered, return -EINTR.
                    if let Some(h) = crate::signal_delivery_hook() {
                        if h(ctx, crate::Syscall::EpollWait.raw()) {
                            // Signal delivered. Interrupt syscall with EINTR.
                            if let Some(old) = old_mask {
                                crate::handlers::set_signal_mask_for_task(task, old);
                            }
                            ctx.set_return(SyscallReturn::ok((-4i64) as u64));
                            // SAFETY: `uctx_ptr` is the in-flight task's
                            // `UserTaskCtx` from `CURRENT`, live for this trap;
                            // `sleep_deadline_ns` is an atomic field, so the
                            // store needs only a valid pointer.
                            // SAFETY: Valid memory or trusted environment
                            unsafe { (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release) };
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
                    // SAFETY: `uctx_ptr` is the in-flight task's `UserTaskCtx`
                    // from `CURRENT`, live for this trap; `state`/`exit_reason`
                    // are its own `UnsafeCell` fields and the `hook` consumes
                    // the same pointer to park exactly this task.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        let uc = &*uctx_ptr;
                        // Flag this park as a net-I/O wait so the poll
                        // routine registers our waker for inbound-data
                        // wakeups (immediate re-poll on TCP data instead
                        // of waiting out the deadline).
                        uc.net_io_wait.store(true, Ordering::Release);
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
                        if narf_scheduler::stackful::user_own_stack_enabled() {
                            crate::handlers::own_stack_block(ctx);
                            return;
                        }
                        hook(uctx_ptr);
                    }
                    // unreachable
                }

                // No task context or no yield hook to park on (the
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

/// Clear the epoll instance registry + exclusive holders. Test hook.
#[doc(hidden)]
pub fn __test_reset() {
    *EPOLL_INSTANCES.lock() = Some(BTreeMap::new());
    *EXCLUSIVE_HOLDERS.lock() = Some(BTreeMap::new());
}
