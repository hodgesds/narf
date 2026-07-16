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
            // Snapshot the ops under the fd-table lock, query the
            // deadline OUTSIDE it — a nested epoll child's
            // `poll_deadline` re-enters `fd::with_table` (same
            // re-entrancy as `poll_fd_readiness`).
            let ops =
                fd::with_table(task_id, |t| t.get(fd as u32).map(|e| e.ops.clone())).flatten();
            if let Some(d) = ops.and_then(|o| o.poll_deadline()) {
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
        let snapshot: Vec<(i32, u32, u32)> = {
            let g = self.inner.lock();
            g.interest
                .values()
                .map(|it| (it.fd, it.events, it.last_mask))
                .collect()
        };
        let task = current_task_id();
        for (fd, events, last_mask) in snapshot {
            // Disarmed EPOLLONESHOT items deliver nothing.
            if (events & EPOLLONESHOT) != 0
                && (events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) == 0
            {
                continue;
            }
            let cur = poll_fd_readiness(task, fd);
            let want = events & !(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
            let ready = cur & want;
            if ready == 0 {
                continue;
            }
            // EPOLLET: readable only on a rising edge, same as
            // `collect_ready`. (The EPOLLEXCLUSIVE claim is deliberately
            // NOT mirrored — a readiness QUERY must not claim the fd.)
            if (events & EPOLLET) != 0 && (ready & !last_mask) == 0 {
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
    task: u64,
    from: &EpollInstance,
    needle: *const EpollInstance,
    depth: u32,
) -> bool {
    if depth >= EP_MAX_NESTS {
        return true;
    }
    let fds: Vec<i32> = from.inner.lock().interest.keys().copied().collect();
    for fd in fds {
        if fd < 0 {
            continue;
        }
        let Some(ops) = epoll_ops(task, fd as u32) else {
            continue;
        };
        let Some(child) = as_epoll(&ops) else {
            continue;
        };
        if core::ptr::eq(child, needle) || epoll_reaches(task, child, needle, depth + 1) {
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

pub fn sys_epoll_create1(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let flags = args.arg0 as u32;
    let cloexec = (flags & crate::fd::O_CLOEXEC) != 0;
    let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
    let fail = SyscallReturn::ok((-1i64) as u64);

    // The fd entry's ops Arc is the ONLY owner handle: every later
    // epoll_ctl/epoll_wait recovers the instance from the fd table
    // (`epoll_ops` + `as_epoll`), and closing the last fd drops it.
    let ops = EpollInstance::new() as Arc<dyn FileOps>;

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
        Some(fd) => ctx.set_return(SyscallReturn::ok(fd as u64)),
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

    let ops = match epoll_ops(task, epfd) {
        Some(o) => o,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let instance = match as_epoll(&ops) {
        Some(i) => i,
        None => {
            ctx.set_return(fail); // not an epoll fd (Linux: EINVAL)
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
            // Nested-epoll hardening, mirroring Linux ep_loop_check:
            // refuse an ADD that would make this epoll reachable from
            // itself (a cycle turns the recursive readiness poll into
            // unbounded kernel recursion) or nest epolls deeper than
            // EP_MAX_NESTS. Linux returns ELOOP; this file's error
            // convention is a bare -1 (LINUX-GAP: no per-errno codes).
            if tfd >= 0 {
                if let Some(tops) = epoll_ops(task, tfd as u32) {
                    if let Some(target) = as_epoll(&tops) {
                        if core::ptr::eq(target, instance)
                            || epoll_reaches(task, target, instance, 1)
                        {
                            ctx.set_return(fail);
                            return;
                        }
                    }
                }
            }
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
                ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                return;
            }
        }
    };
    epoll_wait_common(ctx, true, Some(timeout_ms));
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
    let maxevents = args.arg2 as usize;
    let timeout_ms = timeout_override.unwrap_or(args.arg3 as i32);
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
            let mask = u64::from_ne_bytes(buf); // user sigset_t == NARF N-1 layout
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

    // Resolve through the fd table (NOT a creating-thread registry) so a
    // CLONE_FILES sibling, a dup'd fd, or a fork-inherited epfd all wait
    // on the same instance `poll(2)` sees — see `epoll_ops`.
    let ops = match epoll_ops(task, epfd) {
        Some(o) => o,
        None => {
            if let Some(old) = old_mask {
                crate::handlers::set_signal_mask_for_task(task, old);
            }
            ctx.set_return(fail);
            return;
        }
    };
    let instance = match as_epoll(&ops) {
        Some(i) => i,
        None => {
            if let Some(old) = old_mask {
                crate::handlers::set_signal_mask_for_task(task, old);
            }
            ctx.set_return(fail); // not an epoll fd (Linux: EINVAL)
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
        let ready = instance.collect_ready(task);
        let n = ready.len().min(maxevents);
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

/// Clear the exclusive-wakeup holders. Test hook. (Instances need no
/// reset — they live and die with their fd-table entries.)
#[doc(hidden)]
pub fn __test_reset() {
    *EXCLUSIVE_HOLDERS.lock() = Some(BTreeMap::new());
}
