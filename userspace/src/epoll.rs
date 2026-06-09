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
            // Query current readiness from the fd table.
            let cur_mask: u32 = fd::with_table(task_id, |t| {
                t.get(*fd as u32)
                    .map(|e| e.ops.poll_readiness())
                    .unwrap_or(0)
            })
            .unwrap_or(0);

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
        let mut mask = 0;
        let g = self.inner.lock();
        for (_, item) in &g.interest {
            let fd = item.fd;
            let ready = fd::with_table(current_task_id(), |t| {
                t.get(fd as u32)
                    .map(|e| e.ops.poll_readiness())
                    .unwrap_or(0)
            })
            .unwrap_or(0);
            if (ready & item.events) != 0 {
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
static EPOLL_INSTANCES: IrqSafeSpinLock<Option<BTreeMap<(u64, u32), Arc<EpollInstance>>>> =
    IrqSafeSpinLock::new(None);

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
    let _flags = args.arg0 as u32; // ignored for now
    let fail = SyscallReturn::ok((-1i64) as u64);

    let instance = EpollInstance::new();
    let ops = instance.clone() as Arc<dyn FileOps>;

    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    }) {
        Some(fd) => Some(fd),
        None => None,
    };

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

pub fn sys_epoll_wait(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let events_ptr = args.arg1 as *mut u8;
    let maxevents = args.arg2 as usize;
    let timeout_ms = args.arg3 as i32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();

    if events_ptr.is_null() || maxevents == 0 {
        ctx.set_return(fail);
        return;
    }

    let instance = match instances_lookup(task, epfd) {
        Some(i) => i,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    let uctx_ptr = crate::user_task::current_user_task().expect("epoll_wait outside task context");
    let uctx = unsafe { &*uctx_ptr };

    let deadline_ns: Option<u64> = if timeout_ms == 0 {
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
    };

    loop {
        let ready = instance.collect_ready(task);
        let n = ready.len().min(maxevents);
        if n > 0 {
            uctx.sleep_deadline_ns.store(0, Ordering::Release);
            for (i, (events, data)) in ready[..n].iter().enumerate() {
                if write_epoll_event(
                    events_ptr as u64 + (i * EPOLL_EVENT_SIZE) as u64,
                    *events,
                    *data,
                )
                .is_err()
                {
                    ctx.set_return(fail);
                    return;
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
            Some(d) if d != u64::MAX && narf_scheduler::narf_time::monotonic_ns() >= d => {
                uctx.sleep_deadline_ns.store(0, Ordering::Release);
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            _ => {
                if let Some(hook) = crate::user_task::yield_hook() {
                    // Check for signals. If delivered, return -EINTR.
                    if let Some(h) = crate::signal_delivery_hook() {
                        if h(ctx, crate::Syscall::EpollWait.raw()) {
                            // Signal delivered. Interrupt syscall with EINTR.
                            ctx.set_return(SyscallReturn::ok((-4i64) as u64));
                            uctx.sleep_deadline_ns.store(0, Ordering::Release);
                            return;
                        }
                    }

                    unsafe {
                        let uc = &*uctx_ptr;
                        // Rewind RIP so we re-execute epoll_wait on resume.
                        ctx.set_rip(ctx.rip().wrapping_sub(2));
                        ctx.save_user_state(uc.state.get() as *mut u8);
                        *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                        hook(uctx_ptr);
                    }
                    // unreachable
                }

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
    *EPOLL_INSTANCES.lock() = Some(BTreeMap::new());
    *EXCLUSIVE_HOLDERS.lock() = Some(BTreeMap::new());
}
