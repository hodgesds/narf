//! `poll(2)` — synchronous readiness-wait on a set of file descriptors.
//!
//! Linux ref: `fs/select.c` `do_poll` / `poll_poll`.
//!
//! Wire layout on the user side matches POSIX `struct pollfd`:
//! ```text
//! struct pollfd {
//!     fd:      i32  // offset 0
//!     events:  u16  // offset 4
//!     revents: u16  // offset 6
//! }               // total 8 bytes
//! ```
//!
//! This is a synchronous spin-style poll: we query every fd's
//! `poll_readiness()` once; if nothing is ready we busy-yield (via
//! `sleep_pumps::run()`) until either something becomes ready or the
//! deadline expires.  The waker/async path is the epoll layer.
//!
//! `sys_poll` is called from `handlers.rs`; `do_poll` is the shared
//! body re-used by `sys_select` / `sys_pselect6`.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::FileOps;

use crate::fd;

// ── Re-export POLL_* constants ───────────────────────────────────────
pub use narf_filesystem::{POLL_ERR, POLL_HUP, POLL_IN, POLL_NVAL, POLL_OUT, POLL_PRI};

/// Kernel-internal representation of a single poll item.
#[derive(Copy, Clone, Debug)]
pub struct PollFd {
    pub fd: i32,
    pub events: u16,
    pub revents: u16,
}

/// Core poll implementation.  `fds` is the kernel-side item array
/// (pre-parsed from the user pointer by the syscall shim).
/// `timeout_ms` is -1 for indefinite, 0 for non-blocking, >0 for
/// bounded wait.
///
/// Returns the number of fds with non-zero revents, or 0 on timeout.
///
/// Linux ref: `fs/select.c`:do_poll (GPL-2.0-or-later, kernel.org).
pub fn do_poll(task_id: u64, fds: &mut [PollFd], timeout_ms: i64) -> usize {
    let deadline_ns: Option<u64> = if timeout_ms == 0 {
        Some(0) // non-blocking: exactly one pass
    } else if timeout_ms > 0 {
        let now = narf_scheduler::narf_time::monotonic_ns();
        Some(now.saturating_add((timeout_ms as u64) * 1_000_000))
    } else {
        None // infinite
    };

    loop {
        // --- one pass: query every fd ---
        // Snapshot each open fd's `Arc<dyn FileOps>` under the fd-table lock,
        // then release the lock BEFORE calling `poll_readiness()`. A nested
        // epoll fd's `poll_readiness` re-enters `fd::with_table` to poll its
        // children; polling while still holding the (non-reentrant) lock
        // deadlocks the task — libinput/libwayland nest event loops, so a
        // `poll()` over an inner-epoll fd would otherwise hang. Mirrors
        // `poll_fd_readiness` / `EpollInstance::poll_readiness`.
        let files: Vec<Option<(Arc<dyn FileOps>, u64)>> = fd::with_table(task_id, |t| {
            fds.iter()
                .map(|item| {
                    if item.fd < 0 {
                        None
                    } else {
                        t.get(item.fd as u32).map(|e| (e.ops.clone(), e.offset))
                    }
                })
                .collect()
        })
        .unwrap_or_default();
        let mut n_ready = 0usize;
        for (item, slot) in fds.iter_mut().zip(files.iter()) {
            if item.fd < 0 {
                // POSIX: negative fd → ignored, revents = 0.
                item.revents = 0;
                continue;
            }
            match slot {
                None => {
                    // fd not open → POLLNVAL regardless of events.
                    item.revents = POLL_NVAL as u16;
                    n_ready += 1;
                }
                Some((o, offset)) => {
                    let mask = o.poll_readiness_at(*offset);
                    // OR in ERR/HUP/NVAL so they're always returned
                    // even if the caller didn't ask for them (POSIX).
                    let always = (POLL_ERR | POLL_HUP | POLL_NVAL) as u16;
                    let want = item.events | always;
                    let ready = (mask as u16) & want;
                    item.revents = ready;
                    if ready != 0 {
                        n_ready += 1;
                    }
                }
            }
        }

        if n_ready > 0 {
            return n_ready;
        }

        // --- check deadline ---
        match deadline_ns {
            Some(0) => return 0, // non-blocking, one shot only
            Some(d) => {
                let now = narf_scheduler::narf_time::monotonic_ns();
                if now >= d {
                    return 0; // timed out
                }
                // Yield to let background work run, then retry.
                narf_scheduler::sleep_pumps::run();
                core::hint::spin_loop();
            }
            None => {
                // Indefinite: yield and retry.
                narf_scheduler::sleep_pumps::run();
                core::hint::spin_loop();
            }
        }
    }
}

/// Parse a user `pollfd` array at `ptr` with `nfds` entries into
/// a kernel `Vec<PollFd>`.  Returns `None` on null/zero-length input.
///
/// # Safety
/// Caller must guarantee `ptr` points to `nfds * 8` readable bytes in the
/// currently-active user address space, **and that the range is in the user
/// half** — pass it through `handlers::validate_user_range` first.
///
/// That second clause is not pedantry. This function opens a SMAP bracket, so
/// `EFLAGS.AC` is set for the duration and a `CPL=0` read of a kernel page
/// succeeds silently: SMAP only guards pages with `PTE.U=1`. An unvalidated
/// kernel-half `ptr` is therefore an arbitrary kernel *read*, not a fault. The
/// only caller (`poll_common`) validates; a second caller that forgets would
/// reintroduce that.
pub unsafe fn parse_pollfds(ptr: *const u8, nfds: usize) -> Option<Vec<PollFd>> {
    if ptr.is_null() || nfds == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(nfds);
    // SMAP bracket — bare `read_unaligned` from a kernel-mode CPL=0
    // through a user-only PTE faults with SMAP on (CR4.SMAP=1, the
    // default on every CPU we boot). Open the user-access window
    // for the duration of the parse, then close it once we've
    // staged the values into the kernel-owned `out` vec.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: caller guarantees `nfds * 8` readable user bytes from `ptr`.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            for i in 0..nfds {
                let base = ptr.add(i * 8);
                let fd_val = core::ptr::read_unaligned(base as *const i32);
                let ev_val = core::ptr::read_unaligned(base.add(4) as *const u16);
                out.push(PollFd {
                    fd: fd_val,
                    events: ev_val,
                    revents: 0,
                });
            }
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    for i in 0..nfds {
        // SAFETY: caller guarantees `nfds * 8` readable bytes from `ptr`;
        // `i < nfds`, so `base = ptr + i*8` stays within that region.
        // SAFETY: Valid memory or trusted environment
        let base = unsafe { ptr.add(i * 8) };
        // SAFETY: `base` points at the start of entry `i` (4 readable bytes
        // for the `fd` field); `read_unaligned` tolerates any alignment.
        // SAFETY: Valid memory or trusted environment
        let fd_val = unsafe { core::ptr::read_unaligned(base as *const i32) };
        // SAFETY: `base + 4` is the `events` field, 2 readable bytes still
        // inside the entry; `read_unaligned` tolerates any alignment.
        // SAFETY: Valid memory or trusted environment
        let ev_val = unsafe { core::ptr::read_unaligned(base.add(4) as *const u16) };
        out.push(PollFd {
            fd: fd_val,
            events: ev_val,
            revents: 0,
        });
    }
    Some(out)
}

/// Write `revents` back to the user `pollfd` array at `ptr`.
///
/// # Safety
/// Same pointer-validity contract as `parse_pollfds`, and the same reason for
/// it — except that this direction is worse: each entry's `revents` is two
/// bytes written at `ptr + i*8 + 6`, so an unvalidated kernel-half `ptr` is an
/// arbitrary kernel *write*. `poll(2)` and `ppoll(2)` take no credential, so
/// that would be reachable by any task.
pub unsafe fn write_pollfds(ptr: *mut u8, fds: &[PollFd]) {
    // Same SMAP rationale as `parse_pollfds`: a CPL=0 write to a
    // user-only PTE faults without STAC.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: caller guarantees `nfds * 8` writable user bytes.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            for (i, item) in fds.iter().enumerate() {
                let base = ptr.add(i * 8).add(6) as *mut u16;
                core::ptr::write_unaligned(base, item.revents);
            }
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    for (i, item) in fds.iter().enumerate() {
        // SAFETY: caller guarantees `nfds * 8` writable bytes from `ptr`;
        // `i < fds.len() == nfds`, so `ptr + i*8 + 6` is the `revents` field
        // (2 writable bytes) of entry `i`, inside that region.
        // SAFETY: Valid memory or trusted environment
        let base = unsafe { ptr.add(i * 8).add(6) as *mut u16 };
        // SAFETY: `base` is the writable 2-byte `revents` slot computed above;
        // `write_unaligned` tolerates any alignment.
        // SAFETY: Valid memory or trusted environment
        unsafe { core::ptr::write_unaligned(base, item.revents) };
    }
}

// ── Syscall body ────────────────────────────────────────────────────

use crate::handlers::current_task_id;
use crate::syscall::{SyscallReturn, TrapContext};

/// `sys_poll(pollfds_ptr, nfds, timeout_ms)`
///
/// - arg0 = ptr to packed `[{i32 fd, u16 events, u16 revents}]` array
/// - arg1 = element count (nfds_t)
/// - arg2 = timeout in milliseconds (-1 = block, 0 = nonblock, >0 = bounded)
///
/// Returns the number of ready fds, 0 on timeout, or -1 on error.
///
/// Linux ref: `fs/select.c`:do_sys_poll (GPL-2.0-or-later, kernel.org).
pub fn sys_poll(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    poll_common(
        ctx,
        args.arg0 as *mut u8,
        args.arg1 as usize,
        args.arg2 as i64,
    );
}

/// `ppoll(fds, nfds, timespec*, sigmask, sigsetsize)` — poll with a
/// `timespec` timeout (NULL = block indefinitely) and an ignored
/// sigmask. Converts the timespec to a millisecond timeout and shares
/// the poll core with `sys_poll`.
pub fn sys_ppoll(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let timeout: i64 = if args.arg2 == 0 {
        -1
    } else {
        // SAFETY: `arg2` is a user `timespec*` in-pointer; copy_from_user_vec
        // range-validates the 16-byte read.
        match unsafe { crate::handlers::copy_from_user_vec(args.arg2, 16) } {
            Ok(b) => {
                let secs = u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                let nsec =
                    u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
                secs.saturating_mul(1000).saturating_add(nsec / 1_000_000) as i64
            }
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                return;
            }
        }
    };
    let mut old_mask = None;
    if args.arg3 != 0 && args.arg4 == 8 {
        let mut buf = [0u8; 8];
        // SAFETY: arg4 (sigsetsize) == 8 checked above; copy_from_user
        // range-validates `args.arg3` and SMAP-brackets the read into `buf`.
        if unsafe { crate::handlers::copy_from_user(&mut buf, args.arg3) }.is_ok() {
            let mask = u64::from_ne_bytes(buf); // user sigset_t == NARF N-1 layout
            let task = current_task_id();
            old_mask = Some(crate::handlers::set_signal_mask_for_task(task, mask));
        } else {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    }

    poll_common(ctx, args.arg0 as *mut u8, args.arg1 as usize, timeout);

    if let Some(old) = old_mask {
        crate::handlers::set_signal_mask_for_task(current_task_id(), old);
    }
}

/// One readiness pass over `fds`: fills each `revents`, returns the ready
/// count. The blocking-park path uses this for its pre-park scan (the spin
/// path keeps using `do_poll`). Same per-fd rules as `do_poll`: negative fd
/// ignored, closed fd → POLLNVAL, open fd → `poll_readiness() & (events|ERR|HUP|NVAL)`.
pub(crate) fn poll_scan(task_id: u64, fds: &mut [PollFd]) -> usize {
    // Snapshot ops under the lock, poll OUTSIDE it — a nested epoll fd's
    // `poll_readiness` re-enters the fd-table lock (see `do_poll`).
    //
    // `entry_files` is the entry-time resolution held by `Task::poll_files`
    // for a blocking poll. It is what makes a SIBLING THREAD's `close()`
    // invisible to a poll already in flight, matching `do_sys_poll`, which
    // resolves each fd once and holds the `struct file` for the whole call.
    // Re-resolving on every park wake instead turned such a close into an
    // instant POLLNVAL, and an event loop that reads that as a spurious wake
    // re-polls at once and spins.
    let entry_files = crate::task::task_get(task_id).and_then(|t| {
        let held = t.poll_files.lock();
        (held.len() == fds.len()).then(|| held.clone())
    });
    let files: Vec<Option<(Arc<dyn FileOps>, u64)>> = fd::with_table(task_id, |t| {
        fds.iter()
            .enumerate()
            .map(|(i, item)| {
                if item.fd < 0 {
                    return None;
                }
                let live = t.get(item.fd as u32).map(|e| (e.ops.clone(), e.offset));
                match (&entry_files, live) {
                    // Still open: poll the file we resolved at entry, at its
                    // CURRENT offset. In Linux the offset lives inside the
                    // very `struct file` being polled, so it stays live —
                    // that is what keeps `/dev/kmsg` re-evaluating as its
                    // reader drains.
                    (Some(entry), Some((_, offset))) => {
                        entry[i].as_ref().map(|(ops, _)| (ops.clone(), offset))
                    }
                    // Closed since entry: keep polling the file we hold, at
                    // the offset it had. This is the whole point — the fd
                    // number is gone but the file is not.
                    (Some(entry), None) => entry[i].clone(),
                    (None, live) => live,
                }
            })
            .collect()
    })
    .unwrap_or_default();
    let mut n_ready = 0usize;
    for (item, slot) in fds.iter_mut().zip(files.iter()) {
        if item.fd < 0 {
            item.revents = 0;
            continue;
        }
        match slot {
            None => {
                item.revents = POLL_NVAL as u16;
                n_ready += 1;
            }
            Some((o, offset)) => {
                let mask = o.poll_readiness_at(*offset);
                let always = (POLL_ERR | POLL_HUP | POLL_NVAL) as u16;
                let ready = (mask as u16) & (item.events | always);
                item.revents = ready;
                if ready != 0 {
                    n_ready += 1;
                }
            }
        }
    }
    n_ready
}

/// Earliest absolute monotonic-ns deadline at which any fd becomes ready with
/// no readiness `notify` — i.e. an armed timerfd expiry. A parked poll clamps
/// its scheduler wake-up to this. Mirrors `EpollInstance::nearest_poll_deadline`.
fn poll_nearest_deadline(task_id: u64, fds: &[PollFd]) -> Option<u64> {
    // Snapshot ops under the fd-table lock, query `poll_deadline` OUTSIDE
    // it — an epoll fd forwards to its children through `fd::with_table`
    // (same re-entrancy as `poll_readiness`; see `poll_scan`).
    let ops: Vec<Arc<dyn FileOps>> = fd::with_table(task_id, |t| {
        fds.iter()
            .filter(|item| item.fd >= 0)
            .filter_map(|item| t.get(item.fd as u32).map(|e| e.ops.clone()))
            .collect()
    })
    .unwrap_or_default();
    let mut best: Option<u64> = None;
    for o in &ops {
        if let Some(d) = o.poll_deadline() {
            best = Some(best.map_or(d, |b: u64| b.min(d)));
        }
    }
    best
}

/// Record a blocking poll park's fd set into the task ctx for the stall
/// watchdog (see `UserTaskCtx::poll_wait_fds`): slot = `events<<32 | (fd+1)`.
fn record_poll_wait(uc: &crate::user_task::UserTaskCtx, fds: &[PollFd]) {
    use core::sync::atomic::Ordering;
    // Diagnostics only: recording the fd set costs up to
    // POLL_WAIT_RECORD_MAX atomic stores on EVERY poll park, which is a
    // hot path. Off unless the stall watchdog asked for it, so a normal
    // build pays one relaxed load.
    if !crate::user_task::poll_wait_recording_enabled() {
        return;
    }
    for (i, slot) in uc.poll_wait_fds.iter().enumerate() {
        let v = match fds.get(i) {
            Some(item) if item.fd >= 0 => {
                ((item.events as u64) << 32) | ((item.fd as u32 as u64) + 1)
            }
            _ => 0,
        };
        slot.store(v, Ordering::Relaxed);
    }
    uc.poll_wait_nfds.store(fds.len() as u32, Ordering::Release);
}

/// Clear the watchdog poll-park record on a poll return path, and RELEASE the
/// entry-time file references this poll was holding (`Task::poll_files`).
///
/// `task_id` is passed explicitly rather than read from `current_task_id()`:
/// the release must name the SAME task whose files were installed, and
/// binding it to an implicit global made the release silently target a
/// different task whenever the two diverge.
///
/// Called on every `poll_common` return path, which is what bounds the
/// holder's lifetime to the syscall — the analogue of `do_sys_poll` dropping
/// its `struct file` references when the call returns. Leaking them would
/// keep a closed file alive indefinitely and, worse, make the NEXT poll on
/// this task reuse a stale resolution.
pub(crate) fn clear_poll_wait_record(task_id: u64, uc: &crate::user_task::UserTaskCtx) {
    use core::sync::atomic::Ordering;
    uc.poll_wait_nfds.store(0, Ordering::Release);
    if let Some(t) = crate::task::task_get(task_id) {
        let mut held = t.poll_files.lock();
        if !held.is_empty() {
            // Drop the Arcs OUTSIDE the lock: releasing the last reference to
            // a file can run a destructor that takes other locks.
            let files = core::mem::take(&mut *held);
            drop(held);
            drop(files);
        }
    }
}

/// Resolve every fd of a blocking poll ONCE, at syscall entry, and hold the
/// resulting file references for the duration of the call (see
/// [`crate::task::Task::poll_files`]). No-op when a resolution is already
/// held — the park re-executes this syscall on every wake, and re-resolving
/// then is precisely the bug this prevents.
pub(crate) fn install_poll_files(task_id: u64, fds: &[PollFd]) {
    let Some(t) = crate::task::task_get(task_id) else {
        return;
    };
    {
        let held = t.poll_files.lock();
        if held.len() == fds.len() {
            return;
        }
    }
    let resolved: Vec<crate::task::PollFileSlot> = fd::with_table(task_id, |tbl| {
        fds.iter()
            .map(|item| {
                if item.fd < 0 {
                    None
                } else {
                    tbl.get(item.fd as u32).map(|e| (e.ops.clone(), e.offset))
                }
            })
            .collect()
    })
    .unwrap_or_default();
    if resolved.len() == fds.len() {
        // Swap under the lock, drop the OLD resolution OUTSIDE it —
        // releasing the last reference to a file can run a destructor
        // that takes other locks (the same rule `clear_poll_wait_record`
        // documents). A plain `*lock() = resolved` ran those drops while
        // holding `poll_files`.
        let old = {
            let mut held = t.poll_files.lock();
            core::mem::replace(&mut *held, resolved)
        };
        drop(old);
    }
}

/// Arm every polled fd that owns a durable [`Readiness`](narf_lib::readiness::Readiness)
/// cell (`FileOps::readiness()`), keyed by this task id, so a readiness edge on
/// it wakes THIS poll directly via the cell's `set` instead of the coarse
/// backstop. Returns `true` if any such fd was ALREADY ready at arm time — the
/// register-then-recheck that closes the `poll_scan` → arm lost-wake window; the
/// caller must then NOT park. A no-op returning `false` for descriptors still on
/// the legacy path (`readiness() == None`), so a partially-migrated tree parks
/// exactly as before.
fn arm_readiness_cells(task_id: u64, fds: &[PollFd], waker: &core::task::Waker) -> bool {
    fd::with_table(task_id, |t| {
        let mut any_ready = false;
        for pfd in fds {
            if pfd.fd < 0 {
                continue;
            }
            if let Some(e) = t.get(pfd.fd as u32) {
                let interest = (pfd.events as u32) | POLL_ERR | POLL_HUP | POLL_NVAL;
                if let Some(poll) = e.ops.arm_readiness(task_id, interest, waker) {
                    if poll.is_ready() {
                        any_ready = true;
                    }
                }
            }
        }
        any_ready
    })
    .unwrap_or(false)
}

/// Remove this task's registration from every polled fd's Readiness cell.
/// Called on every non-park return (ready / timeout / EINTR) so a woken-but-
/// returned poll leaves no stale waiter behind. No-op for legacy-path fds.
fn disarm_readiness_cells(task_id: u64, fds: &[PollFd]) {
    let _ = fd::with_table(task_id, |t| {
        for pfd in fds {
            if pfd.fd < 0 {
                continue;
            }
            if let Some(e) = t.get(pfd.fd as u32) {
                e.ops.disarm_readiness(task_id);
            }
        }
    });
}

fn poll_common(ctx: &mut dyn TrapContext, ptr: *mut u8, nfds: usize, timeout: i64) {
    use core::sync::atomic::Ordering;
    let fail = SyscallReturn::ok((-1i64) as u64);

    // Upper bound on nfds to prevent OOM from hostile input.
    if nfds > 1_048_576 {
        ctx.set_return(fail);
        return;
    }

    let task = current_task_id();

    if nfds == 0 {
        // poll({}, 0, timeout_ms) is legal; it just sleeps for timeout_ms.
        if timeout > 0 {
            let deadline = narf_scheduler::narf_time::monotonic_ns()
                .saturating_add((timeout as u64) * 1_000_000);
            while narf_scheduler::narf_time::monotonic_ns() < deadline {
                narf_scheduler::sleep_pumps::run();
                core::hint::spin_loop();
            }
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Validate the whole `struct pollfd[nfds]` before touching a byte of it.
    //
    // This is the one thing `parse_pollfds` / `write_pollfds` cannot do for
    // themselves: both open a SMAP bracket and then `read_unaligned` /
    // `write_unaligned`, so with `EFLAGS.AC` set a `CPL=0` access to a kernel
    // page succeeds silently. The old comment here asserted "user pointer in
    // the active AS" and nothing checked it, which made `revents` — two bytes
    // written at `ptr + i*8 + 6` for every `i` — an arbitrary kernel write, and
    // the parse an arbitrary kernel read. `poll(2)` and `ppoll(2)` take no
    // credential, so unlike the `bpf(2)` gadget of the same class this was
    // reachable by any task.
    //
    // One check covers both directions: the parse reads `[ptr, ptr + nfds*8)`
    // and every write lands inside it. `nfds` is already bounded above, so the
    // multiply cannot wrap, and `validate_user_range` rejects the kernel half,
    // the canonical hole, a null base, and an end-overflow.
    let Some(bytes) = nfds.checked_mul(8) else {
        ctx.set_return(fail);
        return;
    };
    if crate::handlers::validate_user_range(ptr as u64, bytes).is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    // SAFETY: the range was just validated as `nfds * 8` bytes wholly inside
    // the user half, which is exactly the contract `parse_pollfds` documents.
    let mut fds = match unsafe { parse_pollfds(ptr, nfds) } {
        Some(v) => v,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    let uctx_opt = crate::user_task::current_user_task();

    // A blocking wait PARKS instead of busy-spinning — that frees the
    // cooperative own-stack CPU. Busy-polling pins the core at 100% and, since
    // the spin only drives kernel `sleep_pump`s (never yielding to same-CPU
    // user tasks), starves every peer: a compositor looping poll() over
    // {wayland, DRM, input, dbus, ...} otherwise wedges the whole session.
    //
    // We park even when the set contains a "silent" fd (pipe/eventfd/tty — one
    // that becomes ready via a write firing no readiness notify). The park path
    // already arms the ~10 ms lost-wake backstop (`net_io_wait` below →
    // `park_fire_deadline_ns`, clamped under any finite timeout), so a silent
    // readiness edge is picked up within one backstop tick by the re-executed
    // scan rather than being missed — a bounded ≤10 ms latency in place of a
    // 100%-CPU spin. A closed fd is caught by `poll_scan`'s POLLNVAL on the
    // first pass below (immediate return, no park). Only a non-blocking poll or
    // one with no task context (early boot) still takes the one-shot busy path.
    let can_park = timeout != 0 && uctx_opt.is_some();
    if !can_park {
        let n = do_poll(task, &mut fds, timeout);
        // SAFETY: same pointer/length as the parse step; user AS still active.
        unsafe { write_pollfds(ptr, &fds) };
        ctx.set_return(SyscallReturn::ok(n as u64));
        return;
    }

    // ── Park path. Mirrors `epoll_wait_common`. ──
    // SAFETY: `current_user_task()` returned Some, checked in `can_park`.
    let uctx_ptr = uctx_opt.unwrap();

    // Reset net-I/O-wait + snapshot the readiness generation BEFORE the scan so
    // a `notify` racing our scan→park window is caught by the park routine's
    // lost-wake guard. Re-armed every cycle (the syscall re-executes on wake).
    // SAFETY: in-flight task's UserTaskCtx, live for this trap; atomics.
    unsafe {
        (*uctx_ptr).net_io_wait.store(false, Ordering::Release);
        (*uctx_ptr)
            .epoll_park_gen
            .store(narf_net::readiness::generation(), Ordering::Release);
    }

    // Park deadline. `blocking_deadline_ns` persists across the RIP-rewind
    // re-executions so a finite timeout detects expiry instead of re-arming
    // now+timeout forever (the scheduler clears `sleep_deadline_ns` on expiry).
    let deadline_ns: Option<u64> = {
        // SAFETY: as above.
        let uctx = unsafe { &*uctx_ptr };
        if timeout > 0 {
            let persisted = uctx.blocking_deadline_ns.load(Ordering::Acquire);
            let d = if persisted != 0 {
                persisted
            } else {
                let d = narf_scheduler::narf_time::monotonic_ns()
                    .saturating_add((timeout as u64) * 1_000_000);
                uctx.blocking_deadline_ns.store(d, Ordering::Release);
                d
            };
            uctx.sleep_deadline_ns.store(d, Ordering::Release);
            Some(d)
        } else {
            // Infinite (timeout < 0).
            uctx.sleep_deadline_ns.store(u64::MAX, Ordering::Release);
            None
        }
    };

    // Resolve the fd set ONCE for this blocking poll and hold the files for
    // the whole call, so a sibling thread's close() cannot turn it into a
    // POLLNVAL return (Linux `do_sys_poll`). No-op on a park re-execution.
    install_poll_files(task, &fds);

    // One readiness pass. Count it: this is the park path's own readiness
    // question, and the stall watchdog compares its answer against this
    // task's (see `UserTaskCtx::dbg_poll_scans`). A parked poller whose
    // scan count climbs while the watchdog still sees a ready fd is
    // re-asking and getting a different answer; one whose count is frozen
    // is not re-executing at all.
    // SAFETY: `current_user_task()` returned Some, checked in `can_park`.
    unsafe {
        (*uctx_ptr).dbg_poll_scans.fetch_add(1, Ordering::Relaxed);
    }
    let ready = poll_scan(task, &mut fds);
    if ready > 0 {
        // A re-execution that found readiness: tear down any cell arm from the
        // prior park before returning.
        disarm_readiness_cells(task, &fds);
        // SAFETY: as above.
        unsafe {
            (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release);
            (*uctx_ptr).blocking_deadline_ns.store(0, Ordering::Release);
            clear_poll_wait_record(task, &*uctx_ptr);
        }
        // SAFETY: same pointer/length as the parse step.
        unsafe { write_pollfds(ptr, &fds) };
        ctx.set_return(SyscallReturn::ok(ready as u64));
        return;
    }

    // Finite timeout already elapsed across re-executions → return 0.
    if let Some(d) = deadline_ns {
        if d != u64::MAX && narf_scheduler::narf_time::monotonic_ns() >= d {
            disarm_readiness_cells(task, &fds);
            // SAFETY: as above.
            unsafe {
                (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release);
                (*uctx_ptr).blocking_deadline_ns.store(0, Ordering::Release);
                clear_poll_wait_record(task, &*uctx_ptr);
            }
            // SAFETY: same pointer/length.
            unsafe { write_pollfds(ptr, &fds) };
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
    }

    // Park: register the net-I/O waker + a timer fallback, re-execute on wake.
    if let Some(hook) = crate::user_task::yield_hook() {
        // A pending unblocked signal interrupts the wait with -EINTR.
        if let Some(h) = crate::signal_delivery_hook() {
            if h(ctx, crate::Syscall::Poll.raw()) {
                disarm_readiness_cells(task, &fds);
                // SAFETY: clearing this task's own park deadlines.
                unsafe {
                    (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release);
                    (*uctx_ptr).blocking_deadline_ns.store(0, Ordering::Release);
                    clear_poll_wait_record(task, &*uctx_ptr);
                }
                ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // EINTR
                return;
            }
        }
        // Durable per-fd wake: arm each polled fd that owns a Readiness cell so
        // a `set` edge wakes this poll directly (alongside the legacy
        // net_io_wait path during migration). The arm IS the register-then-
        // recheck: if a cell fd went ready in the poll_scan → arm window, do NOT
        // park — disarm, re-scan, and return, exactly like the epoll
        // ready-after-registration path. No-op while no fd has migrated
        // (`readiness()` still `None` everywhere → `any_ready == false`).
        if let Some(w) = narf_scheduler::stackful::current_stackful_waker() {
            if arm_readiness_cells(task, &fds, &w) {
                disarm_readiness_cells(task, &fds);
                // SAFETY: clearing this task's own park deadlines.
                unsafe {
                    (*uctx_ptr).sleep_deadline_ns.store(0, Ordering::Release);
                    (*uctx_ptr).blocking_deadline_ns.store(0, Ordering::Release);
                    clear_poll_wait_record(task, &*uctx_ptr);
                }
                let n = poll_scan(task, &mut fds);
                // SAFETY: same pointer/length as the parse step.
                unsafe { write_pollfds(ptr, &fds) };
                ctx.set_return(SyscallReturn::ok(n as u64));
                return;
            }
        }
        // SAFETY: in-flight task's UserTaskCtx; we park exactly this task.
        unsafe {
            let uc = &*uctx_ptr;
            uc.net_io_wait.store(true, Ordering::Release);
            // Record the parked fd set for the stall watchdog (the poll twin
            // of `epoll_wait_fd`) so a wedged poller's readiness can be
            // re-evaluated from the watchdog tick. Refreshed on every
            // re-execution; cleared on every return path.
            record_poll_wait(uc, &fds);
            // Clamp the scheduler wake-up to the nearest armed timerfd (its
            // expiry fires no readiness notify).
            if let Some(timer_dl) = poll_nearest_deadline(task, &fds) {
                let cur = uc.sleep_deadline_ns.load(Ordering::Acquire);
                let clamped = if cur == 0 {
                    timer_dl
                } else {
                    cur.min(timer_dl)
                };
                uc.sleep_deadline_ns.store(clamped, Ordering::Release);
            }
            // Rewind RIP over the 2-byte syscall so we re-execute poll on wake.
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

    // No yield hook (early boot): can't block — report nothing ready.
    // SAFETY: same pointer/length.
    unsafe { write_pollfds(ptr, &fds) };
    ctx.set_return(SyscallReturn::ok(0));
}
