//! I/O multiplexing primitives — eventfd, timerfd, signalfd, plus
//! the per-task epoll interest-list table.
//!
//! Each event-style fd is a `FileOps` impl that lives in the same
//! per-task fd table as everything else. `poll_readiness()` is the
//! shared probe — sys_poll / sys_epoll_wait walk the listed fds,
//! call this on each, OR the bits, return matches.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat, POLL_IN, POLL_OUT};
use narf_lib::sync::IrqSafeSpinLock;

// ── eventfd ─────────────────────────────────────────────────────

/// `eventfd(2)` — a kernel-side u64 counter exposed as an fd. Each
/// `read` returns 8 bytes (the counter; resets to 0 by default;
/// EFD_SEMAPHORE mode decrements by 1). Each `write` (8 bytes)
/// adds the value. Readable when the counter is non-zero; writable
/// when adding the new value would not overflow u64::MAX.
#[derive(Debug)]
pub struct EventFd {
    counter: AtomicU64,
    semaphore: bool,
    /// Durable per-fd readiness cell — the SOLE readiness mechanism (there is no
    /// edge token). Mirrors POLL_IN (counter > 0) and POLL_OUT (counter < MAX-1);
    /// every counter change publishes the new level via `set` and fires the
    /// wait-queue via `notify` (see [`EventFd::sync_readiness`]), which wakes
    /// armed poll/epoll waiters — including an EPOLLET consumer on a same-level
    /// write.
    readiness: narf_lib::readiness::Readiness,
}

pub const EFD_SEMAPHORE: u32 = 1;

impl EventFd {
    pub fn new(initval: u64, flags: u32) -> Arc<Self> {
        Arc::new(Self {
            counter: AtomicU64::new(initval),
            semaphore: (flags & EFD_SEMAPHORE) != 0,
            readiness: narf_lib::readiness::Readiness::new(
                POLL_OUT | if initval != 0 { POLL_IN } else { 0 },
            ),
        })
    }

    /// Recompute the durable readiness cell from the current counter and publish
    /// the transition. `set` publishes the level and wakes waiters on a rising
    /// edge; `notify(event & add)` then fires the wait-queue for the just-changed
    /// direction UNCONDITIONALLY so an EPOLLET consumer re-fires even when a write
    /// lands on an already-readable counter. `event` is the direction the caller
    /// changed: POLL_IN on a write, POLL_OUT on a read.
    fn sync_readiness(&self, event: u32) {
        let c = self.counter.load(Ordering::Acquire);
        let readable = c > 0;
        let writable = c < u64::MAX - 1;
        let add = (if readable { POLL_IN } else { 0 }) | (if writable { POLL_OUT } else { 0 });
        let clear = (if readable { 0 } else { POLL_IN }) | (if writable { 0 } else { POLL_OUT });
        self.readiness.set(add, clear);
        self.readiness.notify(event & add);
    }
}

impl FileOps for EventFd {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if buf.len() < 8 {
                return Err(FsError::InvalidPath);
            }
            let (v, _was_saturated) = if self.semaphore {
                let mut cur = self.counter.load(Ordering::Acquire);
                loop {
                    if cur == 0 {
                        // Linux fs/eventfd.c::eventfd_read — a zero counter is
                        // -EAGAIN, never 0. Ok(0) here would read as EOF to any
                        // consumer that did not also consult an opt-in.
                        return Err(FsError::WouldBlock);
                    }
                    match self.counter.compare_exchange_weak(
                        cur,
                        cur - 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break (1, cur >= u64::MAX - 1),
                        Err(observed) => cur = observed,
                    }
                }
            } else {
                let cur = self.counter.swap(0, Ordering::AcqRel);
                if cur == 0 {
                    return Err(FsError::WouldBlock);
                }
                (cur, cur >= u64::MAX - 1)
            };
            self.sync_readiness(POLL_OUT);
            buf[..8].copy_from_slice(&v.to_le_bytes());
            Ok(8)
        })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if buf.len() < 8 {
                return Err(FsError::InvalidPath);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[..8]);
            let add = u64::from_le_bytes(bytes);
            // u64::MAX is the eventfd "overflow" sentinel; reject.
            if add == u64::MAX {
                return Err(FsError::InvalidPath);
            }
            let mut cur = self.counter.load(Ordering::Acquire);
            loop {
                let Some(next) = cur.checked_add(add) else {
                    return Err(FsError::InvalidPath);
                };
                if next == u64::MAX {
                    return Err(FsError::InvalidPath);
                }
                match self.counter.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => cur = observed,
                }
            }
            // Wake any task parked in poll/epoll on this eventfd. Without a
            // readiness notify an eventfd was a "silent" source, so a blocking
            // poll containing one could NOT park — it fell back to a busy spin
            // (poll_all_parkable == false). glib's main loop wakes its worker
            // via an eventfd write, so a Qt/glib client (kwin) polling its bus
            // socket + a glib wakeup eventfd busy-spun the whole time, and under
            // the cooperative own-stack scheduler that starved a same-CPU peer
            // (dbus-daemon couldn't service elogind's GetConnectionUnixUser →
            // kwin's GetSession timed out at 25s → "no graphical session"). With
            // this notify the eventfd is parkable, so the poll parks and this
            // write wakes it promptly. notify(0) = wake-all (an eventfd carries
            // no kernel TCB key); best-effort, mirrors the AF_UNIX send path.
            self.sync_readiness(POLL_IN);
            narf_net::readiness::notify(0);
            Ok(8)
        })
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

    /// eventfd `write` fires `readiness::notify` (above), so a blocking poll
    /// over an eventfd can PARK instead of busy-spinning — the write wakes it.
    /// An empty eventfd read must WAIT, never report end-of-file.
    ///
    /// `read()` on an eventfd whose counter is 0 blocks on Linux, or returns
    /// EAGAIN on an O_NONBLOCK fd. It NEVER returns 0 — `read() == 0` means
    /// hangup, and eventfd is the wakeup primitive under every Qt/GLib event
    /// loop, so a phantom EOF there makes the loop treat its own wakeup
    /// channel as dead.
    ///
    /// The read op returns [`FsError::WouldBlock`] on an empty counter, which
    /// `sys_read` turns into a park or EAGAIN without re-classifying `Ok(0)`.
    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    fn readiness_notifies(&self) -> bool {
        true
    }

    fn poll_readiness(&self) -> u32 {
        let mut bits = 0;
        if self.counter.load(Ordering::Acquire) > 0 {
            bits |= POLL_IN;
        }
        // Always writable until u64::MAX-1 (close to never).
        if self.counter.load(Ordering::Acquire) < u64::MAX - 1 {
            bits |= POLL_OUT;
        }
        bits
    }

    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        Some(&self.readiness)
    }
}

// ── timerfd ─────────────────────────────────────────────────────

/// `timerfd_create(2)` — a fd that becomes readable when a deadline
/// passes. `read` returns the number of expirations since the last
/// read (u64).
#[derive(Debug)]
pub struct TimerFd {
    state: IrqSafeSpinLock<TimerState>,
}

#[derive(Debug)]
struct TimerState {
    /// Absolute monotonic-ns deadline; 0 = disarmed.
    next_fire_ns: u64,
    /// Re-arm interval in ns; 0 = one-shot.
    interval_ns: u64,
    /// Pending expirations not yet read out.
    expirations: u64,
}

impl TimerFd {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: IrqSafeSpinLock::new(TimerState {
                next_fire_ns: 0,
                interval_ns: 0,
                expirations: 0,
            }),
        })
    }

    /// Set the timer. `value_ns` is the absolute monotonic-ns
    /// deadline for the first fire; `interval_ns` is the rearm
    /// period (0 = one-shot).
    pub fn arm(&self, value_ns: u64, interval_ns: u64) {
        let mut s = self.state.lock();
        s.next_fire_ns = value_ns;
        s.interval_ns = interval_ns;
        s.expirations = 0;
    }

    /// Wave-64: `timerfd_gettime(2)` snapshot.
    ///
    /// Returns `(value_remaining_ns, interval_ns)` — the time
    /// remaining until the next expiration and the configured
    /// re-arm interval (0 = one-shot). Both relative.
    ///
    /// Linux ref: `fs/timerfd.c`:do_timerfd_gettime
    /// (GPL-2.0-or-later, kernel.org).
    pub fn current(&self) -> (u64, u64) {
        let s = self.state.lock();
        if s.next_fire_ns == 0 {
            return (0, s.interval_ns);
        }
        let now = narf_scheduler::narf_time::monotonic_ns();
        let remaining = s.next_fire_ns.saturating_sub(now);
        (remaining, s.interval_ns)
    }

    /// Tick: if the deadline has passed, increment expirations and
    /// re-arm if periodic. Called from `read` and `poll_readiness`.
    fn tick(&self) {
        let now = narf_scheduler::narf_time::monotonic_ns();
        let mut s = self.state.lock();
        if s.next_fire_ns == 0 || now < s.next_fire_ns {
            return;
        }
        if s.interval_ns == 0 {
            s.expirations += 1;
            s.next_fire_ns = 0;
        } else {
            // Count missed expirations.
            let missed = ((now - s.next_fire_ns) / s.interval_ns).saturating_add(1);
            s.expirations = s.expirations.saturating_add(missed);
            s.next_fire_ns = s
                .next_fire_ns
                .saturating_add(s.interval_ns.saturating_mul(missed));
        }
        drop(s);
    }
}

impl FileOps for TimerFd {
    /// An unexpired timerfd read must WAIT, never report end-of-file.
    ///
    /// Linux blocks a `read()` on a timerfd with no expirations, or returns
    /// EAGAIN on an O_NONBLOCK fd. It never returns 0 — `read() == 0` means
    /// hangup. The old comment here ("libc loops until non-zero") described
    /// the SYMPTOM as if it were the contract: a caller handed a 0 has
    /// nothing to wait on, so it re-reads immediately and BURNS CPU. That is
    /// a busy-spin the kernel is inflicting on userspace, not libc's design.
    ///
    /// `sys_read` turns its explicit `WouldBlock` result into a park or an
    /// EAGAIN. Same class as the pipe, PTY, /dev/uinput, and EventFd.
    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.tick();
            let mut s = self.state.lock();
            if s.expirations == 0 {
                // Linux fs/timerfd.c::timerfd_read — an unexpired timer is
                // -EAGAIN, never 0.
                return Err(FsError::WouldBlock);
            }
            if buf.len() < 8 {
                return Err(FsError::InvalidPath);
            }
            buf[..8].copy_from_slice(&s.expirations.to_le_bytes());
            s.expirations = 0;
            Ok(8)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o400,
            },
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        self.tick();
        if self.state.lock().expirations > 0 {
            POLL_IN
        } else {
            0
        }
    }

    /// The armed deadline so a parked `epoll`/`poll` waiter can wake when
    /// this timer elapses. Already-expired (`expirations > 0`) or disarmed
    /// (`next_fire_ns == 0`) timers report `None` — the former is reported
    /// ready by `poll_readiness`, the latter has no schedule.
    fn poll_deadline(&self) -> Option<u64> {
        let s = self.state.lock();
        if s.next_fire_ns == 0 || s.expirations > 0 {
            None
        } else {
            Some(s.next_fire_ns)
        }
    }
}

// ── signalfd ────────────────────────────────────────────────────

/// Per-owner-task registry of live signalfd readiness cells. A signal raised
/// for a task fires every signalfd cell registered here (Linux wakes the
/// signalfd wait queue on delivery), so an EPOLLET consumer re-fires even on a
/// drain→re-raise refill where the readiness mask stays POLL_IN. Keyed by owner
/// task; multiple signalfds per task are held as `Weak` and reaped lazily.
static SIGNALFD_CELLS: IrqSafeSpinLock<
    alloc::collections::BTreeMap<
        u64,
        alloc::vec::Vec<alloc::sync::Weak<narf_lib::readiness::Readiness>>,
    >,
> = IrqSafeSpinLock::new(alloc::collections::BTreeMap::new());

/// Register a signalfd's readiness cell for `task` so [`wake_signalfds`] fires it
/// on every signal raised for that task. Used by both the io_mux `SignalFd` and
/// the linux-compat `SignalFdFile`.
pub fn register_signalfd_cell(task: u64, cell: &Arc<narf_lib::readiness::Readiness>) {
    SIGNALFD_CELLS
        .lock()
        .entry(task)
        .or_default()
        .push(Arc::downgrade(cell));
}

/// Fire the readiness wait-queue of every signalfd owned by `task` — called from
/// the signal-raise path. `set`+`notify` POLL_IN so an armed poll/epoll waiter
/// (including an EPOLLET consumer between non-parking waits) wakes; the fd's
/// `poll_readiness` still gates actual delivery on `pending_in_mask`, so firing
/// on a signal outside the fd's mask is a harmless spurious wake.
pub fn wake_signalfds(task: u64) {
    let cells: alloc::vec::Vec<Arc<narf_lib::readiness::Readiness>> = {
        let mut map = SIGNALFD_CELLS.lock();
        let Some(list) = map.get_mut(&task) else {
            return;
        };
        list.retain(|w| w.strong_count() != 0);
        if list.is_empty() {
            map.remove(&task);
            return;
        }
        list.iter().filter_map(alloc::sync::Weak::upgrade).collect()
    };
    for cell in cells {
        cell.set(POLL_IN, 0);
        cell.notify(POLL_IN);
    }
}

/// `signalfd(2)` — receive signals as a `read` instead of as an
/// async handler delivery. `read` returns one or more `signalfd_siginfo`
/// records (128 B each).
#[derive(Debug)]
pub struct SignalFd {
    /// Mask of signum bits this fd watches. Signals not in the
    /// mask are not delivered through it.
    pub mask: AtomicU64,
    /// Owning task id — only signals queued to this task are
    /// reported. Multi-process signalfd is a Stage-2 follow-up.
    pub owner_task: u64,
    /// Durable readiness cell (Linux signalfd wait queue). POLL_IN when a
    /// masked signal is pending; fired by [`wake_signalfds`] on every raise for
    /// `owner_task` so an EPOLLET consumer re-fires on a drain→re-raise refill.
    readiness: Arc<narf_lib::readiness::Readiness>,
}

impl SignalFd {
    pub fn new(mask: u64, owner: u64) -> Arc<Self> {
        let readiness = Arc::new(narf_lib::readiness::Readiness::new(0));
        SIGNALFD_CELLS
            .lock()
            .entry(owner)
            .or_default()
            .push(Arc::downgrade(&readiness));
        Arc::new(Self {
            mask: AtomicU64::new(mask),
            owner_task: owner,
            readiness,
        })
    }

    /// Test whether any pending signal in the mask is set for the
    /// owner. Looked up against the existing per-task signal pending
    /// table via the public accessor.
    fn pending_in_mask(&self) -> u64 {
        let mask = self.mask.load(Ordering::Acquire);
        let pending = crate::handlers::signal_pending_of(self.owner_task);
        pending & mask
    }
}

impl FileOps for SignalFd {
    /// A signalfd with nothing pending must WAIT, never report end-of-file.
    ///
    /// Linux blocks a `read()` on a signalfd with no pending signal in its
    /// mask, or returns EAGAIN on an O_NONBLOCK fd; 0 would mean hangup.
    /// Handing back 0 makes a signal-driven loop treat its own signal
    /// channel as closed — and a caller that retries instead burns CPU.
    ///
    /// Same class as pipe / PtyMaster / uinput / EventFd / TimerFd.
    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let pending = self.pending_in_mask();
            if pending == 0 {
                // Linux fs/signalfd.c::signalfd_read — no pending signal is
                // -EAGAIN, never 0.
                return Err(FsError::WouldBlock);
            }
            // Drain the lowest pending bit. signalfd_siginfo is
            // 128 bytes; we fill only the first 4 (ssi_signo) and
            // zero the rest. Real consumers read the signo and
            // dispatch.
            let signum = crate::handlers::sig_from_bit(pending);
            const SI_LEN: usize = 128;
            if buf.len() < SI_LEN {
                return Err(FsError::InvalidPath);
            }
            buf[..SI_LEN].fill(0);
            buf[..4].copy_from_slice(&signum.to_le_bytes());
            // Clear the bit so subsequent reads see the next signal.
            crate::handlers::clear_signal_pending(self.owner_task, signum);
            Ok(SI_LEN)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o400,
            },
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        if self.pending_in_mask() != 0 {
            POLL_IN
        } else {
            0
        }
    }

    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        Some(&self.readiness)
    }

    /// Reconcile the cell to the live pending level before arming so a stale
    /// latched POLL_IN (a signal drained since the last wake) can't spuriously
    /// return Ready. `wake_signalfds` re-latches + notifies on the next raise.
    fn arm_readiness(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        let readable = self.pending_in_mask() != 0;
        self.readiness.set(
            if readable { POLL_IN } else { 0 },
            if readable { 0 } else { POLL_IN },
        );
        Some(self.readiness.arm(task_id, interest, waker))
    }

    fn arm_readiness_persistent(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        let readable = self.pending_in_mask() != 0;
        self.readiness.set(
            if readable { POLL_IN } else { 0 },
            if readable { 0 } else { POLL_IN },
        );
        Some(self.readiness.arm_persistent(id, interest, waker))
    }
}
