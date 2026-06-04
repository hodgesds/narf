//! I/O multiplexing primitives — eventfd, timerfd, signalfd, plus
//! the per-task epoll interest-list table.
//!
//! Each event-style fd is a `FileOps` impl that lives in the same
//! per-task fd table as everything else. `poll_readiness()` is the
//! shared probe — sys_poll / sys_epoll_wait walk the listed fds,
//! call this on each, OR the bits, return matches.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
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
}

pub const EFD_SEMAPHORE: u32 = 1;

impl EventFd {
    pub fn new(initval: u64, flags: u32) -> Arc<Self> {
        Arc::new(Self {
            counter: AtomicU64::new(initval),
            semaphore: (flags & EFD_SEMAPHORE) != 0,
        })
    }
}

impl FileOps for EventFd {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if buf.len() < 8 {
                return Err(FsError::InvalidPath);
            }
            let v = if self.semaphore {
                let cur = self.counter.load(Ordering::Acquire);
                if cur == 0 {
                    return Ok(0);
                }
                self.counter.fetch_sub(1, Ordering::AcqRel);
                1u64
            } else {
                let cur = self.counter.swap(0, Ordering::AcqRel);
                if cur == 0 {
                    return Ok(0);
                }
                cur
            };
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
            let _ = self.counter.fetch_add(add, Ordering::AcqRel);
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
    }
}

impl FileOps for TimerFd {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.tick();
            let mut s = self.state.lock();
            if s.expirations == 0 {
                return Ok(0); // libc loops until non-zero
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
}

// ── signalfd ────────────────────────────────────────────────────

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
}

impl SignalFd {
    pub fn new(mask: u64, owner: u64) -> Arc<Self> {
        Arc::new(Self {
            mask: AtomicU64::new(mask),
            owner_task: owner,
        })
    }

    /// Test whether any pending signal in the mask is set for the
    /// owner. Looked up against the existing per-task signal pending
    /// table via the public accessor.
    fn pending_in_mask(&self) -> u32 {
        let mask = self.mask.load(Ordering::Acquire) as u32;
        let pending = crate::handlers::signal_pending_of(self.owner_task);
        pending & mask
    }
}

impl FileOps for SignalFd {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let pending = self.pending_in_mask();
            if pending == 0 {
                return Ok(0);
            }
            // Drain the lowest pending bit. signalfd_siginfo is
            // 128 bytes; we fill only the first 4 (ssi_signo) and
            // zero the rest. Real consumers read the signo and
            // dispatch.
            let signum = pending.trailing_zeros();
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
}

// ── epoll instance ──────────────────────────────────────────────

/// Per-instance epoll interest list. Stage-1 level-triggered only;
/// EPOLLET edge-triggered lands once a consumer needs it.
#[derive(Debug)]
pub struct EpollFile {
    interest: IrqSafeSpinLock<BTreeMap<i32, EpollEntry>>,
}

#[derive(Copy, Clone, Debug)]
pub struct EpollEntry {
    pub events: u32,
    pub user_data: u64,
}

impl EpollFile {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            interest: IrqSafeSpinLock::new(BTreeMap::new()),
        })
    }

    pub fn ctl_add(&self, fd: i32, entry: EpollEntry) {
        self.interest.lock().insert(fd, entry);
    }

    pub fn ctl_mod(&self, fd: i32, entry: EpollEntry) {
        self.interest.lock().insert(fd, entry);
    }

    pub fn ctl_del(&self, fd: i32) {
        self.interest.lock().remove(&fd);
    }

    pub fn snapshot(&self) -> Vec<(i32, EpollEntry)> {
        self.interest.lock().iter().map(|(k, v)| (*k, *v)).collect()
    }
}

impl FileOps for EpollFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
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
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }
    fn poll_readiness(&self) -> u32 {
        // An epoll fd is itself readable when any watched fd has
        // events ready — a relatively expensive query that consumers
        // typically don't do. Return 0 here; epoll_wait does the
        // real walk.
        0
    }
}
