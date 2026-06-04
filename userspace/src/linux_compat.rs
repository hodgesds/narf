//! Wave-70 Linux-compat surface: signalfd4(2) + memfd_create(2) with
//! file sealing. Gated behind the `linux-compat` feature so a strictly-
//! NARF-native build can opt out.
//!
//! Both types are independent `FileOps` impls and live in the per-task
//! fd table like every other event-style fd (eventfd, timerfd, epoll).
//!
//! `SignalFdFile` reads from the existing Wave-51 per-task pending-
//! signal bitmap (`signal_pending_of` / `clear_signal_pending`).
//! Each `read` drains one pending signal in mask, fills a 128-byte
//! `signalfd_siginfo`, and returns. Multiple signals: caller loops.
//! `poll_readiness(POLL_IN)` reports any in-mask pending → epoll-
//! integrated.
//!
//! `MemFdFile` is an anonymous, growable byte buffer with a Linux-
//! shaped seal word (F_SEAL_SHRINK / GROW / WRITE / SEAL). Seals are
//! one-way: once set they never clear; `F_SEAL_SEAL` itself blocks
//! adding more seals. fcntl(F_ADD_SEALS / F_GET_SEALS) routes through
//! the FileOps `ioctl` slot using sentinel cmd numbers that don't
//! collide with the Linux ioctl space (the fcntl handler dispatches
//! by fd type explicitly, not by cmd-word decode).

#![cfg(feature = "linux-compat")]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN};
use narf_lib::sync::IrqSafeSpinLock;

// ── signalfd4 ──────────────────────────────────────────────────────

/// `SFD_CLOEXEC` — install fd with FD_CLOEXEC bit set.
pub const SFD_CLOEXEC: u32 = 0o2000000;
/// `SFD_NONBLOCK` — set O_NONBLOCK on the new fd. We model the bit
/// but `read` is already non-blocking (returns 0 when empty).
pub const SFD_NONBLOCK: u32 = 0o4000;

/// `signalfd_siginfo` size — Linux ABI.
pub const SIGNALFD_SIGINFO_LEN: usize = 128;

/// Wave-70 signalfd4 backing. Reads `signalfd_siginfo` records by
/// draining the lowest in-mask pending signum for `owner_task`.
#[derive(Debug)]
pub struct SignalFdFile {
    mask: AtomicU64,
    owner_task: u64,
}

impl SignalFdFile {
    pub fn new(mask: u64, owner: u64) -> Arc<Self> {
        Arc::new(Self {
            mask: AtomicU64::new(mask),
            owner_task: owner,
        })
    }

    /// Replace the watched signal mask. Used by `signalfd4(fd, ...)`
    /// when the caller passes a non-`-1` fd.
    pub fn set_mask(&self, mask: u64) {
        self.mask.store(mask, Ordering::Release);
    }

    pub fn mask(&self) -> u64 {
        self.mask.load(Ordering::Acquire)
    }

    pub fn owner(&self) -> u64 {
        self.owner_task
    }

    /// In-mask pending bitmap for the owner.
    fn pending(&self) -> u32 {
        let m = self.mask.load(Ordering::Acquire) as u32;
        crate::handlers::signal_pending_of(self.owner_task) & m
    }
}

impl FileOps for SignalFdFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let pending = self.pending();
            if pending == 0 {
                // EAGAIN shape: short return for non-blocking caller.
                return Ok(0);
            }
            if buf.len() < SIGNALFD_SIGINFO_LEN {
                return Err(FsError::InvalidData);
            }
            // Drain lowest pending bit.
            let signum = pending.trailing_zeros();
            buf[..SIGNALFD_SIGINFO_LEN].fill(0);
            // ssi_signo: u32 at offset 0.
            buf[..4].copy_from_slice(&signum.to_le_bytes());
            // ssi_errno (offset 4) and ssi_code (offset 8) left 0.
            crate::handlers::clear_signal_pending(self.owner_task, signum);
            Ok(SIGNALFD_SIGINFO_LEN)
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
                file_type: FileType::Special,
                perms: 0o400,
            },
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        if self.pending() != 0 {
            POLL_IN
        } else {
            0
        }
    }
}

// ── memfd_create + file sealing ────────────────────────────────────

/// `MFD_CLOEXEC` — install fd with FD_CLOEXEC bit set.
pub const MFD_CLOEXEC: u32 = 0x0001;
/// `MFD_ALLOW_SEALING` — sealing operations are permitted via fcntl.
pub const MFD_ALLOW_SEALING: u32 = 0x0002;

/// `F_SEAL_SEAL` — no more seals can be added.
pub const F_SEAL_SEAL: u32 = 0x0001;
/// `F_SEAL_SHRINK` — no truncate-shorter.
pub const F_SEAL_SHRINK: u32 = 0x0002;
/// `F_SEAL_GROW` — no truncate-longer + no write past EOF.
pub const F_SEAL_GROW: u32 = 0x0004;
/// `F_SEAL_WRITE` — no writes at all.
pub const F_SEAL_WRITE: u32 = 0x0008;
/// Mask of all valid seal bits.
pub const F_SEAL_ALL: u32 = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

/// Wave-70 memfd_create backing. Anonymous growable byte buffer +
/// a Linux-shaped seal word. Read/write/truncate respect seals.
pub struct MemFdFile {
    bytes: IrqSafeSpinLock<Vec<u8>>,
    seals: AtomicU32,
    /// Whether sealing is allowed (MFD_ALLOW_SEALING). When false,
    /// every F_ADD_SEALS returns -EPERM and F_GET_SEALS returns
    /// F_SEAL_SEAL — matching Linux's fixed default.
    allow_sealing: bool,
}

impl core::fmt::Debug for MemFdFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemFdFile")
            .field("len", &self.bytes.lock().len())
            .field("seals", &self.seals.load(Ordering::Relaxed))
            .field("allow_sealing", &self.allow_sealing)
            .finish()
    }
}

impl MemFdFile {
    pub fn new(flags: u32) -> Arc<Self> {
        let allow = (flags & MFD_ALLOW_SEALING) != 0;
        // When sealing is not allowed, the read-side F_GET_SEALS
        // must return F_SEAL_SEAL per Linux man-page semantics.
        let initial_seals = if allow { 0 } else { F_SEAL_SEAL };
        Arc::new(Self {
            bytes: IrqSafeSpinLock::new(Vec::new()),
            seals: AtomicU32::new(initial_seals),
            allow_sealing: allow,
        })
    }

    pub fn seals(&self) -> u32 {
        self.seals.load(Ordering::Acquire)
    }

    /// Add `new_seals` to the seal word. Returns Ok(()) on success,
    /// Err(()) when sealing is forbidden, F_SEAL_SEAL already set, or
    /// new_seals is out of range.
    pub fn add_seals(&self, new_seals: u32) -> Result<(), ()> {
        if !self.allow_sealing {
            return Err(());
        }
        if (new_seals & !F_SEAL_ALL) != 0 {
            return Err(());
        }
        let cur = self.seals.load(Ordering::Acquire);
        if (cur & F_SEAL_SEAL) != 0 {
            return Err(());
        }
        self.seals
            .store(cur | new_seals, Ordering::Release);
        Ok(())
    }
}

impl FileOps for MemFdFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let g = self.bytes.lock();
            let off = offset as usize;
            if off >= g.len() {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), g.len() - off);
            buf[..n].copy_from_slice(&g[off..off + n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let seals = self.seals.load(Ordering::Acquire);
            if (seals & F_SEAL_WRITE) != 0 {
                return Err(FsError::ReadOnly);
            }
            let mut g = self.bytes.lock();
            let off = offset as usize;
            let new_end = off + buf.len();
            if new_end > g.len() {
                if (seals & F_SEAL_GROW) != 0 {
                    // Allow filling existing space only.
                    if off >= g.len() {
                        return Err(FsError::ReadOnly);
                    }
                    let n = g.len() - off;
                    g[off..off + n].copy_from_slice(&buf[..n]);
                    return Ok(n);
                }
                g.resize(new_end, 0);
            }
            g[off..off + buf.len()].copy_from_slice(buf);
            Ok(buf.len())
        })
    }

    fn stat(&self) -> Stat {
        let g = self.bytes.lock();
        Stat {
            size: g.len() as u64,
            blocks: (g.len() as u64).div_ceil(512),
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let seals = self.seals.load(Ordering::Acquire);
            let mut g = self.bytes.lock();
            let cur = g.len() as u64;
            if len < cur && (seals & F_SEAL_SHRINK) != 0 {
                return Err(FsError::ReadOnly);
            }
            if len > cur && (seals & F_SEAL_GROW) != 0 {
                return Err(FsError::ReadOnly);
            }
            g.resize(len as usize, 0);
            Ok(())
        })
    }
}
