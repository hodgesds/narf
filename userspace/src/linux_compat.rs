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
    /// Durable readiness cell (Linux signalfd wait queue). Fired by
    /// [`crate::io_mux::wake_signalfds`] on every signal raised for `owner_task`,
    /// so an EPOLLET consumer re-fires on a drain→re-raise refill where the
    /// readiness mask stays POLL_IN.
    readiness: Arc<narf_lib::readiness::Readiness>,
}

impl SignalFdFile {
    pub fn new(mask: u64, owner: u64) -> Arc<Self> {
        let readiness = Arc::new(narf_lib::readiness::Readiness::new(0));
        crate::io_mux::register_signalfd_cell(owner, &readiness);
        Arc::new(Self {
            mask: AtomicU64::new(mask),
            owner_task: owner,
            readiness,
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
    fn pending(&self) -> u64 {
        let m = self.mask.load(Ordering::Acquire);
        crate::handlers::signal_pending_of(self.owner_task) & m
    }
}

impl FileOps for SignalFdFile {
    /// A signalfd with nothing pending must WAIT, never report end-of-file.
    ///
    /// The old comment below called `Ok(0)` an "EAGAIN shape" — but a bare
    /// 0 is NOT EAGAIN at the syscall boundary, it is EOF, and userspace
    /// reads it as the signal channel having hung up. These opt-ins are what
    /// make `sys_read` actually produce EAGAIN (O_NONBLOCK) or a park
    /// (blocking) from that same return.
    ///
    /// Same class as pipe / PtyMaster / uinput / EventFd / TimerFd.
    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let pending = self.pending();
            if pending == 0 {
                // Linux fs/signalfd.c::signalfd_read — no pending signal is
                // -EAGAIN, never 0.
                return Err(FsError::WouldBlock);
            }
            if buf.len() < SIGNALFD_SIGINFO_LEN {
                return Err(FsError::InvalidData);
            }
            // Drain lowest pending bit.
            let signum = crate::handlers::sig_from_bit(pending);
            buf[..SIGNALFD_SIGINFO_LEN].fill(0);
            // ssi_signo: u32 at offset 0.
            buf[..4].copy_from_slice(&signum.to_le_bytes());
            // ssi_errno (offset 4) left 0. If this instance was queued via
            // rt_sigqueueinfo/sigqueue, surface its payload: ssi_code @8,
            // ssi_int @44 (sival_int), ssi_ptr @48 (sival_ptr). Popping the
            // payload and clearing/re-arming the pending bit happen together
            // under the sigqueue bucket lock (atomic against a racing sender's
            // store+set), so a queued standard signal is never read as a
            // payload-less SI_USER nor left stranded — same invariant as the
            // sigwait and handler-delivery consumers.
            if let Some((si_code, si_value, si_pid)) =
                crate::handlers::sigqueue_take_and_clear(self.owner_task, signum)
            {
                buf[8..12].copy_from_slice(&si_code.to_le_bytes());
                buf[12..16].copy_from_slice(&si_pid.to_le_bytes()); // ssi_pid
                buf[44..48].copy_from_slice(&(si_value as u32).to_le_bytes());
                buf[48..56].copy_from_slice(&si_value.to_le_bytes());
            }
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

    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        Some(&self.readiness)
    }

    /// Reconcile the cell to the live pending level before arming so a stale
    /// latched POLL_IN (a signal drained since the last wake) can't spuriously
    /// return Ready; `wake_signalfds` re-latches + notifies on the next raise.
    fn arm_readiness(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        let readable = self.pending() != 0;
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
        let readable = self.pending() != 0;
        self.readiness.set(
            if readable { POLL_IN } else { 0 },
            if readable { 0 } else { POLL_IN },
        );
        Some(self.readiness.arm_persistent(id, interest, waker))
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

/// Why `MemFdFile::add_seals` refused. `fcntl(F_ADD_SEALS)` reports the two
/// cases with different errnos — an undefined seal bit is -EINVAL, while a
/// file that may not be sealed any further is -EPERM — and a caller that
/// retries with a corrected seal set depends on telling them apart.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SealError {
    /// A seal bit outside [`F_SEAL_ALL`]. Linux: -EINVAL.
    Invalid,
    /// The file is already sealed against further sealing. Linux: -EPERM.
    Denied,
}

/// Wave-70 memfd_create backing. Anonymous growable byte buffer +
/// Page-frame-backed store for a memfd. The content lives in dedicated
/// physical frames (page-aligned, never relocated) rather than a heap
/// `Vec<u8>`, so two `MAP_SHARED` mappings of the same memfd — e.g. a
/// Wayland client and the compositor sharing a wl_shm pool — alias the
/// same memory. `mmap_frames` hands these frames to `sys_mmap`.
struct MemfdStore {
    /// Backing page frames (zeroed on allocation). `frames[i]` covers
    /// bytes `[i*4096, (i+1)*4096)`.
    frames: Vec<narf_memory::PhysFrame>,
    /// Logical file length (may be < frames.len()*4096).
    len: usize,
}

impl MemfdStore {
    /// Grow the frame list to cover `pages` pages, zeroing new frames.
    /// Returns false on allocation failure.
    fn ensure_pages(&mut self, pages: usize) -> bool {
        while self.frames.len() < pages {
            match narf_memory::alloc_frame() {
                Ok(f) => {
                    // SAFETY: a freshly-allocated frame is identity-mapped
                    // (x86_64 KERNEL_PHYS_OFFSET == 0) and owned by us.
                    unsafe {
                        core::ptr::write_bytes(f.start_address().raw() as *mut u8, 0, 4096);
                    }
                    self.frames.push(f);
                }
                Err(_) => return false,
            }
        }
        true
    }

    /// Identity-mapped pointer to backing page `page`.
    fn page_ptr(&self, page: usize) -> *mut u8 {
        self.frames[page].start_address().raw() as *mut u8
    }
}

impl Drop for MemfdStore {
    fn drop(&mut self) {
        // NOTE: a mapping that outlives the memfd fd (close-then-use, which
        // Linux permits) would dangle. The shm pattern keeps the fd open for
        // the mapping's lifetime, so this is sound in practice.
        for f in self.frames.drain(..) {
            narf_memory::free_frame(f);
        }
    }
}

/// a Linux-shaped seal word. Read/write/truncate respect seals.
pub struct MemFdFile {
    store: IrqSafeSpinLock<MemfdStore>,
    seals: AtomicU32,
    /// Whether sealing is allowed (MFD_ALLOW_SEALING). When false,
    /// every F_ADD_SEALS returns -EPERM and F_GET_SEALS returns
    /// F_SEAL_SEAL — matching Linux's fixed default.
    allow_sealing: bool,
}

impl core::fmt::Debug for MemFdFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemFdFile")
            .field("len", &self.store.lock().len)
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
            store: IrqSafeSpinLock::new(MemfdStore {
                frames: Vec::new(),
                len: 0,
            }),
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
    pub fn add_seals(&self, new_seals: u32) -> Result<(), SealError> {
        // `mm/memfd.c::memfd_add_seals` validates the requested set BEFORE
        // it looks at what the file already carries:
        //
        //   if (seals & ~(unsigned int)F_ALL_SEALS) return -EINVAL;
        //   ...
        //   if (*file_seals & F_SEAL_SEAL) { error = -EPERM; }
        //
        // so an undefined seal bit is -EINVAL even on a file that could not
        // have been sealed anyway. A separate `allow_sealing` early-return
        // used to pre-empt this and answer -EPERM; it was also redundant,
        // because a memfd created without MFD_ALLOW_SEALING already starts
        // with F_SEAL_SEAL set and so fails the check below on its own.
        if (new_seals & !F_SEAL_ALL) != 0 {
            return Err(SealError::Invalid);
        }
        let cur = self.seals.load(Ordering::Acquire);
        if (cur & F_SEAL_SEAL) != 0 {
            return Err(SealError::Denied);
        }
        self.seals.store(cur | new_seals, Ordering::Release);
        Ok(())
    }
}

/// Copy `buf.len()` bytes between a byte slice and the frame store at byte
/// `off`. `to_store=true` writes buf→store, false reads store→buf. The
/// caller guarantees the store covers `[off, off+buf.len())`.
fn store_copy(store: &MemfdStore, off: usize, buf: &mut [u8], to_store: bool) {
    let mut done = 0;
    while done < buf.len() {
        let abs = off + done;
        let page = abs / 4096;
        let in_page = abs % 4096;
        let n = core::cmp::min(buf.len() - done, 4096 - in_page);
        // SAFETY: `page` is within the store's frames (caller-ensured), each
        // frame is 4096 identity-mapped bytes; `in_page + n <= 4096`.
        unsafe {
            let p = store.page_ptr(page).add(in_page);
            if to_store {
                core::ptr::copy_nonoverlapping(buf[done..].as_ptr(), p, n);
            } else {
                core::ptr::copy_nonoverlapping(p, buf[done..].as_mut_ptr(), n);
            }
        }
        done += n;
    }
}

impl FileOps for MemFdFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let g = self.store.lock();
            let off = offset as usize;
            if off >= g.len {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), g.len - off);
            store_copy(&g, off, &mut buf[..n], false);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let seals = self.seals.load(Ordering::Acquire);
            if (seals & F_SEAL_WRITE) != 0 {
                return Err(FsError::OperationNotPermitted);
            }
            let mut g = self.store.lock();
            let off = offset as usize;
            let new_end = off + buf.len();
            // F_SEAL_GROW: only fill existing space.
            if new_end > g.len && (seals & F_SEAL_GROW) != 0 {
                if off >= g.len {
                    return Err(FsError::OperationNotPermitted);
                }
                let n = g.len - off;
                let mut tmp = buf[..n].to_vec();
                store_copy(&g, off, &mut tmp, true);
                return Ok(n);
            }
            let pages = new_end.div_ceil(4096);
            if !g.ensure_pages(pages) {
                return Err(FsError::Unsupported);
            }
            if new_end > g.len {
                g.len = new_end;
            }
            let mut tmp = buf.to_vec();
            store_copy(&g, off, &mut tmp, true);
            Ok(buf.len())
        })
    }

    fn stat(&self) -> Stat {
        let g = self.store.lock();
        Stat {
            size: g.len as u64,
            blocks: (g.len as u64).div_ceil(512),
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let seals = self.seals.load(Ordering::Acquire);
            let mut g = self.store.lock();
            let cur = g.len as u64;
            if len < cur && (seals & F_SEAL_SHRINK) != 0 {
                return Err(FsError::OperationNotPermitted);
            }
            if len > cur && (seals & F_SEAL_GROW) != 0 {
                return Err(FsError::OperationNotPermitted);
            }
            // Allocate frames up-front (the shm pattern truncates to the pool
            // size before mmap). Shrinking keeps frames to avoid dangling an
            // active mapping; only `len` changes.
            let pages = (len as usize).div_ceil(4096);
            if !g.ensure_pages(pages) {
                return Err(FsError::Unsupported);
            }
            g.len = len as usize;
            Ok(())
        })
    }

    /// `MAP_SHARED` backing — return the physical frames for the byte range
    /// `[offset, offset+len)` so both mappers alias the same memory. This is
    /// what makes wl_shm work: the compositor sees the client's pixels.
    fn mmap_frames(&self, offset: u64, len: usize) -> Result<alloc::vec::Vec<u64>, FsError> {
        if offset & 0xFFF != 0 {
            return Err(FsError::InvalidData);
        }
        let mut g = self.store.lock();
        let start = (offset as usize) / 4096;
        let pages = len.div_ceil(4096);
        if !g.ensure_pages(start + pages) {
            return Err(FsError::Unsupported);
        }
        Ok((start..start + pages)
            .map(|p| g.frames[p].start_address().raw())
            .collect())
    }
}
