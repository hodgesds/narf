//! Per-task file-descriptor table.
//!
//! Stage-4 needed by real `Read` / `Write` / `Close` syscall
//! handlers: a handler reads `arg0` as an `fd` (a small u32), looks
//! it up in the calling task's table, and routes the operation to
//! the backing `FileOps` impl. fd 0..=2 are reserved for stdin /
//! stdout / stderr; subsequent slots are first-free.
//!
//! The table is per-task and stored in a global `BTreeMap<TaskId,
//! FdTable>`. Tests + the scheduler call `attach_to(task_id, ops)`
//! to install a backing FileOps; the `Open` handler (when wired)
//! calls `attach_to(current_task, ops)` after VFS resolves a path.
//! `detach(task_id)` removes the whole table on task exit.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

/// Per-task fd table entry.
#[derive(Clone)]
pub struct FdEntry {
    pub ops: Arc<dyn FileOps>,
    /// File-pointer offset into the underlying object. Updated on
    /// every `Read` / `Write` so they're position-tracking by
    /// default (POSIX semantics).
    pub offset: u64,
    /// Per-fd-slot flags. `FD_CLOEXEC = bit 0`. Mirrors the kernel
    /// fd-table "fd flags" word that `fcntl(F_GETFD/F_SETFD)`
    /// manipulates — not the open-file-description status flags
    /// (those live in `status_flags`).
    pub flags: u32,
    /// Open-file-description status flags (`F_GETFL`/`F_SETFL`).
    /// `O_NONBLOCK | O_APPEND | O_DIRECT` are honoured; access mode
    /// bits (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) are stored but not yet
    /// enforced at the syscall layer. Defaults to 0 on every new fd.
    pub status_flags: u32,
}

/// `FD_CLOEXEC` — bit 0 of `FdEntry::flags`. Mirrors POSIX. Kept
/// here so callers don't have to import a libc-style header to
/// poke the bit.
pub const FD_CLOEXEC: u32 = 1;

// ── Open-file status flag bits (Linux x86_64 numbering) ────────────
//
// These live in `FdEntry::status_flags` and are toggled by
// `fcntl(F_SETFL)`. Access-mode bits (`O_RDONLY`/`O_WRONLY`/`O_RDWR`)
// are reported by `F_GETFL` but ignored by `F_SETFL` (POSIX: only the
// mutable subset is settable).
pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_ACCMODE: u32 = 0o3;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_APPEND: u32 = 0o2000;
pub const O_DIRECT: u32 = 0o40000;
pub const O_CLOEXEC: u32 = 0o2000000;

/// Settable subset of file status flags per `F_SETFL`. Linux honours
/// these and silently masks the rest.
pub const O_SETFL_MASK: u32 = O_NONBLOCK | O_APPEND | O_DIRECT;

impl core::fmt::Debug for FdEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FdEntry")
            .field("offset", &self.offset)
            .field("flags", &self.flags)
            .field("status_flags", &self.status_flags)
            .finish_non_exhaustive()
    }
}

/// Per-task fd table. Slot 0/1/2 are stdin/stdout/stderr; the
/// kernel populates them at task creation (today's helper:
/// `attach_console_stdio`).
#[derive(Debug, Default)]
pub struct FdTable {
    slots: Vec<Option<FdEntry>>,
}

impl FdTable {
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Insert `entry` at the lowest free slot ≥ 3. Slots 0..=2 are
    /// reserved for stdio; install those via `set` directly.
    pub fn open(&mut self, entry: FdEntry) -> u32 {
        // Ensure stdio slots exist.
        while self.slots.len() < 3 {
            self.slots.push(None);
        }
        for (i, s) in self.slots.iter_mut().enumerate().skip(3) {
            if s.is_none() {
                *s = Some(entry);
                return i as u32;
            }
        }
        let i = self.slots.len();
        self.slots.push(Some(entry));
        i as u32
    }

    /// Insert `entry` at the lowest free slot ≥ `min`. Used by
    /// `fcntl(F_DUPFD)` / `F_DUPFD_CLOEXEC`. Caps `min` at 3 if it
    /// would otherwise land on the stdio reservations.
    pub fn open_at_least(&mut self, entry: FdEntry, min: u32) -> u32 {
        let min = (min as usize).max(3);
        while self.slots.len() <= min {
            self.slots.push(None);
        }
        for (i, s) in self.slots.iter_mut().enumerate().skip(min) {
            if s.is_none() {
                *s = Some(entry);
                return i as u32;
            }
        }
        let i = self.slots.len();
        self.slots.push(Some(entry));
        i as u32
    }

    /// Place `entry` at a specific slot (typically used for stdio).
    pub fn set(&mut self, fd: u32, entry: FdEntry) {
        let i = fd as usize;
        while self.slots.len() <= i {
            self.slots.push(None);
        }
        self.slots[i] = Some(entry);
    }

    /// Remove the entry at `fd`. Returns `true` if it existed.
    pub fn close(&mut self, fd: u32) -> bool {
        let i = fd as usize;
        match self.slots.get_mut(i) {
            Some(slot @ Some(_)) => {
                *slot = None;
                true
            }
            _ => false,
        }
    }

    /// Borrow the entry at `fd` without removing it.
    pub fn get(&self, fd: u32) -> Option<&FdEntry> {
        self.slots.get(fd as usize).and_then(Option::as_ref)
    }

    /// Mutable borrow — used by Read/Write to advance the offset.
    pub fn get_mut(&mut self, fd: u32) -> Option<&mut FdEntry> {
        self.slots.get_mut(fd as usize).and_then(Option::as_mut)
    }
}

// ── Global per-task table ──────────────────────────────────────────

/// `TaskId.raw()` keys.
type Tables = BTreeMap<u64, FdTable>;

static TABLES: IrqSafeSpinLock<Option<Tables>> = IrqSafeSpinLock::new(None);

/// Initialise the per-task fd table store. Called once at boot
/// before any task can install fds.
pub fn init() {
    *TABLES.lock() = Some(BTreeMap::new());
}

/// Look up + run `op` against the table for `task_id`. Creates a
/// fresh table — pre-populated with stdio at fds 0/1/2 — on first
/// reference. Returns the closure's value.
pub fn with_table<R>(task_id: u64, op: impl FnOnce(&mut FdTable) -> R) -> Option<R> {
    let mut g = TABLES.lock();
    let map = g.as_mut()?;
    let table = map.entry(task_id).or_insert_with(|| {
        let mut t = FdTable::new();
        // Stage-4 default: all three stdio slots route to the
        // kernel console. stdin reads return 0 (EOF) until a
        // real keyboard/serial backing lands.
        let console: Arc<dyn FileOps> = Arc::new(ConsoleFile::new());
        t.set(
            0,
            FdEntry {
                ops: console.clone(),
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        );
        t.set(
            1,
            FdEntry {
                ops: console.clone(),
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        );
        t.set(
            2,
            FdEntry {
                ops: console,
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        );
        t
    });
    Some(op(table))
}

/// Per-tty backing. Reads drain the input ring; writes go to the
/// kernel console via `narf_console::Writer`. Each `ConsoleFile`
/// instance owns its own foreground process group, so once `/dev/pts`
/// lands a per-PTY TIOCSPGRP write only affects that one tty.
///
/// The stdio fast-path (fd 0/1/2 sharing one `Arc<ConsoleFile>`) still
/// shares fg_pgrp across the three slots — that matches POSIX: stdio
/// inherits from the controlling tty, so tcsetpgrp on fd 0 is visible
/// on fd 1/2 of the same shell.
pub struct ConsoleFile {
    /// Foreground process group for this tty. 0 = unset; a job-
    /// control shell calls `tcsetpgrp` (TIOCSPGRP) at startup.
    fg_pgrp: AtomicU64,
}

impl ConsoleFile {
    pub const fn new() -> Self {
        Self {
            fg_pgrp: AtomicU64::new(0),
        }
    }
}

impl Default for ConsoleFile {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ConsoleFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConsoleFile")
            .field("fg_pgrp", &self.fg_pgrp.load(Ordering::Relaxed))
            .finish()
    }
}

// ── Terminal ioctl numbers (Linux ABI) ─────────────────────────────
//
// The console serves as the system tty. Real userspace (ls, bash,
// vi, less) probes these to decide whether stdout is a terminal,
// what dimensions to draw to, and how many bytes are waiting to be
// read. Returning a sensible default for each is enough to unblock
// every "is this a tty" code path; the actual values can stay
// 80x24/0/etc. until a real tty driver lands.

/// `ioctl(fd, TCGETS, &termios)` — read termios state. musl's
/// `isatty(fd)` calls `tcgetattr(fd, ...)` → `ioctl(fd, TCGETS, ...)`
/// and treats success as "this fd is a tty". Without it, libc
/// thinks stdio isn't a tty → switches to block-buffered mode →
/// `puts` / `printf` output never flushes on \n and a short-lived
/// program (busybox pwd, uname, etc.) exits before fflush runs.
pub const TCGETS: u32 = 0x5401;
/// `ioctl(fd, TIOCGWINSZ, &winsize)` — query window dimensions.
pub const TIOCGWINSZ: u32 = 0x5413;
/// `ioctl(fd, TIOCSWINSZ, &winsize)` — set window dimensions.
pub const TIOCSWINSZ: u32 = 0x5414;
/// `ioctl(fd, FIONREAD, &i32)` — bytes immediately readable.
pub const FIONREAD: u32 = 0x541B;
/// `ioctl(fd, TIOCGPGRP, &pid_t)` — foreground process group.
pub const TIOCGPGRP: u32 = 0x540F;
/// `ioctl(fd, TIOCSPGRP, &pid_t)` — set foreground process group.
pub const TIOCSPGRP: u32 = 0x5410;

/// POSIX `struct winsize` — row/col + pixel hints. Pixel fields
/// stay zero (we don't model a pixel-aware terminal).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// Default console dimensions. Override via TIOCSWINSZ; survives
/// until reboot. 80x24 matches the historical VT default and is
/// what every "$LINES not set" autocheck falls back to.
static CONSOLE_WINSIZE: IrqSafeSpinLock<Winsize> = IrqSafeSpinLock::new(Winsize {
    ws_row: 24,
    ws_col: 80,
    ws_xpixel: 0,
    ws_ypixel: 0,
});

/// Query the current console window size. Test hook + introspection.
pub fn console_winsize() -> Winsize {
    *CONSOLE_WINSIZE.lock()
}

/// Override the console window size. Wired by `TIOCSWINSZ`.
pub fn set_console_winsize(ws: Winsize) {
    *CONSOLE_WINSIZE.lock() = ws;
}

/// Reset terminal state — test hook. Per-tty `fg_pgrp` drops with
/// the `ConsoleFile` Arc when the test tears down its fd table.
#[doc(hidden)]
pub fn __test_reset_tty() {
    *CONSOLE_WINSIZE.lock() = Winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
}

impl FileOps for ConsoleFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Non-blocking raw-mode read. Drains whatever bytes are in the
        // BYTE_RING (serial RX / keyboard ASCII path) without blocking.
        //
        // Returns Ok(0) immediately when the ring is empty — callers that
        // want blocking behaviour (the shell's `read_byte` loop) retry with
        // a brief usleep(10_000) between attempts, matching the pattern that
        // `devfs::DevConsole::read` already uses for /dev/console.
        //
        // Approach: raw mode (no line discipline). The shell's classify()
        // function handles backspace / submit / ignore semantics per-byte.
        let mut n = 0usize;
        while n < buf.len() {
            match narf_input::pop_ascii_byte() {
                Some(b) => {
                    buf[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
        let result = Ok(n);
        Box::pin(async move { result })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = buf.len();
        // Eagerly write: the future just reports the count.
        use core::fmt::Write as _;
        let mut w = narf_console::Writer;
        for &b in buf {
            let _ = w.write_char(b as char);
        }
        Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    /// `poll(2)` readiness — POLLIN only when at least one ASCII
    /// byte is queued in the input ring, POLLOUT always (the
    /// kernel console writer never blocks). Returning POLLIN
    /// unconditionally — the default — breaks interactive shells:
    /// busybox sh's read-loop does `poll(stdin, POLLIN, -1)`,
    /// reads zero bytes when the ring is empty, interprets that
    /// as EOF and exits the moment the user gets to a prompt.
    fn poll_readiness(&self) -> u32 {
        let mut mask = narf_filesystem::POLL_OUT;
        if narf_input::pending_bytes() > 0 {
            mask |= narf_filesystem::POLL_IN;
        }
        mask
    }
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        // Terminal ioctls. All return Ok(0) on success; any
        // user-pointer fault is reported as FsError::InvalidData
        // (→ EINVAL at the syscall layer — close enough to EFAULT
        // for ABI purposes since the wire shape is the same).
        match cmd {
            TCGETS => {
                // Return a zeroed `struct termios`. We're not a
                // real tty, but musl's isatty just checks success;
                // the actual termios fields aren't consulted by
                // anything that runs inside this kernel. Buffer
                // is 60 bytes on Linux x86_64 — overshoot to 64
                // for safety.
                let zero = [0u8; 64];
                if unsafe { crate::handlers::copy_to_user(arg as u64, &zero) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCGWINSZ => {
                let ws = console_winsize();
                let bytes: [u8; 8] = unsafe { core::mem::transmute(ws) };
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCSWINSZ => {
                let mut bytes = [0u8; 8];
                if unsafe { crate::handlers::copy_from_user(&mut bytes, arg as u64) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                let ws: Winsize = unsafe { core::mem::transmute(bytes) };
                set_console_winsize(ws);
                Ok(0)
            }
            FIONREAD => {
                // Best-effort: peek the input ring's current depth.
                let n: i32 = narf_input::pending_bytes() as i32;
                let bytes = n.to_le_bytes();
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCGPGRP => {
                // pid_t = i32 on Linux x86_64.
                //
                // POSIX `tcgetpgrp(3)` returns the foreground process
                // group ID of the controlling terminal. NARF boots
                // straight into a single console without going through
                // a getty/login that would `setsid` + `TIOCSCTTY` +
                // `tcsetpgrp` — so the first caller to ask for the
                // foreground pgid arrives with `fg_pgrp == 0`. Return
                // a real pgid in that case by auto-installing the
                // caller's pgrp, mirroring how a session leader
                // implicitly acquires the controlling tty.
                //
                // Without this, busybox `sh`'s job-control init loop
                // (`while tcgetpgrp(0) != getpgrp() { raise(SIGTTIN); }`)
                // spins forever because tcgetpgrp returns 0 and
                // getpgrp returns the shell's tid.
                let mut pgrp = self.fg_pgrp.load(Ordering::Acquire);
                if pgrp == 0 {
                    let caller_pgrp = crate::handlers::current_task_pgid();
                    if caller_pgrp != 0 {
                        // CAS so two concurrent first-callers can't
                        // race-install different pgrps; the loser
                        // observes the winner's pgrp.
                        match self.fg_pgrp.compare_exchange(
                            0,
                            caller_pgrp,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => pgrp = caller_pgrp,
                            Err(observed) => pgrp = observed,
                        }
                    }
                }
                let bytes = (pgrp as i32).to_le_bytes();
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCSPGRP => {
                let mut bytes = [0u8; 4];
                if unsafe { crate::handlers::copy_from_user(&mut bytes, arg as u64) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                let pgrp = i32::from_le_bytes(bytes);
                if pgrp < 0 {
                    return Err(FsError::InvalidData);
                }
                self.fg_pgrp.store(pgrp as u64, Ordering::Release);
                Ok(0)
            }
            _ => Err(FsError::Unsupported),
        }
    }
}

/// Duplicate every fd entry from `parent` into a fresh table for
/// `child`. POSIX fork(2): the child inherits an independent copy
/// of the descriptor table whose entries reference the same
/// underlying open-file objects (Arc::clone on the inner `FileOps`
/// trait object — refcount up, no extra `Box::new`). Per-fd `flags`
/// and `offset` snapshot at fork time.
///
/// Idempotent only if the child table doesn't already exist; if it
/// does, the existing table is overwritten with the parent's
/// snapshot — fork is the entry point that should hit this, and a
/// child's table cannot pre-exist its own creation.
///
/// Returns the number of fds copied.
pub fn fork(parent: u64, child: u64) -> usize {
    let mut g = TABLES.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => return 0,
    };
    let parent_slots: Vec<Option<FdEntry>> = map
        .get(&parent)
        .map(|t| t.slots.clone())
        .unwrap_or_default();
    let copied = parent_slots.iter().filter(|s| s.is_some()).count();
    let mut child_table = FdTable::new();
    child_table.slots = parent_slots;
    map.insert(child, child_table);
    copied
}

/// Drop the entire fd table for `task_id`. Call on task exit so
/// the FileOps `Arc`s can release.
pub fn detach(task_id: u64) {
    if let Some(map) = TABLES.lock().as_mut() {
        map.remove(&task_id);
    }
    // Drop any advisory POSIX locks the task held so its peers can
    // make progress on shared inodes.
    #[cfg(feature = "linux-compat")]
    locks::release_owner(task_id);
}

/// Test/reset hook — wipe every per-task table. Lets independent
/// kernel_test cases share state cleanly.
#[doc(hidden)]
pub fn __test_reset() {
    *TABLES.lock() = Some(BTreeMap::new());
}

/// Number of tasks with at least one fd installed. Diagnostic.
pub fn live_task_count() -> usize {
    TABLES.lock().as_ref().map(|m| m.len()).unwrap_or(0)
}

// ── Advisory POSIX file locks (Wave-68, linux-compat) ──────────────
//
// `fcntl(F_SETLK/F_SETLKW/F_GETLK)` advisory range locks. Keyed by
// the underlying open-file object identity (`Arc::as_ptr` cast to
// usize), so two fds that point at the same inode share locks.
// Conflict rule: a write lock conflicts with any other lock on an
// overlapping range; a read lock conflicts only with a write lock.
// `owner` is the holding task id — same owner replaces / extends.
//
// F_SETLKW (blocking) is *not* wired to a waker; today it returns
// EAGAIN on conflict just like F_SETLK. A follow-up wave will add
// the per-inode wait queue.

#[cfg(feature = "linux-compat")]
pub mod locks {
    use super::*;

    /// `l_type` values from POSIX `struct flock`.
    pub const F_RDLCK: i16 = 0;
    pub const F_WRLCK: i16 = 1;
    pub const F_UNLCK: i16 = 2;

    #[derive(Clone, Copy, Debug)]
    pub struct Lock {
        pub owner: u64,
        pub ty: i16, // F_RDLCK or F_WRLCK
        pub start: i64,
        pub len: i64, // 0 = to EOF
    }

    impl Lock {
        /// Inclusive end of this range; `i64::MAX` if `len == 0`.
        pub fn end(&self) -> i64 {
            if self.len == 0 {
                i64::MAX
            } else {
                self.start.saturating_add(self.len).saturating_sub(1)
            }
        }
        pub fn overlaps(&self, other: &Lock) -> bool {
            self.start <= other.end() && other.start <= self.end()
        }
        pub fn conflicts(&self, other: &Lock) -> bool {
            if self.owner == other.owner {
                return false;
            }
            if !self.overlaps(other) {
                return false;
            }
            self.ty == F_WRLCK || other.ty == F_WRLCK
        }
    }

    static TABLE: IrqSafeSpinLock<Option<BTreeMap<usize, Vec<Lock>>>> = IrqSafeSpinLock::new(None);

    fn ensure() {
        let mut g = TABLE.lock();
        if g.is_none() {
            *g = Some(BTreeMap::new());
        }
    }

    /// Attempt to install `req`. Returns Ok if installed, Err with
    /// the first conflicting lock if not.
    pub fn try_set(key: usize, req: Lock) -> Result<(), Lock> {
        ensure();
        let mut g = TABLE.lock();
        let map = g.as_mut().unwrap();
        let bucket = map.entry(key).or_insert_with(Vec::new);
        if req.ty == F_UNLCK {
            bucket.retain(|l| !(l.owner == req.owner && l.overlaps(&req)));
            return Ok(());
        }
        for l in bucket.iter() {
            if l.conflicts(&req) {
                return Err(*l);
            }
        }
        // Merge with same-owner locks of the same type, drop covered.
        bucket.retain(|l| !(l.owner == req.owner && l.overlaps(&req)));
        bucket.push(req);
        Ok(())
    }

    /// Probe `req`. If a conflict exists, returns the blocker; else
    /// returns None (caller should report F_UNLCK).
    pub fn probe(key: usize, req: Lock) -> Option<Lock> {
        let g = TABLE.lock();
        let map = match g.as_ref() {
            Some(m) => m,
            None => return None,
        };
        let bucket = map.get(&key)?;
        bucket.iter().copied().find(|l| l.conflicts(&req))
    }

    /// Drop every lock owned by `owner`. Call on task exit so leaked
    /// locks don't pin out other tasks forever.
    pub fn release_owner(owner: u64) {
        let mut g = TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => return,
        };
        for bucket in map.values_mut() {
            bucket.retain(|l| l.owner != owner);
        }
        map.retain(|_, v| !v.is_empty());
    }

    #[doc(hidden)]
    pub fn __test_reset() {
        *TABLE.lock() = Some(BTreeMap::new());
    }
}
