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

    /// Insert `entry` at the lowest free fd. POSIX `open(2)` returns the
    /// lowest-numbered descriptor not currently open — so when stdio
    /// occupies 0..=2 this lands at 3+, but a program that closes a low
    /// fd gets that slot back. busybox ash relies on this: to redirect an
    /// async job's stdin it does `close(0); if (open("/dev/null") != 0)
    /// error`, asserting the reopened fd is exactly 0. Skipping 0..=2
    /// unconditionally made every `cmd &` in the distro fail with
    /// "can't open '/dev/null'".
    pub fn open(&mut self, entry: FdEntry) -> u32 {
        for (i, s) in self.slots.iter_mut().enumerate() {
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
    /// `fcntl(F_DUPFD)` / `F_DUPFD_CLOEXEC`, which POSIX defines as the
    /// lowest free fd at or above `min` — honour `min` verbatim (a free
    /// slot below 3, e.g. a closed stdio fd, is a valid target).
    pub fn open_at_least(&mut self, entry: FdEntry, min: u32) -> u32 {
        let min = min as usize;
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

    /// `close_range(first, last, flags)` — close every open fd in the
    /// inclusive range `[first, last]`. With `cloexec` set
    /// (CLOSE_RANGE_CLOEXEC) the fds are marked FD_CLOEXEC instead of
    /// being closed. Out-of-range bounds are clamped to the table.
    pub fn close_range(&mut self, first: u32, last: u32, cloexec: bool) {
        let lo = first as usize;
        if lo >= self.slots.len() {
            return;
        }
        let hi = (last as usize).min(self.slots.len() - 1);
        if hi < lo {
            return;
        }
        for slot in self.slots[lo..=hi].iter_mut() {
            if let Some(entry) = slot {
                if cloexec {
                    entry.flags |= FD_CLOEXEC;
                } else {
                    *slot = None;
                }
            }
        }
    }

    /// Close every fd marked `FD_CLOEXEC` (the exec path). Returns the
    /// number closed. Dropping each `Some` entry releases its
    /// `Arc<dyn FileLike>` reference (closing the underlying object
    /// when this was the last holder).
    pub fn close_cloexec_slots(&mut self) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if let Some(entry) = slot {
                if entry.flags & FD_CLOEXEC != 0 {
                    *slot = None;
                    n += 1;
                }
            }
        }
        n
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

// ── Sharded per-task table ─────────────────────────────────────────

/// `TaskId.raw()` → the task's fd table. The table is behind an
/// `Arc<IrqSafeSpinLock<…>>` so that CLONE_FILES threads can SHARE one table
/// (the same `Arc` is installed under each thread's TaskId; see `share`) while
/// fork still gets an independent COPY (`fork`). The shard lock guards only the
/// map (Arc lookup/insert/remove); fd operations run under the per-table inner
/// lock, so distinct processes don't serialise and a long `poll_blocking` read
/// holds only its own table's lock, not the whole shard.
type Tables = BTreeMap<u64, Arc<IrqSafeSpinLock<FdTable>>>;

/// A fresh fd table pre-populated with the three stdio slots routed to the
/// kernel console (stdin reads EOF until a real backing lands).
fn fresh_table() -> FdTable {
    let mut t = FdTable::new();
    let console: Arc<dyn FileOps> = Arc::new(ConsoleFile::new());
    for fd in 0..3u32 {
        t.set(
            fd,
            FdEntry {
                ops: console.clone(),
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        );
    }
    t
}

/// Number of fd-table shards (power of two). The fd table is consulted on
/// EVERY fd syscall (read/write/epoll resolve fd→FileOps via `with_table`),
/// keyed by task id. A single global lock there serialized all tasks — under
/// an 8-worker server every read/write/poll contended one lock (a hot
/// contributor to the 8-thread mt-echo lock-spin wedge). Sharding by task id
/// means distinct tasks almost never share a shard lock. Same idea as the
/// TCP `TCB_TABLE` / `CONN_INDEX` shards.
const TABLE_SHARDS: usize = 32;

#[inline]
fn table_shard(task_id: u64) -> usize {
    (task_id as usize) & (TABLE_SHARDS - 1)
}

static TABLES: [IrqSafeSpinLock<Option<Tables>>; TABLE_SHARDS] =
    [const { IrqSafeSpinLock::new(None) }; TABLE_SHARDS];

/// Initialise the per-task fd table store. Called once at boot
/// before any task can install fds.
pub fn init() {
    for shard in TABLES.iter() {
        *shard.lock() = Some(BTreeMap::new());
    }
}

/// Look up + run `op` against the table for `task_id`. Creates a
/// fresh table — pre-populated with stdio at fds 0/1/2 — on first
/// reference. Returns the closure's value.
pub fn with_table<R>(task_id: u64, op: impl FnOnce(&mut FdTable) -> R) -> Option<R> {
    // Get-or-create this task's table Arc under the shard lock, clone the Arc,
    // then DROP the shard lock before running `op` under the per-table lock.
    // This keeps the hot shard lock held only for the brief map lookup, and lets
    // CLONE_FILES siblings (who share one Arc) serialise on the table itself.
    let arc = {
        let mut g = TABLES[table_shard(task_id)].lock();
        let map = g.as_mut()?;
        map.entry(task_id)
            .or_insert_with(|| Arc::new(IrqSafeSpinLock::new(fresh_table())))
            .clone()
    };
    let mut table = arc.lock();
    Some(op(&mut table))
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
/// SMAP-safe read of a 60-byte `struct termios` from a user pointer.
/// Uses `read_unaligned` inside the SMAP window deliberately: a
/// `copy_nonoverlapping`/memcpy (what `copy_from_user` inlines to for a
/// const-size buffer) escapes the STAC/CLAC bracket and faults the
/// kernel supervisor-reading the user page.
unsafe fn read_user_termios(uptr: u64) -> Result<[u8; 60], FsError> {
    if uptr == 0 || crate::handlers::validate_user_range(uptr, 60).is_err() {
        return Err(FsError::InvalidData);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range-validated; with_user_access brackets SMAP and
    // read_unaligned emits inline loads.
    let v = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::read_unaligned(uptr as *const [u8; 60])
        })
    };
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: range-validated; no SMAP off x86_64.
    let v = unsafe { core::ptr::read_unaligned(uptr as *const [u8; 60]) };
    Ok(v)
}

/// SMAP-safe write of a 60-byte `struct termios` to a user pointer.
unsafe fn write_user_termios(uptr: u64, src: [u8; 60]) -> Result<(), FsError> {
    if uptr == 0 || crate::handlers::validate_user_range(uptr, 60).is_err() {
        return Err(FsError::InvalidData);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range-validated; with_user_access brackets SMAP and
    // write_unaligned emits inline stores.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut [u8; 60], src)
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: range-validated; no SMAP off x86_64.
    unsafe {
        core::ptr::write_unaligned(uptr as *mut [u8; 60], src);
    }
    Ok(())
}

/// The boot console behind fd 0/1/2. Stateless: the console is a
/// singleton, so its terminal attributes (termios, winsize) and job-
/// control foreground pgrp all live in `narf_filesystem::console_tty`,
/// shared with `/dev/console` (`DevConsole`). A `tcsetpgrp` on fd 0 is
/// therefore visible to the shell reading `/dev/console` and vice versa.
pub struct ConsoleFile;

impl ConsoleFile {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ConsoleFile {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ConsoleFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConsoleFile").finish()
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
/// `ioctl(fd, TCSETS, &termios)` — set terminal attributes (immediate).
pub const TCSETS: u32 = 0x5402;
/// `ioctl(fd, TCSETSW, &termios)` — set terminal attributes (drain output).
pub const TCSETSW: u32 = 0x5403;
/// `ioctl(fd, TCSETSF, &termios)` — set terminal attributes (drain + flush).
pub const TCSETSF: u32 = 0x5404;
/// `ioctl(fd, TIOCSCTTY, 0)` — make this the caller's controlling tty.
pub const TIOCSCTTY: u32 = 0x540E;
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

/// Reset terminal state — test hook. The console's foreground pgrp +
/// termios + line discipline are singleton state in `console_tty` now, so
/// clear them too (a leaked fg_pgrp would perturb later job-control tests).
#[doc(hidden)]
pub fn __test_reset_tty() {
    *CONSOLE_WINSIZE.lock() = Winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    narf_filesystem::console_tty::__test_reset_cooked();
}

impl FileOps for ConsoleFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Route through the single shared console line discipline
        // (`narf_filesystem::console_tty`), the same path /dev/console
        // uses. It owns the termios + cooked/raw mode and drains both
        // input rings (serial bytes + translated keys), so fd 0 and
        // /dev/console see one console with one termios. Cooked mode
        // (the default) returns whole lines with echo + backspace;
        // a program that TCSETSes raw gets byte-at-a-time.
        let n = narf_filesystem::console_tty::read_into(buf);
        Box::pin(async move { Ok(n) })
    }
    /// Block an empty console read on the input waker (woken by the
    /// serial/keyboard IRQ) instead of returning a spurious 0. This is what
    /// lets an interactive shell `read(stdin)` truly sleep until a keystroke
    /// rather than busy-poll. sys_read parks via the `console_read_pending`
    /// path when this is true and the fd is blocking. Delegates to the
    /// shared discipline: park while no completed line/byte is buffered.
    fn block_on_input(&self) -> bool {
        narf_filesystem::console_tty::block_on_input()
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
        if narf_filesystem::console_tty::readable_bytes() > 0 {
            mask |= narf_filesystem::POLL_IN;
        }
        mask
    }
    /// Job control: the boot console's stable tty id.
    fn tty_id(&self) -> Option<u32> {
        Some(narf_filesystem::TTY_ID_CONSOLE)
    }
    /// Job control: the console's (singleton) foreground process group.
    fn tty_fg_pgrp(&self) -> Option<u64> {
        Some(narf_filesystem::console_tty::fg_pgrp())
    }
    /// Job control: TOSTOP from the shared console termios.
    fn tty_tostop(&self) -> bool {
        narf_filesystem::console_tty::tostop()
    }
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        // Terminal ioctls. All return Ok(0) on success; any
        // user-pointer fault is reported as FsError::InvalidData
        // (→ EINVAL at the syscall layer — close enough to EFAULT
        // for ABI purposes since the wire shape is the same).
        match cmd {
            TCGETS => {
                // Return the current termios from the shared console_tty
                // (cooked default until a program TCSETS its own), so
                // isatty(0) succeeds AND an interactive shell sees a real
                // cooked tty (ICANON|ECHO). The discipline now enforces it.
                let raw = narf_filesystem::console_tty::termios();
                // SAFETY: `arg` is the user `struct termios *` from ioctl;
                // write_user_termios range-validates + SMAP-brackets it.
                unsafe { write_user_termios(arg as u64, raw)? };
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                // Round-trip the caller's termios into the shared state so
                // a program can switch raw/cooked; the console_tty line
                // discipline reads these flags on the next read (what
                // vi/less/readline rely on). Visible to TCGETS on fd 1/2
                // and /dev/console alike.
                // SAFETY: `arg` is the validated user `struct termios *`.
                let raw = unsafe { read_user_termios(arg as u64)? };
                narf_filesystem::console_tty::set_termios(raw);
                Ok(0)
            }
            TIOCSCTTY => {
                // Make the boot console the caller's controlling terminal.
                // Needed after setsid() (which detaches): a getty/login that
                // claims the console as its session's ctty records it here so
                // the job-control SIGTTIN/SIGTTOU check recognises it.
                #[cfg(feature = "linux-compat")]
                crate::handlers::set_controlling_tty_console(crate::handlers::current_task_id());
                Ok(0)
            }
            TIOCGWINSZ => {
                let ws = console_winsize();
                // SAFETY: `Winsize` is a `repr(C)` POD of four `u16` (8 bytes)
                // with no padding, so its layout matches `[u8; 8]` exactly.
                // SAFETY: Valid memory or trusted environment
                let bytes: [u8; 8] = unsafe { core::mem::transmute(ws) };
                // SAFETY: `copy_to_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 8-byte
                // `bytes` buffer holding the serialized `struct winsize`.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCSWINSZ => {
                let mut bytes = [0u8; 8];
                // SAFETY: `copy_from_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 8-byte
                // `bytes` buffer that receives the serialized `struct winsize`.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_from_user(&mut bytes, arg as u64) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                // SAFETY: `Winsize` is a `repr(C)` POD of four `u16` (8 bytes)
                // with no padding and every bit pattern valid, so the
                // round-trip from `[u8; 8]` is sound.
                // SAFETY: Valid memory or trusted environment
                let ws: Winsize = unsafe { core::mem::transmute(bytes) };
                set_console_winsize(ws);
                Ok(0)
            }
            FIONREAD => {
                // Best-effort: bytes immediately readable through the
                // shared discipline (completed lines + queued raw input).
                let n: i32 = narf_filesystem::console_tty::readable_bytes() as i32;
                let bytes = n.to_le_bytes();
                // SAFETY: `copy_to_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 4-byte
                // little-endian encoding of the `i32` pending-byte count.
                // SAFETY: Valid memory or trusted environment
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
                // fg_pgrp is kept in task-id space internally; report it
                // to userspace in the visible-pid space getpid/getpgrp use.
                let pgrp = crate::handlers::pgid_to_user(
                    narf_filesystem::console_tty::fg_pgrp_or_install(
                        crate::handlers::current_task_pgid(),
                    ),
                );
                let bytes = (pgrp as i32).to_le_bytes();
                // SAFETY: `copy_to_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 4-byte
                // little-endian encoding of the `pid_t` foreground pgid.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCSPGRP => {
                let mut bytes = [0u8; 4];
                // SAFETY: `copy_from_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 4-byte
                // buffer that receives the little-endian `pid_t` pgid.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_from_user(&mut bytes, arg as u64) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                let pgrp = i32::from_le_bytes(bytes);
                if pgrp < 0 {
                    return Err(FsError::InvalidData);
                }
                // Userspace passes a visible pid; the tty stores fg_pgrp in
                // task-id space (consistent with read_pgid / the SIGTTIN
                // check), so translate before storing.
                let pgrp = crate::handlers::pgid_from_user(pgrp as u64);
                narf_filesystem::console_tty::set_fg_pgrp(pgrp);
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
    // Snapshot the parent's slots (under the parent table's own lock), build an
    // INDEPENDENT copy in a fresh Arc, install for the child. Never hold two
    // shard locks at once → no lock-ordering hazard.
    let parent_arc = {
        let g = TABLES[table_shard(parent)].lock();
        match g.as_ref() {
            Some(m) => m.get(&parent).cloned(),
            None => return 0,
        }
    };
    let parent_slots: Vec<Option<FdEntry>> = match parent_arc {
        Some(a) => a.lock().slots.clone(),
        None => Vec::new(),
    };
    let copied = parent_slots.iter().filter(|s| s.is_some()).count();
    let mut child_table = FdTable::new();
    child_table.slots = parent_slots;
    let mut g = TABLES[table_shard(child)].lock();
    match g.as_mut() {
        Some(m) => {
            m.insert(child, Arc::new(IrqSafeSpinLock::new(child_table)));
            copied
        }
        None => 0,
    }
}

/// CLONE_FILES: install the SAME table `Arc` under the child's TaskId so the
/// child and parent (and every other thread of the process) share one fd table
/// — an fd opened by any thread is visible to all, and `close` in one closes it
/// for all (Linux thread semantics). The table is freed only when the last
/// sharer `detach`es (Arc refcount). Returns the number of fds in the table.
pub fn share(parent: u64, child: u64) -> usize {
    // Get-or-create the parent's table Arc atomically (same logic as
    // `with_table`'s first-touch), then install that same Arc for the child.
    let arc = {
        let mut g = TABLES[table_shard(parent)].lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => return 0,
        };
        map.entry(parent)
            .or_insert_with(|| Arc::new(IrqSafeSpinLock::new(fresh_table())))
            .clone()
    };
    let n = arc.lock().slots.iter().filter(|s| s.is_some()).count();
    if let Some(m) = TABLES[table_shard(child)].lock().as_mut() {
        m.insert(child, arc);
    }
    n
}

/// Close every `FD_CLOEXEC`-marked fd for `task_id` (the exec path).
/// Returns the count closed; no-op if the task has no table (never
/// opened an fd). Shares one fd table with CLONE_FILES siblings, so a
/// CLOEXEC close is visible to them too — matching Linux, where exec
/// unshares files first; NARF's exec implies a non-shared table.
pub fn close_cloexec(task_id: u64) -> usize {
    let arc = {
        let g = TABLES[table_shard(task_id)].lock();
        match g.as_ref().and_then(|m| m.get(&task_id).cloned()) {
            Some(a) => a,
            None => return 0,
        }
    };
    let n = arc.lock().close_cloexec_slots();
    n
}

/// Drop the entire fd table for `task_id`. Call on task exit so
/// the FileOps `Arc`s can release.
pub fn detach(task_id: u64) {
    if let Some(map) = TABLES[table_shard(task_id)].lock().as_mut() {
        map.remove(&task_id);
    }
    // Drop any advisory POSIX locks the task held so its peers can
    // make progress on shared inodes — and wake their F_SETLKW waiters
    // NOW. This is the FIRST of the two exit-path release_owner calls
    // (release_task_tables runs after and finds the table already
    // drained), so the immediate wake must fire from here or a waiter
    // blocked on a dead holder only gets its 1 ms backstop.
    #[cfg(feature = "linux-compat")]
    for key in locks::release_owner(task_id) {
        for (waiter, w) in locks::drain_waiters(key) {
            crate::handlers::wake_one(waiter, w);
        }
    }
}

/// Test/reset hook — wipe every per-task table. Lets independent
/// kernel_test cases share state cleanly.
#[doc(hidden)]
pub fn __test_reset() {
    for shard in TABLES.iter() {
        *shard.lock() = Some(BTreeMap::new());
    }
}

/// Number of tasks with at least one fd installed. Diagnostic.
pub fn live_task_count() -> usize {
    TABLES
        .iter()
        .map(|s| s.lock().as_ref().map(|m| m.len()).unwrap_or(0))
        .sum()
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
        let bucket = map.entry(key).or_default();
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
        let map = g.as_ref()?;
        let bucket = map.get(&key)?;
        bucket.iter().copied().find(|l| l.conflicts(&req))
    }

    /// Drop every lock owned by `owner`. Call on task exit so leaked
    /// locks don't pin out other tasks forever. Returns the keys that
    /// actually lost a lock — the caller wakes their F_SETLKW waiters
    /// (the wake needs `wake_one`, which lives with the handlers).
    pub fn release_owner(owner: u64) -> Vec<usize> {
        let mut g = TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => return Vec::new(),
        };
        let mut touched = Vec::new();
        for (key, bucket) in map.iter_mut() {
            let before = bucket.len();
            bucket.retain(|l| l.owner != owner);
            if bucket.len() != before {
                touched.push(*key);
            }
        }
        map.retain(|_, v| !v.is_empty());
        touched
    }

    // ── F_SETLKW waiters ─────────────────────────────────────────────
    //
    // key → (tid → waker). Registered by `park_should_block` while a
    // task is parked in a blocked F_SETLKW (the uctx `flock_key` field
    // routes it here, exactly like `futex_uaddr` routes to the futex
    // queue); drained-and-woken by the unlock paths so a waiter retries
    // IMMEDIATELY instead of riding out its 1 ms wheel backstop. The
    // backstop stays armed — it bounds the register-vs-unlock race
    // window to one period, so a missed wake degrades, never wedges.
    static WAITERS: IrqSafeSpinLock<Option<BTreeMap<usize, BTreeMap<u64, core::task::Waker>>>> =
        IrqSafeSpinLock::new(None);

    pub fn register_waiter(key: usize, tid: u64, waker: core::task::Waker) {
        let mut g = WAITERS.lock();
        g.get_or_insert_with(BTreeMap::new)
            .entry(key)
            .or_default()
            .insert(tid, waker);
    }

    pub fn drop_waiter(key: usize, tid: u64) {
        let mut g = WAITERS.lock();
        if let Some(m) = g.as_mut() {
            if let Some(set) = m.get_mut(&key) {
                set.remove(&tid);
                if set.is_empty() {
                    m.remove(&key);
                }
            }
        }
    }

    /// Drop `tid` from every key's waiter set (task exit).
    pub fn drop_waiter_owner(tid: u64) {
        let mut g = WAITERS.lock();
        if let Some(m) = g.as_mut() {
            for set in m.values_mut() {
                set.remove(&tid);
            }
            m.retain(|_, s| !s.is_empty());
        }
    }

    /// Take every waiter parked on `key`. The caller fires the wakes
    /// AFTER this lock is dropped (wake() may re-enter the scheduler).
    pub fn drain_waiters(key: usize) -> Vec<(u64, core::task::Waker)> {
        let mut g = WAITERS.lock();
        g.as_mut()
            .and_then(|m| m.remove(&key))
            .map(|set| set.into_iter().collect())
            .unwrap_or_default()
    }

    #[doc(hidden)]
    pub fn __test_reset() {
        *TABLE.lock() = Some(BTreeMap::new());
        *WAITERS.lock() = Some(BTreeMap::new());
    }
}
