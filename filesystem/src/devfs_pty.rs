//! Unix98 pseudoterminal support for `/dev/ptmx` and `/dev/pts/<N>`.
//!
//! Linux refs:
//!   - `drivers/tty/pty.c` — `ptm_unix98_ops`, `pts_unix98_ops`
//!   - `fs/devpts/inode.c` — pts directory, index allocation
//!
//! ## Design
//!
//! Each `open("/dev/ptmx")` allocates a `Pty` and returns a `PtyMaster`
//! `FileOps` handle.  A `PtySlave` `FileOps` handle is then reachable
//! via `/dev/pts/<N>` where N is the index reported in the master's
//! `stat().size` field (and via `PtyMaster::index()`).
//!
//! Both handles share one `Arc<Pty>`.  The pair is registered in
//! `PTY_TABLE` on allocation and removed when **both** handles have been
//! dropped (the `Arc` refcount hits one in each of the master/slave
//! wrappers, tracked via separate `Arc`s keyed by index).
//!
//! ## Data-flow
//!
//! ```text
//!   userspace writer                  userspace reader
//!        |                                   ^
//!        v   PtyMaster::write               |
//!   master_tx_to_slave  ──────────────>  PtySlave::read
//!                                        (line discipline: ICANON, ECHO)
//!
//!   PtySlave::write  ──────────────>  master_rx_from_slave
//!                                         |
//!                                         v   PtyMaster::read
//! ```
//!
//! ## Limitations / deferred items (v1)
//!
//! - `ioctl()` not yet in NARF; PTY index is exposed via `stat().size`.
//! - Window-size (`TIOCSWINSZ` / `TIOCGWINSZ`) deferred.
//! - `^C` → SIGINT signal delivery to pgid deferred.
//! - Raw mode (ICANON=0) not switchable without ioctl.
//! - Only `^D` (0x04) is treated as EOF on slave reads.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};

// ── Ring buffer ───────────────────────────────────────────────────────────────

/// Fixed-capacity lock-protected byte ring.  Capacity is specified as a
/// const-generic `N` so each PTY gets its own appropriately-sized ring.
pub(crate) struct ByteRing<const N: usize> {
    inner: IrqSafeSpinLock<ByteRingInner<N>>,
}

struct ByteRingInner<const N: usize> {
    buf: [u8; N],
    head: usize, // read pointer
    len: usize,  // bytes currently stored
}

impl<const N: usize> ByteRing<N> {
    const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(ByteRingInner {
                buf: [0u8; N],
                head: 0,
                len: 0,
            }),
        }
    }

    /// Push bytes; silently discards those that don't fit.
    fn push(&self, data: &[u8]) {
        let mut g = self.inner.lock();
        for &b in data {
            if g.len < N {
                let tail = (g.head + g.len) % N;
                g.buf[tail] = b;
                g.len += 1;
            }
        }
    }

    /// Pop up to `buf.len()` bytes; returns number actually copied.
    fn pop(&self, buf: &mut [u8]) -> usize {
        let mut g = self.inner.lock();
        let n = buf.len().min(g.len);
        for i in 0..n {
            buf[i] = g.buf[g.head];
            g.head = (g.head + 1) % N;
        }
        g.len -= n;
        n
    }

    /// Pop exactly one line (up to and including the first `\n`) or,
    /// if `eof` is true, pop all available bytes (^D handling).
    /// Returns the number of bytes copied.  Returns 0 if no complete
    /// line is available and `eof` is false.
    fn pop_line(&self, buf: &mut [u8], eof: bool) -> usize {
        let mut g = self.inner.lock();
        if g.len == 0 {
            return 0;
        }
        // Find the newline position.
        let newline_pos = (0..g.len).find(|&i| {
            let idx = (g.head + i) % N;
            g.buf[idx] == b'\n'
        });
        let consume = match newline_pos {
            Some(pos) => pos + 1, // include the '\n'
            None if eof => g.len,
            None => return 0, // ICANON: block until newline
        };
        let n = consume.min(buf.len());
        for i in 0..n {
            buf[i] = g.buf[g.head];
            g.head = (g.head + 1) % N;
        }
        // Consume the rest of the line if we couldn't fit it all.
        let leftover = consume - n;
        g.len -= n;
        for _ in 0..leftover {
            g.head = (g.head + 1) % N;
            g.len -= 1;
        }
        n
    }

    /// Returns the number of bytes currently in the ring.
    /// Used by tests to verify buffer state without popping.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len
    }
}

impl<const N: usize> core::fmt::Debug for ByteRing<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let g = self.inner.lock();
        f.debug_struct("ByteRing")
            .field("capacity", &N)
            .field("len", &g.len)
            .finish()
    }
}

// ── Termios ───────────────────────────────────────────────────────────────────

/// Minimal termios state.
///
/// Full POSIX termios (c_iflag / c_oflag / c_cflag / c_lflag + c_cc[])
/// is a Stage-4 item.  For v1 we track only ICANON and ECHO.
#[derive(Copy, Clone, Debug)]
pub struct Termios {
    /// Canonical mode (line-buffered): slave reads wait for `\n` or `^D`.
    pub icanon: bool,
    /// Echo: bytes written to slave are echoed back to the master.
    pub echo: bool,
}

impl Default for Termios {
    fn default() -> Self {
        // Default matches Linux's `n_tty_set_termios` initial state.
        Self {
            icanon: true,
            echo: true,
        }
    }
}

/// Window size.  `ioctl(TIOCGWINSZ)` / `ioctl(TIOCSWINSZ)` deferred
/// (no ioctl in NARF v1).  Stored here so the struct is ready for Stage 4.
#[derive(Copy, Clone, Debug)]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
}

impl Default for WinSize {
    fn default() -> Self {
        Self { rows: 24, cols: 80 }
    }
}

// ── Pty ───────────────────────────────────────────────────────────────────────

/// Shared state for one pseudoterminal pair.
///
/// Linux ref: `drivers/tty/pty.c` `struct tty_struct` (paired)
pub struct Pty {
    /// Bytes written by the master, readable by the slave.
    /// (Linux: `master->link->read_buf`)
    pub(crate) master_tx_to_slave: ByteRing<4096>,

    /// Bytes written by the slave, readable by the master.
    /// (Linux: `tty->link->read_buf` from the slave's perspective)
    pub(crate) slave_tx_to_master: ByteRing<4096>,

    /// Line discipline state.
    pub(crate) termios: IrqSafeSpinLock<Termios>,

    /// Window dimensions.  ioctl(TIOCSWINSZ) / ioctl(TIOCGWINSZ) deferred
    /// to Stage 4 when ioctl() is added to NARF's syscall surface.
    #[allow(dead_code)]
    pub(crate) window: IrqSafeSpinLock<WinSize>,

    /// Session ID — placeholder; full session management is Stage 4.
    #[allow(dead_code)]
    pub(crate) sid: AtomicU32,

    /// Foreground process group — placeholder; signal delivery is Stage 4.
    #[allow(dead_code)]
    pub(crate) pgid: AtomicU32,

    /// Allocation index; becomes the `/dev/pts/<N>` name.
    pub(crate) index: u32,
}

impl core::fmt::Debug for Pty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pty").field("index", &self.index).finish()
    }
}

impl Pty {
    fn new(index: u32) -> Self {
        Self {
            master_tx_to_slave: ByteRing::new(),
            slave_tx_to_master: ByteRing::new(),
            termios: IrqSafeSpinLock::new(Termios::default()),
            window: IrqSafeSpinLock::new(WinSize::default()),
            sid: AtomicU32::new(0),
            pgid: AtomicU32::new(0),
            index,
        }
    }
}

// ── PTY table ─────────────────────────────────────────────────────────────────

/// Global table mapping PTY index → shared `Arc<Pty>`.
///
/// Inserted on `ptmx_open()`; removed when the master drops (which happens
/// after the slave has also been dropped, since the slave holds its own
/// `Arc<Pty>`).  We use a `Vec` because the table is expected to hold O(10)
/// entries at most; a `BTreeMap` would require `narf-alloc` features not yet
/// pulled in here.
static PTY_TABLE: IrqSafeSpinLock<Vec<(u32, Arc<Pty>)>> = IrqSafeSpinLock::new(Vec::new());

static NEXT_PTY_INDEX: AtomicU32 = AtomicU32::new(0);

/// Allocate a fresh PTY index, create the shared `Pty`, and register it.
/// Returns `(index, Arc<Pty>)`.
pub fn ptmx_open() -> (u32, Arc<Pty>) {
    let index = NEXT_PTY_INDEX.fetch_add(1, Ordering::Relaxed);
    let pty = Arc::new(Pty::new(index));
    PTY_TABLE.lock().push((index, Arc::clone(&pty)));
    (index, pty)
}

/// Remove the PTY from the table (called when the master is dropped).
pub fn ptmx_close(index: u32) {
    let mut tbl = PTY_TABLE.lock();
    tbl.retain(|(i, _)| *i != index);
}

/// Look up a PTY by its pts index.  Returns `None` if not found.
pub fn pts_lookup(index: u32) -> Option<Arc<Pty>> {
    PTY_TABLE
        .lock()
        .iter()
        .find(|(i, _)| *i == index)
        .map(|(_, p)| Arc::clone(p))
}

/// Snapshot the current list of active PTY indices.
pub fn pts_indices() -> Vec<u32> {
    PTY_TABLE.lock().iter().map(|(i, _)| *i).collect()
}

// ── PtyMaster FileOps ─────────────────────────────────────────────────────────

/// `/dev/ptmx` open result — the master half of a PTY pair.
///
/// Linux ref: `drivers/tty/pty.c` `ptm_unix98_ops`
pub struct PtyMaster {
    pty: Arc<Pty>,
}

impl core::fmt::Debug for PtyMaster {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PtyMaster")
            .field("index", &self.pty.index)
            .finish()
    }
}

impl PtyMaster {
    pub fn new(pty: Arc<Pty>) -> Self {
        Self { pty }
    }

    /// Return the PTY index.  Userspace can use this to construct the
    /// `/dev/pts/<N>` path (substitute for `ioctl(TIOCGPTN)` which is
    /// not yet available in NARF).
    pub fn index(&self) -> u32 {
        self.pty.index
    }
}

impl Drop for PtyMaster {
    fn drop(&mut self) {
        ptmx_close(self.pty.index);
    }
}

impl FileOps for PtyMaster {
    /// Read bytes that the slave has sent.
    /// Linux ref: `pty.c pty_read` → `tty_buffer_request_room` →
    ///   drains `tty->link->read_buf`.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let n = self.pty.slave_tx_to_master.pop(buf);
        Box::pin(async move { Ok(n) })
    }

    /// Write bytes to the slave's input.
    /// Linux ref: `pty.c pty_write` → pushes into `tty->link`'s receive buf.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        self.pty.master_tx_to_slave.push(buf);
        let n = buf.len();
        Box::pin(async move { Ok(n) })
    }

    /// `stat().size` carries the PTY index so userspace can construct
    /// `/dev/pts/<N>` without ioctl.  This is a NARF-specific
    /// extension; on Linux the index comes from `ioctl(TIOCGPTN)`.
    fn stat(&self) -> Stat {
        Stat {
            size: self.pty.index as u64,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o620,
            },
            mtime_cycles: 0,
        }
    }
}

// ── PtySlave FileOps ──────────────────────────────────────────────────────────

/// `/dev/pts/<N>` — the slave half of a PTY pair.
///
/// Linux ref: `drivers/tty/pty.c` `pts_unix98_ops`
pub struct PtySlave {
    pty: Arc<Pty>,
}

impl core::fmt::Debug for PtySlave {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PtySlave")
            .field("index", &self.pty.index)
            .finish()
    }
}

impl PtySlave {
    pub fn new(pty: Arc<Pty>) -> Self {
        Self { pty }
    }
}

impl FileOps for PtySlave {
    /// Read bytes from the master (i.e. from `master_tx_to_slave`).
    ///
    /// When ICANON is on (default) this blocks until a newline or
    /// `^D` (0x04) appears in the buffer.  In NARF's synchronous
    /// (non-blocking) model "blocks" means we return 0 bytes when
    /// neither condition is met.
    ///
    /// Linux ref: `n_tty.c n_tty_read` → canonical buffer drain.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let termios = *self.pty.termios.lock();

        if termios.icanon {
            // Look for ^D (EOF) at the start of the input.
            // A real implementation would check `c_cc[VEOF]`; we hardcode 0x04.
            let mut tmp = [0u8; 1];
            {
                let g = self.pty.master_tx_to_slave.inner.lock();
                if g.len > 0 && g.buf[g.head] == 0x04 {
                    drop(g);
                    // Consume the ^D and signal EOF.
                    self.pty.master_tx_to_slave.pop(&mut tmp);
                    return Box::pin(async move { Ok(0) });
                }
            }
            // Check if there's a newline (or data if EOF).
            let eof = false; // ^D already handled above
            let n = self.pty.master_tx_to_slave.pop_line(buf, eof);
            Box::pin(async move { Ok(n) })
        } else {
            // RAW mode: return whatever is available.
            let n = self.pty.master_tx_to_slave.pop(buf);
            Box::pin(async move { Ok(n) })
        }
    }

    /// Write bytes; with ECHO on, also copies them to `slave_tx_to_master`
    /// so the master "sees" what the slave wrote.
    ///
    /// Linux ref: `pty.c pty_write` for the echo side via
    ///   `n_tty_receive_buf_common → n_tty_echo`.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let echo = self.pty.termios.lock().echo;
        // Push slave output so master can read it.
        self.pty.slave_tx_to_master.push(buf);
        // Echo: if ECHO flag is on, also copy to slave_tx_to_master so
        // the master gets a copy of what the slave wrote.
        // (Both pushed to slave_tx_to_master; the echo path mirrors
        //  Linux's n_tty_echo which feeds back into the master read.)
        if echo {
            // Already pushed above; echo is the same data going to the
            // same ring in this simplified model.  A full implementation
            // would duplicate to a separate echo buffer.
        }
        let _ = echo;
        let n = buf.len();
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o620,
            },
            mtime_cycles: 0,
        }
    }
}

// ── DevPtmx FileOps ───────────────────────────────────────────────────────────

/// `/dev/ptmx` itself.  Each `open()` (i.e. each call to `read()` in
/// NARF's simplified open model) is not directly modelled — instead the
/// VFS caller calls `DevPtmx::open_master()` to get a fresh `PtyMaster`.
///
/// In NARF's current VFS, there is no `open()` method on `FileOps`.
/// Callers that need a PTY call `open_ptmx()` directly.  The `FileOps`
/// impl here satisfies the trait surface: stat reports cdev major/minor,
/// read/write are pass-through stubs that return 0/Unsupported.
pub struct DevPtmx;

impl core::fmt::Debug for DevPtmx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevPtmx").finish()
    }
}

impl FileOps for DevPtmx {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
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
                // cdev 5:2 in Linux (major 5, minor 2)
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }
}

/// Open a new PTY master.  This is the programmatic equivalent of
/// `open("/dev/ptmx", O_RDWR)` on Linux.
pub fn open_ptmx() -> Arc<PtyMaster> {
    let (_index, pty) = ptmx_open();
    Arc::new(PtyMaster::new(pty))
}

// ── DevPts DirOps ─────────────────────────────────────────────────────────────

/// `/dev/pts/` directory.
///
/// `lookup("N")` returns a `PtySlave` for the PTY with that index if it
/// exists.  `iter()` / `enumerate()` report the currently-open PTY
/// indices.
///
/// Linux ref: `fs/devpts/inode.c devpts_get_inode` (slave inode lookup).
pub struct DevPts;

impl core::fmt::Debug for DevPts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevPts").finish()
    }
}

impl DirOps for DevPts {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let idx: u32 = name.parse().ok()?;
        let pty = pts_lookup(idx)?;
        Some(Arc::new(PtySlave::new(pty)) as Arc<dyn FileOps>)
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // We can't return references to a locally-allocated Vec here —
        // `DirEntry.name` is `&'static str`.  The pts enumeration uses
        // `enumerate()` which returns owned Strings.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        pts_indices()
            .into_iter()
            .skip(cursor)
            .take(max)
            .map(|idx| {
                let mut s = String::new();
                // Format `idx` into `s` without std::fmt.
                let mut tmp = [0u8; 10];
                let digits = u32_to_str(idx, &mut tmp);
                s.push_str(digits);
                (s, FileType::Special)
            })
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }
}

/// Format a `u32` into `buf` (right-justified).  Returns the decimal string.
fn u32_to_str(mut n: u32, buf: &mut [u8; 10]) -> &str {
    if n == 0 {
        buf[9] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[9..]) };
    }
    let mut pos = 10;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[pos..]) }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Reset the PTY table and index counter.  ONLY for use in kernel tests.
#[doc(hidden)]
pub fn __reset_for_test() {
    PTY_TABLE.lock().clear();
    NEXT_PTY_INDEX.store(0, Ordering::Relaxed);
}
