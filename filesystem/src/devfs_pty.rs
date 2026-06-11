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

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};

// ── Terminal ioctl numbers (Linux ABI) ────────────────────────────────────────
//
// Mirrors `userspace::fd` constants — duplicated here so the FS layer doesn't
// need to import the kernel-userspace crate. The wire values are stable Linux
// ABI; if these ever drift, sys_ioctl will route the wrong cmd word.

/// `ioctl(fd, TIOCGPGRP, &pid_t)` — foreground process group.
pub const TIOCGPGRP: u32 = 0x540F;
/// `ioctl(fd, TIOCSPGRP, &pid_t)` — set foreground process group.
pub const TIOCSPGRP: u32 = 0x5410;
/// `ioctl(fd, TIOCSCTTY, 0)` — set this tty as the caller's controlling tty.
pub const TIOCSCTTY: u32 = 0x540E;
/// `ioctl(master_fd, TIOCGPTN, &u32)` — query the slave index N.
pub const TIOCGPTN: u32 = 0x80045430;
/// `ioctl(master_fd, TIOCSPTLCK, &i32)` — set (1) / clear (0) slave-lock.
pub const TIOCSPTLCK: u32 = 0x40045431;
/// `ioctl(master_fd, TIOCGPTPEER, flags)` — open a fresh slave fd. Handled
/// by the syscall layer because fd allocation lives in userspace::fd.
pub const TIOCGPTPEER: u32 = 0x40045441;
/// `ioctl(fd, TIOCGWINSZ, &winsize)` — query window dimensions.
pub const TIOCGWINSZ: u32 = 0x5413;
/// `ioctl(fd, TIOCSWINSZ, &winsize)` — set window dimensions.
pub const TIOCSWINSZ: u32 = 0x5414;
/// `ioctl(fd, TCGETS, &termios)` — get terminal attributes.
pub const TCGETS: u32 = 0x5401;
/// `ioctl(fd, TCSETS, &termios)` — set terminal attributes (immediate).
pub const TCSETS: u32 = 0x5402;
/// `ioctl(fd, TCSETSW, &termios)` — set terminal attributes (drain output).
pub const TCSETSW: u32 = 0x5403;
/// `ioctl(fd, TCSETSF, &termios)` — set terminal attributes (drain + flush).
pub const TCSETSF: u32 = 0x5404;
/// `ioctl(fd, FIONREAD, &i32)` — bytes immediately readable.
pub const FIONREAD: u32 = 0x541B;

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
        for slot in buf.iter_mut().take(n) {
            *slot = g.buf[g.head];
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
        for slot in buf.iter_mut().take(n) {
            *slot = g.buf[g.head];
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

    /// Wave-76: per-tty foreground process group (TIOCSPGRP/TIOCGPGRP).
    /// Owned per pair so a write to a PTY master/slave does NOT clobber
    /// the global console's fg_pgrp. 0 = unset; tcsetpgrp(3) installs.
    // Only read by the `linux-compat` ioctl path (TIOCSPGRP/TIOCGPGRP); always
    // constructed so the field is dead only when that feature is off.
    #[cfg_attr(not(feature = "linux-compat"), allow(dead_code))]
    pub(crate) fg_pgrp: AtomicU64,

    /// Wave-76: slave-lock flag (TIOCSPTLCK). After ptmx_open the slave
    /// is locked; userspace calls unlockpt() / TIOCSPTLCK(0) before
    /// `open("/dev/pts/N")`. While locked, `DevPts::lookup` returns
    /// `FsError::Io(...)` so the syscall layer surfaces -EIO.
    // Only read by the `linux-compat` lock/unlock paths; always constructed so
    // the field is dead only when that feature is off.
    #[cfg_attr(not(feature = "linux-compat"), allow(dead_code))]
    pub(crate) locked: AtomicBool,
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
            fg_pgrp: AtomicU64::new(0),
            // Linux: ptmx_open() starts with the slave locked. unlockpt()
            // clears via TIOCSPTLCK(0) before the slave can be opened.
            locked: AtomicBool::new(true),
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

/// Wave-76: open a fresh slave by master index. Used by the syscall
/// layer to satisfy `TIOCGPTPEER` (musl/glibc prefer this over
/// `ptsname()+open()`). Returns `None` if the master is gone, or
/// `Some(Err(()))` if the slave is still locked.
#[cfg(feature = "linux-compat")]
pub fn pts_open_peer(index: u32) -> Option<Result<Arc<PtySlave>, ()>> {
    let pty = pts_lookup(index)?;
    if pty.locked.load(Ordering::Acquire) {
        return Some(Err(()));
    }
    Some(Ok(Arc::new(PtySlave::new(pty))))
}

// ── User-pointer helpers ──────────────────────────────────────────────────────
//
// Raw memcpy across user/kernel — mirrors `drivers/gpu/src/drm_ioctl_bridge`
// `copy_in`/`copy_out`. The SMAP/STAC bracket lives in the syscall trap
// layer; this layer just sees an opaque usize and does a pointer load/store.

// SMAP gotcha — every load/store to user memory below has to sit
// inside a `with_user_access` window. A bare `mov` from a user-only
// PTE at CPL=0 faults with #PF (CR2 = user vaddr) once CR4.SMAP=1,
// which is the case on every CPU NARF boots. See
// `[[project_user_cstr_page_safety]]` for the broader pattern.

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
unsafe fn read_user_i32(uptr: usize) -> Result<i32, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let v = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| core::ptr::read_unaligned(uptr as *const i32))
    };
    Ok(v)
}

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
unsafe fn write_user_i32(uptr: usize, v: i32) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut i32, v);
        });
    }
    Ok(())
}

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
unsafe fn write_user_u32(uptr: usize, v: u32) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut u32, v);
        });
    }
    Ok(())
}

// Non-x86_64 fallback — no SMAP, just raw pointer ops (aarch64 has
// its own MTE/PAN dance but the FS layer here is still x86_64-only
// in practice).
#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
unsafe fn read_user_i32(uptr: usize) -> Result<i32, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const i32) })
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
unsafe fn write_user_i32(uptr: usize, v: i32) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    unsafe { core::ptr::write_unaligned(uptr as *mut i32, v) };
    Ok(())
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
unsafe fn write_user_u32(uptr: usize, v: u32) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    unsafe { core::ptr::write_unaligned(uptr as *mut u32, v) };
    Ok(())
}

/// POSIX `struct winsize` — mirrors `userspace::fd::Winsize` so the FS
/// crate can satisfy `TIOCGWINSZ`/`TIOCSWINSZ` without depending on it.
#[cfg(feature = "linux-compat")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct WireWinsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
unsafe fn read_user_winsize(uptr: usize) -> Result<WireWinsize, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let v = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::read_unaligned(uptr as *const WireWinsize)
        })
    };
    Ok(v)
}

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
unsafe fn write_user_winsize(uptr: usize, v: WireWinsize) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut WireWinsize, v);
        });
    }
    Ok(())
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
unsafe fn read_user_winsize(uptr: usize) -> Result<WireWinsize, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const WireWinsize) })
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
unsafe fn write_user_winsize(uptr: usize, v: WireWinsize) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    unsafe { core::ptr::write_unaligned(uptr as *mut WireWinsize, v) };
    Ok(())
}

/// Zero-fill an opaque 60-byte `struct termios` into user memory.
/// musl's `isatty()` and similar checks only care that `tcgetattr`
/// succeeds; the field contents aren't consulted by anything inside
/// this kernel. Linux's `struct termios` is 60 bytes on x86_64
/// (c_iflag/c_oflag/c_cflag/c_lflag/c_line/c_cc[19]/c_ispeed/c_ospeed).
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
unsafe fn write_user_termios_zero(uptr: usize) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let zero = [0u8; 60];
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(zero.as_ptr(), uptr as *mut u8, 60);
        });
    }
    Ok(())
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
unsafe fn write_user_termios_zero(uptr: usize) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let zero = [0u8; 60];
    unsafe { core::ptr::copy_nonoverlapping(zero.as_ptr(), uptr as *mut u8, 60) };
    Ok(())
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

    /// Wave-76: PtyMaster identifies itself via the FileOps hook so
    /// `sys_ioctl(TIOCGPTPEER)` can allocate a fresh slave fd without
    /// a `Any`-based downcast on `Arc<dyn FileOps>`.
    #[cfg(feature = "linux-compat")]
    fn as_pty_master_index(&self) -> Option<u32> {
        Some(self.pty.index)
    }

    /// Wave-76: master-side ioctls.
    ///
    /// - `TIOCGPTN`     — write the slave number into *(u32*)arg
    /// - `TIOCSPTLCK`   — set/clear the slave-lock flag from *(i32*)arg
    /// - `TIOCSPGRP`    — set fg_pgrp from *(i32*)arg (per-tty slot)
    /// - `TIOCGPGRP`    — read fg_pgrp into *(i32*)arg
    /// - `TIOCGPTPEER`  — NOT handled here; the syscall layer special-cases
    ///   it to allocate a fresh fd in the caller's table.
    #[cfg(feature = "linux-compat")]
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match cmd {
            TIOCGPTN => {
                unsafe { write_user_u32(arg, self.pty.index)? };
                Ok(0)
            }
            TIOCSPTLCK => {
                let v = unsafe { read_user_i32(arg)? };
                self.pty.locked.store(v != 0, Ordering::Release);
                Ok(0)
            }
            TIOCGPGRP => {
                let pgrp = self.pty.fg_pgrp.load(Ordering::Acquire) as i32;
                unsafe { write_user_i32(arg, pgrp)? };
                Ok(0)
            }
            TIOCSPGRP => {
                let pgrp = unsafe { read_user_i32(arg)? };
                if pgrp < 0 {
                    return Err(FsError::InvalidData);
                }
                self.pty.fg_pgrp.store(pgrp as u64, Ordering::Release);
                Ok(0)
            }
            TIOCGWINSZ => {
                let w = *self.pty.window.lock();
                let ws = WireWinsize {
                    ws_row: w.rows,
                    ws_col: w.cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                unsafe { write_user_winsize(arg, ws)? };
                Ok(0)
            }
            TIOCSWINSZ => {
                let ws = unsafe { read_user_winsize(arg)? };
                let mut w = self.pty.window.lock();
                w.rows = ws.ws_row;
                w.cols = ws.ws_col;
                Ok(0)
            }
            TCGETS => {
                unsafe { write_user_termios_zero(arg)? };
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                // Accept any termios write — we don't model the full
                // line discipline, so the caller's settings are
                // recorded as a no-op. Linux semantics: success.
                let _ = arg;
                Ok(0)
            }
            FIONREAD => {
                // Bytes the master can read = bytes slave has written.
                let n = self.pty.slave_tx_to_master.len() as i32;
                unsafe { write_user_i32(arg, n)? };
                Ok(0)
            }
            // TIOCGPTPEER is dispatched by sys_ioctl directly; if it
            // reaches here, fall through to Unsupported (→ -ENOTTY).
            _ => Err(FsError::Unsupported),
        }
    }

    /// POLLIN when the master's input queue (slave_tx_to_master) has
    /// at least one byte; POLLOUT always.
    fn poll_readiness(&self) -> u32 {
        let mut mask = crate::POLL_OUT;
        if self.pty.slave_tx_to_master.len() > 0 {
            mask |= crate::POLL_IN;
        }
        mask
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

    /// Wave-76: slave-side ioctls.
    ///
    /// - `TIOCGPTN`   — returns this slave's index (Linux extension; harmless)
    /// - `TIOCSPGRP`  — set the per-tty fg_pgrp (same slot as the master)
    /// - `TIOCGPGRP`  — read the per-tty fg_pgrp
    /// - `TIOCSCTTY`  — install this PTY as the caller's controlling tty
    ///   via the userspace registry (see `set_controlling_tty_hook`).
    #[cfg(feature = "linux-compat")]
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match cmd {
            TIOCGPTN => {
                unsafe { write_user_u32(arg, self.pty.index)? };
                Ok(0)
            }
            TIOCGPGRP => {
                let pgrp = self.pty.fg_pgrp.load(Ordering::Acquire) as i32;
                unsafe { write_user_i32(arg, pgrp)? };
                Ok(0)
            }
            TIOCSPGRP => {
                let pgrp = unsafe { read_user_i32(arg)? };
                if pgrp < 0 {
                    return Err(FsError::InvalidData);
                }
                self.pty.fg_pgrp.store(pgrp as u64, Ordering::Release);
                Ok(0)
            }
            TIOCSCTTY => {
                // Hand off to whichever crate installed the hook. The
                // filesystem layer can't reach the per-task session
                // table directly — userspace::handlers wires it.
                let _ = arg;
                if let Some(hook) = CTTY_HOOK.lock().as_ref() {
                    hook(self.pty.index);
                }
                Ok(0)
            }
            TIOCGWINSZ => {
                let w = *self.pty.window.lock();
                let ws = WireWinsize {
                    ws_row: w.rows,
                    ws_col: w.cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                unsafe { write_user_winsize(arg, ws)? };
                Ok(0)
            }
            TIOCSWINSZ => {
                let ws = unsafe { read_user_winsize(arg)? };
                let mut w = self.pty.window.lock();
                w.rows = ws.ws_row;
                w.cols = ws.ws_col;
                Ok(0)
            }
            TCGETS => {
                unsafe { write_user_termios_zero(arg)? };
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                let _ = arg;
                Ok(0)
            }
            FIONREAD => {
                // Bytes the slave can read = bytes master has written.
                let n = self.pty.master_tx_to_slave.len() as i32;
                unsafe { write_user_i32(arg, n)? };
                Ok(0)
            }
            _ => Err(FsError::Unsupported),
        }
    }

    /// POLLIN when the slave's input queue (master_tx_to_slave) has
    /// at least one byte; POLLOUT always. Mirrors the ConsoleFile
    /// pattern but reads from the per-PTY ring instead of the global
    /// input ring.
    fn poll_readiness(&self) -> u32 {
        let mut mask = crate::POLL_OUT;
        if self.pty.master_tx_to_slave.len() > 0 {
            mask |= crate::POLL_IN;
        }
        mask
    }
}

// ── Controlling-tty hook ──────────────────────────────────────────────────────
//
// `TIOCSCTTY` and master-close-SIGHUP both need to reach the per-task
// session table that lives in `userspace::handlers`. Rather than make
// the filesystem crate depend on userspace, we expose a function-pointer
// hook the userspace crate installs at boot.

#[cfg(feature = "linux-compat")]
type CttyHook = fn(pty_index: u32);

#[cfg(feature = "linux-compat")]
static CTTY_HOOK: IrqSafeSpinLock<Option<CttyHook>> = IrqSafeSpinLock::new(None);

/// Install the hook called from `PtySlave::ioctl(TIOCSCTTY)`. Userspace
/// uses this to record the caller's controlling tty.
#[cfg(feature = "linux-compat")]
pub fn set_controlling_tty_hook(hook: CttyHook) {
    *CTTY_HOOK.lock() = Some(hook);
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

    /// Mark this FileOps as the ptmx clone-on-open node. `sys_open`
    /// allocates a fresh `Pty` pair via [`open_ptmx`] and installs
    /// the master FileOps in the caller's fd table instead of this
    /// singleton. Linux: `drivers/tty/pty.c::ptmx_open`.
    fn is_ptmx_clone(&self) -> bool {
        true
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
        // Wave-76: a locked slave is invisible to `lookup()` — the
        // async path surfaces this as EIO. We can't return Err from
        // a sync `lookup`, so a locked PTY reports NotFound here.
        // The async path below distinguishes locked vs absent.
        #[cfg(feature = "linux-compat")]
        if pty.locked.load(Ordering::Acquire) {
            return None;
        }
        Some(Arc::new(PtySlave::new(pty)) as Arc<dyn FileOps>)
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let idx: u32 = name.parse().map_err(|_| FsError::NotFound)?;
            let pty = pts_lookup(idx).ok_or(FsError::NotFound)?;
            #[cfg(feature = "linux-compat")]
            if pty.locked.load(Ordering::Acquire) {
                return Err(FsError::Busy);
            }
            Ok(Arc::new(PtySlave::new(pty)) as Arc<dyn FileOps>)
        })
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
        // SAFETY: the only byte in `buf[9..]` was just set to b'0' (0x30), an
        // ASCII digit, which is valid UTF-8.
        return unsafe { core::str::from_utf8_unchecked(&buf[9..]) };
    }
    let mut pos = 10;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    // SAFETY: every byte written into `buf[pos..]` above is `b'0' + digit`
    // where `digit` is `n % 10` in 0..=9, so each byte is an ASCII digit
    // (0x30..=0x39) and the whole slice is valid UTF-8.
    unsafe { core::str::from_utf8_unchecked(&buf[pos..]) }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Reset the PTY table and index counter.  ONLY for use in kernel tests.
#[doc(hidden)]
pub fn __reset_for_test() {
    PTY_TABLE.lock().clear();
    NEXT_PTY_INDEX.store(0, Ordering::Relaxed);
}
