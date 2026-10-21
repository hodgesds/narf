//! The kernel console ttys: the VT tty and the 8250 UART's tty (`ttyS0`).
//!
//! Linux gives the serial port and the virtual terminals separate
//! `tty_struct`s. `ttyS0` (4:64) has its own termios, line discipline, input
//! buffer, session and foreground process group; it reads the UART and writes
//! the UART. The VTs (`tty1..N`, 4:1..) draw on the framebuffer console and
//! read the keyboard. Neither sees the other's input or output; only the
//! kernel log (printk) goes to every registered console. NARF models the VTs
//! with one shared tty (one physical screen, one keyboard; see `vt.rs`), so
//! there are exactly two console ttys here, [`VT`] and [`SERIAL`], each a
//! [`TtyPort`].
//!
//! `/dev/console` (5:1) is whichever of them the kernel command line names
//! last with `console=` ([`console`]), and `/sys/class/tty/console/active`
//! lists every registered console with that one last ([`active_sysfs`]).
//!
//! Each port owns its terminal state and line discipline; every front-end
//! (fd 0/1/2's `ConsoleFile`, `/dev/console`, `/dev/tty0`, `/dev/ttyN`,
//! `/dev/ttyS0`) routes `read`/`block_on_input`/termios ioctls through the
//! port it names, so one port has exactly one `termios`, one input stream and
//! one line discipline.
//!
//! Line discipline: when `ICANON` is set (the cooked default) input is
//! buffered into lines — printable bytes echo (if `ECHO`), backspace
//! erases, `^U` kills the line, Enter completes it, `^D` flushes or
//! signals EOF — and `read` returns only completed lines. With `ICANON`
//! clear (raw mode: vi, readline, a PTY-less full-screen app) every byte
//! is immediately readable. When `ISIG` is set, the `c_cc[VINTR/VQUIT/
//! VSUSP]` chars raise their signal at the port's foreground process group
//! instead of reaching the reader.
//!
//! Linux ref: `drivers/tty/n_tty.c` (`n_tty_receive_buf`, `n_tty_read`),
//! `drivers/tty/serial/serial_core.c` (`uart_write`), `drivers/tty/vt/vt.c`
//! (`con_write`), `kernel/printk/printk.c` (`console=`, `console_setup`),
//! `drivers/tty/tty_io.c` (`show_cons_active`, `tty_lookup_driver`).

use crate::devfs_pty::{Termios, WinSize};
use crate::ntty::{self, LineState, OutputState};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

/// Which device a [`TtyPort`] drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortKind {
    /// The VT tty: keyboard in, framebuffer console out.
    Vt,
    /// `ttyS0`: UART in, UART out.
    Serial,
}

/// One console tty: its termios, window size, line discipline, output
/// column state and foreground process group.
pub struct TtyPort {
    kind: PortKind,
    termios: IrqSafeSpinLock<Option<Termios>>,
    /// The tty's `struct winsize`. 80x24 until the framebuffer console
    /// publishes its text grid to the VT (see [`grid_changed`]). Linux
    /// reports 0x0 for a serial line it was never told the size of, and its
    /// readers then fall back to 80 columns; NARF answers 80x24 for
    /// `ttyS0`, which those readers treat the same way.
    winsize: IrqSafeSpinLock<WinSize>,
    discipline: IrqSafeSpinLock<LineState>,
    output: IrqSafeSpinLock<OutputState>,
    /// Foreground process group (job control), 0 when unset. Shared by every
    /// front-end of this port, so a `tcsetpgrp` through `/dev/console` is
    /// visible to fd 0 when both name this port, and the SIGTTIN/SIGTTOU
    /// background check sees one value.
    fg_pgrp: AtomicU64,
}

impl core::fmt::Debug for TtyPort {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TtyPort")
            .field("kind", &self.kind)
            .field("fg_pgrp", &self.fg_pgrp())
            .finish_non_exhaustive()
    }
}

const DEFAULT_WINSIZE: WinSize = WinSize {
    rows: 24,
    cols: 80,
    xpixel: 0,
    ypixel: 0,
};

impl TtyPort {
    const fn new(kind: PortKind) -> Self {
        Self {
            kind,
            termios: IrqSafeSpinLock::new(None),
            winsize: IrqSafeSpinLock::new(DEFAULT_WINSIZE),
            discipline: IrqSafeSpinLock::new(LineState::new()),
            output: IrqSafeSpinLock::new(OutputState::new()),
            fg_pgrp: AtomicU64::new(0),
        }
    }

    /// Which device this port drives.
    pub fn kind(&self) -> PortKind {
        self.kind
    }

    /// The port's stable [`crate::FileOps::tty_id`].
    pub fn tty_id(&self) -> u32 {
        match self.kind {
            PortKind::Vt => crate::TTY_ID_CONSOLE,
            PortKind::Serial => crate::TTY_ID_SERIAL0,
        }
    }

    /// Linux `dev_t` of the port's own node (`/dev/tty1` for the VT tty, as
    /// a VT session's `tty_nr`; `/dev/ttyS0` for the UART).
    pub fn rdev(&self) -> u64 {
        match self.kind {
            PortKind::Vt => (4 << 8) | 1,
            PortKind::Serial => (4 << 8) | 64,
        }
    }

    /// Current foreground process group (`tcgetpgrp`), 0 if unset.
    pub fn fg_pgrp(&self) -> u64 {
        self.fg_pgrp.load(Ordering::Acquire)
    }

    /// Set the foreground process group (`tcsetpgrp` / TIOCSPGRP).
    pub fn set_fg_pgrp(&self, pgrp: u64) {
        self.fg_pgrp.store(pgrp, Ordering::Release);
    }

    /// TIOCGPGRP with POSIX auto-install: when no foreground group is set
    /// yet, CAS-install `caller_pgrp` (a session leader implicitly acquires
    /// the controlling tty's foreground group on first query — this is what
    /// lets a job-control shell's init loop converge). Returns the resulting
    /// fg pgrp. `caller_pgrp == 0` leaves it unset.
    pub fn fg_pgrp_or_install(&self, caller_pgrp: u64) -> u64 {
        let cur = self.fg_pgrp.load(Ordering::Acquire);
        if cur != 0 {
            return cur;
        }
        if caller_pgrp == 0 {
            return 0;
        }
        match self
            .fg_pgrp
            .compare_exchange(0, caller_pgrp, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => caller_pgrp,
            Err(observed) => observed,
        }
    }

    /// True when the termios has TOSTOP set (background writes raise
    /// SIGTTOU).
    pub fn tostop(&self) -> bool {
        self.termios
            .lock()
            .get_or_insert_with(Termios::default)
            .tostop()
    }

    /// Snapshot the termios wire image (cooked default until a program
    /// `TCSETS`es its own).
    pub fn termios(&self) -> [u8; 60] {
        self.termios.lock().get_or_insert_with(Termios::default).raw
    }

    /// Replace the termios wire image (TCSETS/TCSETSW/TCSETSF).
    pub fn set_termios(&self, raw: [u8; 60]) {
        self.termios.lock().get_or_insert_with(Termios::default).raw = raw;
    }

    /// The window size, pixels included, for TIOCGWINSZ.
    pub fn winsize(&self) -> WinSize {
        *self.winsize.lock()
    }

    /// Apply a new window size (TIOCSWINSZ, or the framebuffer console's
    /// grid), signalling the foreground process group when it changed.
    ///
    /// `tty_do_resize` (`drivers/tty/tty_io.c`): an unchanged size returns
    /// early, otherwise `kill_pgrp(pgrp, SIGWINCH, 1)` and store. The early
    /// return keeps a program that re-sends its size from storming SIGWINCH.
    pub fn resize(&self, ws: WinSize) {
        {
            let mut cur = self.winsize.lock();
            if *cur == ws {
                return;
            }
            *cur = ws;
        }
        crate::devfs_pty::pty_deliver_signal(self.fg_pgrp(), crate::devfs_pty::SIGWINCH);
    }

    /// Run `bytes` through OPOST and put the result on this port's device
    /// verbatim: the UART for `ttyS0` (`uart_write`), the framebuffer
    /// console for the VT (`con_write`).
    ///
    /// This is the tty write path and must NOT reuse `narf_console::write_str`,
    /// the kernel console path (`uart_console_write`), which inserts a CR of
    /// its own. Doing the translation here, from `c_oflag`, is what makes
    /// `stty -opost` mean something.
    fn opost_out(&self, bytes: &[u8]) {
        let t = Termios {
            raw: self.termios(),
        };
        let mut out = self.output.lock();
        let mut processed = Vec::with_capacity(bytes.len() + 8);
        ntty::process_output(&mut out, &t, bytes, &mut |c| processed.push(c));
        drop(out);
        match self.kind {
            PortKind::Serial => narf_console::write_uart_raw(&processed),
            PortKind::Vt => narf_console::write_fb_raw(&processed),
        }
    }

    /// A userspace write to the tty.
    ///
    /// Returns the count the CALLER supplied: a `\n` that OPOST expanded to
    /// CR-NL still consumed one byte of their buffer.
    pub fn write_user(&self, bytes: &[u8]) -> usize {
        // The kernel log keeps the ORIGINAL text, so the persistent boot log
        // (`narf.bootlog=`) holds what userspace printed on the console too.
        if let Ok(s) = core::str::from_utf8(bytes) {
            narf_console::klog::record(s);
        }
        self.opost_out(bytes);
        bytes.len()
    }

    /// Echo one input byte back. Echo is output too, so it goes through OPOST
    /// like everything else (Linux `process_echoes` -> `do_output_char`).
    fn echo_byte(&self, b: u8) {
        self.opost_out(core::slice::from_ref(&b));
    }

    /// An ISIG character: raise its signal at this port's foreground process
    /// group (Linux `isig` -> `kill_pgrp(tty->pgrp)`). Returns true iff the
    /// byte was consumed as a signal.
    fn raise_signal(&self, b: u8) -> bool {
        let pgrp = self.fg_pgrp();
        let raw = SIGNAL_PGRP_HOOK.load(Ordering::Acquire);
        if pgrp != 0 && raw != 0 {
            // SAFETY: stored from a `fn(u64, u8) -> bool` by
            // `install_signal_pgrp_hook`.
            let hook: fn(u64, u8) -> bool = unsafe { core::mem::transmute(raw) };
            if hook(pgrp, b) {
                return true;
            }
        }
        signal_hook_consumes(b)
    }

    /// Pull the device's next input byte: the UART's received bytes for
    /// `ttyS0`, translated key presses for the VT. `None` when dry.
    fn next_input_byte(&self) -> Option<u8> {
        match self.kind {
            PortKind::Serial => narf_input::pop_ascii_byte(),
            PortKind::Vt => {
                // Drain key events until one yields a byte (key-ups and
                // modifier presses translate to None and are skipped).
                while let Some(k) = narf_input::pop_key() {
                    if k.pressed {
                        if let Some(b) = crate::devfs::key_to_ascii(k.code, k.modifiers) {
                            return Some(b);
                        }
                    }
                }
                None
            }
        }
    }

    /// Unthrottle serial receive: bytes the RX interrupt left in the UART
    /// because the byte ring was full are pulled in now that the reader is
    /// consuming (see `narf_input::refill_byte_ring`).
    fn refill(&self) {
        if self.kind == PortKind::Serial {
            narf_input::refill_byte_ring(narf_console::try_read_byte);
        }
    }

    /// Drain the device's input through the n_tty discipline into `state`.
    fn pump(&self, state: &mut LineState) {
        let t = *self.termios.lock().get_or_insert_with(Termios::default);
        // Bound the loop so a fast producer can't wedge us; whatever's left
        // is picked up on the next read.
        let mut budget = 1024usize;
        while budget > 0 {
            budget -= 1;
            let b = match self.next_input_byte() {
                Some(b) => b,
                None => break,
            };
            ntty::feed_byte(state, &t, b, &mut |c| self.echo_byte(c), &mut |x| {
                self.raise_signal(x)
            });
        }
    }

    /// Read input through the line discipline into `buf`. Returns the number
    /// of bytes produced — 0 when nothing is ready yet (the caller parks via
    /// `block_on_input`) or at a freshly-raised EOF.
    pub fn read_into(&self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        self.refill();
        let mut state = self.discipline.lock();
        self.pump(&mut state);
        self.refill();
        if state.readable() == 0 {
            // Distinguish a pending EOF (^D) from "no input yet": consume the
            // EOF latch and report 0 with no parking.
            state.take_eof();
            return 0;
        }
        state.drain_into(buf)
    }

    /// Should a `read` that produced 0 bytes park (vs. return EOF)? True
    /// when no completed input is buffered and no EOF is pending.
    pub fn block_on_input(&self) -> bool {
        self.discipline.lock().would_block()
    }

    /// `poll(2)` `POLLIN`: true when a `read` would return at once —
    /// completed input (a line in canonical mode, any byte in raw mode) or a
    /// pending `^D` EOF. Linux `n_tty_poll` → `input_available_p`.
    ///
    /// Pending device input is run through the line discipline first, as a
    /// read would, so a partial canonical line does not count: reporting it
    /// readable sends a blocking reader (plymouthd's event loop) into a read
    /// that never returns.
    pub fn poll_readable(&self) -> bool {
        self.refill();
        let mut state = self.discipline.lock();
        self.pump(&mut state);
        !state.would_block()
    }

    /// Bytes immediately readable without blocking — completed
    /// line-discipline output plus raw device input still queued. Used by
    /// FIONREAD and `poll(2)` readiness.
    pub fn readable_bytes(&self) -> usize {
        let queued = match self.kind {
            PortKind::Serial => narf_input::pending_bytes(),
            PortKind::Vt => narf_input::pending_keys(),
        };
        self.discipline.lock().readable() + queued
    }

    fn reset_cooked(&self) {
        *self.discipline.lock() = LineState::new();
        *self.winsize.lock() = WinSize::default();
        *self.termios.lock() = Some(Termios::default());
        self.fg_pgrp.store(0, Ordering::Release);
    }

    fn reset_raw(&self) {
        *self.discipline.lock() = LineState::new();
        let mut t = Termios::default();
        // Clear ISIG|ICANON|ECHO in c_lflag (wire offset 12).
        let mut lf = u32::from_ne_bytes(t.raw[12..16].try_into().unwrap());
        lf &= !0x0000_000b; // ~(ISIG|ICANON|ECHO)
        t.raw[12..16].copy_from_slice(&lf.to_ne_bytes());
        *self.termios.lock() = Some(t);
    }
}

/// The VT tty (`/dev/tty0`, `/dev/ttyN`).
pub static VT: TtyPort = TtyPort::new(PortKind::Vt);

/// The UART's tty (`/dev/ttyS0`).
pub static SERIAL: TtyPort = TtyPort::new(PortKind::Serial);

/// The port behind a console tty id, or `None` for a PTY.
pub fn port_by_id(id: u32) -> Option<&'static TtyPort> {
    match id {
        crate::TTY_ID_CONSOLE => Some(&VT),
        crate::TTY_ID_SERIAL0 => Some(&SERIAL),
        _ => None,
    }
}

// ── console= : which tty /dev/console is ────────────────────────────────────

/// A console device named by `console=`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleName {
    /// `ttyN`: `tty0` is "the foreground VT", `tty1..` a specific VT.
    Vt(u32),
    /// `ttyS0`.
    Serial(u32),
}

impl ConsoleName {
    fn port(self) -> &'static TtyPort {
        match self {
            ConsoleName::Vt(_) => &VT,
            ConsoleName::Serial(_) => &SERIAL,
        }
    }

    fn name(self) -> String {
        match self {
            ConsoleName::Vt(n) => alloc::format!("tty{n}"),
            ConsoleName::Serial(n) => alloc::format!("ttyS{n}"),
        }
    }
}

/// The registered consoles, in registration order, and the preferred one
/// (`/dev/console`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleConfig {
    pub registered: Vec<ConsoleName>,
    pub preferred: ConsoleName,
}

/// Parse the `console=` options of a kernel command line.
///
/// Linux `console_setup`: every `console=<name>[,options]` registers that
/// console, and the LAST one becomes the preferred console `/dev/console`
/// opens (`add_preferred_console` sets `preferred_console` to it, also when
/// the name repeats an earlier one). Names NARF has no device for are
/// skipped (`ttyS1`, `hvc0`, `ttyUSB0`, a VT above 63).
///
/// With no usable `console=`, NARF registers both consoles and prefers
/// `ttyS0`, as `console=tty0 console=ttyS0` would. Linux falls back to the
/// first console driver that registers; NARF's kernel log has always gone to
/// the UART from the first instruction, a headless VM has only that line, and
/// every QEMU harness talks to the guest through it. A display-first boot
/// (bare metal) says `console=tty0` and gets the VT as `/dev/console`.
pub fn parse_console_config(cmdline: &str) -> ConsoleConfig {
    let mut registered: Vec<ConsoleName> = Vec::new();
    let mut preferred = None;
    for arg in cmdline.split_ascii_whitespace() {
        let Some(value) = arg.strip_prefix("console=") else {
            continue;
        };
        let device = value.split(',').next().unwrap_or("");
        let name = if let Some(n) = device.strip_prefix("ttyS") {
            match n.parse::<u32>() {
                Ok(0) => ConsoleName::Serial(0),
                _ => continue,
            }
        } else if let Some(n) = device.strip_prefix("tty") {
            match n.parse::<u32>() {
                Ok(n) if n <= crate::vt::MAX_VT => ConsoleName::Vt(n),
                _ => continue,
            }
        } else {
            continue;
        };
        if !registered.contains(&name) {
            registered.push(name);
        }
        preferred = Some(name);
    }
    match preferred {
        Some(preferred) => ConsoleConfig {
            registered,
            preferred,
        },
        None => ConsoleConfig {
            registered: alloc::vec![ConsoleName::Vt(0), ConsoleName::Serial(0)],
            preferred: ConsoleName::Serial(0),
        },
    }
}

static CONFIG: IrqSafeSpinLock<Option<ConsoleConfig>> = IrqSafeSpinLock::new(None);

fn config() -> ConsoleConfig {
    CONFIG
        .lock()
        .get_or_insert_with(|| parse_console_config(narf_boot::cmdline()))
        .clone()
}

/// Test-only: replace the console configuration (`None` re-reads the kernel
/// command line on next use) and return the previous one.
#[doc(hidden)]
pub fn __test_swap_config(cfg: Option<ConsoleConfig>) -> Option<ConsoleConfig> {
    core::mem::replace(&mut *CONFIG.lock(), cfg)
}

/// The tty `/dev/console` is: the preferred `console=`.
pub fn console() -> &'static TtyPort {
    config().preferred.port()
}

/// `/sys/class/tty/console/active`: the registered consoles, the preferred
/// one (the one `/dev/console` opens) last, as `show_cons_active` prints them.
/// systemd's getty generator starts `serial-getty@` for every non-VT name in
/// it, and plymouth takes its console from the last.
pub fn active_sysfs() -> String {
    let cfg = config();
    let mut names: Vec<String> = cfg
        .registered
        .iter()
        .filter(|&&n| n != cfg.preferred)
        .map(|n| n.name())
        .collect();
    names.push(cfg.preferred.name());
    let mut out = names.join(" ");
    out.push('\n');
    out
}

// ── Hooks into the userspace crate ──────────────────────────────────────────

/// `fn(u8) -> bool` installed by userspace: given a control byte, returns
/// `true` iff it was consumed as a signal and must NOT appear in the read
/// buffer. The fallback when a port has no foreground group to signal.
/// Stored as a raw `usize` so this crate needs no dep on userspace.
static SIGNAL_HOOK: AtomicUsize = AtomicUsize::new(0);

/// `fn(pgrp, u8) -> bool`: raise the signal for a control byte at a process
/// group. Preferred over [`SIGNAL_HOOK`] when the port has a foreground group.
static SIGNAL_PGRP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the signal-character hook. See `SIGNAL_HOOK`.
pub fn install_signal_hook(hook: fn(u8) -> bool) {
    SIGNAL_HOOK.store(hook as usize, Ordering::Release);
}

/// Install the per-port foreground-group signal hook. See `SIGNAL_PGRP_HOOK`.
pub fn install_signal_pgrp_hook(hook: fn(u64, u8) -> bool) {
    SIGNAL_PGRP_HOOK.store(hook as usize, Ordering::Release);
}

/// Ask the installed signal hook whether `b` should be consumed as a
/// signal. Returns `false` when no hook is installed.
fn signal_hook_consumes(b: u8) -> bool {
    let raw = SIGNAL_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: `raw` was stored by `install_signal_hook` from a
    // `fn(u8) -> bool`; transmuting the identical signature back is sound.
    let hook: fn(u8) -> bool = unsafe { core::mem::transmute(raw) };
    hook(b)
}

/// Controlling-tty hooks for the console ttys (`DevConsole::ioctl`),
/// mirroring the PTY-slave `set_controlling_tty_hook`. The per-task
/// session/ctty tables live in the userspace crate; the console front-ends
/// reach them through these fn-pointer hooks installed at boot. Stored as raw
/// `usize` (0 = uninstalled) like `SIGNAL_HOOK`.
static CTTY_SET_HOOK: AtomicUsize = AtomicUsize::new(0);
static CTTY_DETACH_HOOK: AtomicUsize = AtomicUsize::new(0);
static SID_QUERY_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the console controlling-tty hooks (`TIOCSCTTY` acquire of a tty
/// id, `TIOCNOTTY` detach, `TIOCGSID` session-id query). Called once at boot.
pub fn install_ctty_hooks(set: fn(u32), detach: fn(), sid: fn() -> u64) {
    CTTY_SET_HOOK.store(set as usize, Ordering::Release);
    CTTY_DETACH_HOOK.store(detach as usize, Ordering::Release);
    SID_QUERY_HOOK.store(sid as usize, Ordering::Release);
}

/// `TIOCSCTTY` on a console tty: record `port` as the caller's controlling
/// terminal via the installed hook (no-op if uninstalled).
pub fn tiocsctty(port: &TtyPort) {
    let raw = CTTY_SET_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: `raw` was stored from a `fn(u32)` by `install_ctty_hooks`;
        // fn pointers and usize share size/alignment.
        let hook: fn(u32) = unsafe { core::mem::transmute(raw) };
        hook(port.tty_id());
    }
}

/// `TIOCNOTTY` on a console tty: detach the caller from its controlling
/// terminal via the installed hook (no-op if uninstalled).
pub fn tiocnotty() {
    let raw = CTTY_DETACH_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: see `tiocsctty`.
        let hook: fn() = unsafe { core::mem::transmute(raw) };
        hook();
    }
}

/// `TIOCGSID` on a console tty: the caller's session id in visible-pid
/// space (0 when no hook is installed — the caller then reports 0).
pub fn tiocgsid() -> u64 {
    let raw = SID_QUERY_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return 0;
    }
    // SAFETY: `raw` was stored from a `fn() -> u64` by `install_ctty_hooks`.
    let hook: fn() -> u64 = unsafe { core::mem::transmute(raw) };
    hook()
}

/// The framebuffer console's text grid changed (installed by the userspace
/// crate as `narf_console`'s grid hook). Linux's `vc_do_resize` does the
/// same for the VT: rows and columns become its winsize, and the foreground
/// process group gets SIGWINCH. The serial line is unaffected.
pub fn grid_changed(cols: u16, rows: u16) {
    VT.resize(WinSize {
        rows,
        cols,
        xpixel: 0,
        ypixel: 0,
    });
}

/// Test-only: clear both ports' line disciplines and set them to a canonical
/// (cooked) termios. The ports are process-global, so console tests reset
/// them before exercising a specific mode.
#[doc(hidden)]
pub fn __test_reset_cooked() {
    VT.reset_cooked();
    SERIAL.reset_cooked();
}

/// Test-only: clear both disciplines and set a RAW termios (ICANON / ECHO /
/// ISIG cleared) so input surfaces byte-at-a-time with no echo or signal
/// interception — the behaviour the byte-drain tests assert.
#[doc(hidden)]
pub fn __test_reset_raw() {
    VT.reset_raw();
    SERIAL.reset_raw();
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Capture sink for the output tests: the framebuffer fan-out receives what
/// the VT draws, which makes it the one place a test can see VT output.
static CAPTURE: IrqSafeSpinLock<Vec<u8>> = IrqSafeSpinLock::new(Vec::new());

fn capture_hook(bytes: &[u8]) {
    CAPTURE.lock().extend_from_slice(bytes);
}

/// A userspace write to the VT is processed by OPOST, not by the UART
/// backend's unconditional CR.
///
/// Linux keeps these two paths apart: `uart_console_write`
/// (`drivers/tty/serial/serial_core.c:2081`) hardcodes
/// `if (*s == '\n') putchar(port, '\r')` so a panic renders with no termios
/// at all, while a userspace write reaches the tty driver having already
/// been through the line discipline. Sharing one path meant `stty -opost`
/// did nothing and a full-screen program got CRs it never asked for.
fn smoke_console_userspace_write_honours_opost() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let saved_termios = VT.termios();
    let prior = narf_console::take_fb_hook();
    narf_console::set_fb_hook(capture_hook);

    // Default cooked termios carries OPOST|ONLCR: the newline expands.
    let mut t = Termios::default();
    VT.set_termios(t.raw);
    CAPTURE.lock().clear();
    let n = VT.write_user(b"a\nb");
    let cooked = CAPTURE.lock().clone();

    // Clearing OPOST (c_oflag bit 0) is what cfmakeraw does.
    let mut oflag = u32::from_ne_bytes(t.raw[4..8].try_into().unwrap());
    oflag &= !1;
    t.raw[4..8].copy_from_slice(&oflag.to_ne_bytes());
    VT.set_termios(t.raw);
    CAPTURE.lock().clear();
    VT.write_user(b"a\nb");
    let raw = CAPTURE.lock().clone();

    VT.set_termios(saved_termios);
    narf_console::restore_fb_hook(prior);

    if n != 3 {
        return TestResult::Fail("write_user must report the caller's byte count");
    }
    if cooked != b"a\r\nb" {
        return TestResult::Fail("ONLCR must expand the newline on a console write");
    }
    if raw != b"a\nb" {
        return TestResult::Fail("with OPOST clear the console must emit a bare LF");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!(
    "filesystem/console",
    smoke_console_userspace_write_honours_opost
);

/// `ttyS0` and the VT are separate ttys: a write to the serial tty never
/// reaches the framebuffer console, its termios and foreground group are its
/// own, and UART input reaches only `ttyS0` while key presses reach only the
/// VT (Linux: `uart_write` vs `con_write`; RX through the 8250 port's own
/// `tty_port`, keys through the keyboard handler to `fg_console`).
fn smoke_console_serial_and_vt_are_separate_ttys() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    narf_input::__reset_global_ring_for_test();
    __test_reset_raw();
    let prior = narf_console::take_fb_hook();
    narf_console::set_fb_hook(capture_hook);
    CAPTURE.lock().clear();
    SERIAL.write_user(b"serial-only");
    let fb_after_serial = CAPTURE.lock().clone();
    CAPTURE.lock().clear();
    VT.write_user(b"vt");
    let fb_after_vt = CAPTURE.lock().clone();
    narf_console::restore_fb_hook(prior);

    SERIAL.set_fg_pgrp(41);
    VT.set_fg_pgrp(42);
    let pgrps = (SERIAL.fg_pgrp(), VT.fg_pgrp());
    let mut t = SERIAL.termios();
    t[0] ^= 0x40;
    SERIAL.set_termios(t);
    let termios_shared = VT.termios() == SERIAL.termios();

    let _ = narf_input::push_global(narf_input::InputEvent::AsciiByte(b's'));
    let mut buf = [0u8; 8];
    let vt_got_serial = VT.read_into(&mut buf);
    let serial_got = SERIAL.read_into(&mut buf);
    let serial_byte = buf[0];
    __test_reset_cooked();

    if !fb_after_serial.is_empty() {
        return TestResult::Fail("a ttyS0 write reached the framebuffer console");
    }
    if fb_after_vt != b"vt" {
        return TestResult::Fail("a VT write did not reach the framebuffer console");
    }
    if pgrps != (41, 42) {
        return TestResult::Fail("ttyS0 and the VT share a foreground process group");
    }
    if termios_shared {
        return TestResult::Fail("ttyS0 and the VT share a termios");
    }
    if vt_got_serial != 0 {
        return TestResult::Fail("UART input reached the VT tty");
    }
    if serial_got != 1 || serial_byte != b's' {
        return TestResult::Fail("UART input did not reach ttyS0");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!(
    "filesystem/console",
    smoke_console_serial_and_vt_are_separate_ttys
);

/// `console=` selects `/dev/console` as Linux's `console_setup` does: the
/// last usable name wins, unknown names are skipped, a repeated name moves
/// the preference, and `/sys/class/tty/console/active` lists the preferred
/// console last. With none, NARF registers `tty0` and `ttyS0` and prefers
/// the serial line.
fn smoke_console_cmdline_selects_dev_console() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let c = |cmdline: &str| parse_console_config(cmdline);
    let both = c("quiet console=tty0 console=ttyS0,115200n8");
    if both.preferred != ConsoleName::Serial(0)
        || both.registered != [ConsoleName::Vt(0), ConsoleName::Serial(0)]
    {
        return TestResult::Fail("console=tty0 console=ttyS0 must prefer ttyS0");
    }
    let vt = c("console=ttyS0 console=tty0");
    if vt.preferred != ConsoleName::Vt(0) {
        return TestResult::Fail("the last console= must win");
    }
    let repeat = c("console=tty0 console=ttyS0 console=tty0");
    if repeat.preferred != ConsoleName::Vt(0) || repeat.registered.len() != 2 {
        return TestResult::Fail("a repeated console= moves the preference only");
    }
    let unknown = c("console=hvc0 console=ttyS1 console=tty1");
    if unknown.preferred != ConsoleName::Vt(1) || unknown.registered != [ConsoleName::Vt(1)] {
        return TestResult::Fail("console names without a device must be skipped");
    }
    let default = c("root=UUID=x");
    if default.preferred != ConsoleName::Serial(0) || default.registered.len() != 2 {
        return TestResult::Fail("no console= must register tty0 + ttyS0, preferring ttyS0");
    }

    let saved = __test_swap_config(Some(vt.clone()));
    let vt_active = active_sysfs();
    let vt_console = console().kind();
    let _ = __test_swap_config(Some(both.clone()));
    let both_active = active_sysfs();
    let both_console = console().kind();
    let _ = __test_swap_config(saved);
    if vt_active != "ttyS0 tty0\n" || vt_console != PortKind::Vt {
        return TestResult::Fail("console=ttyS0 console=tty0: /dev/console must be the VT");
    }
    if both_active != "tty0 ttyS0\n" || both_console != PortKind::Serial {
        return TestResult::Fail("console=tty0 console=ttyS0: /dev/console must be ttyS0");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!(
    "filesystem/console",
    smoke_console_cmdline_selects_dev_console
);

// ── TIOCCONS: console output redirection ────────────────────────────────

/// The tty `/dev/console` output is redirected to (`TIOCCONS`), if any.
///
/// Linux `drivers/tty/tty_io.c`: `redirect` holds a reference to the file a
/// privileged `ioctl(fd, TIOCCONS)` named, and `redirected_tty_write` sends
/// every write to `/dev/console` there instead. plymouthd (`--attach-to-
/// session`) points it at a pty slave so the boot messages systemd writes to
/// the console land in plymouth's log and splash; without it plymouthd
/// refuses to start (`EX_UNAVAILABLE`). Only writes through `/dev/console`
/// follow it: the kernel log and the VTs are untouched, as on Linux.
static REDIRECT: IrqSafeSpinLock<Option<alloc::sync::Arc<dyn crate::FileOps>>> =
    IrqSafeSpinLock::new(None);

/// The current redirect target, if one is set.
pub fn redirect() -> Option<alloc::sync::Arc<dyn crate::FileOps>> {
    REDIRECT.lock().clone()
}

/// `TIOCCONS` on a tty other than `/dev/console`: redirect console output to
/// `target`. `Err(())` (Linux `-EBUSY`) when a redirect is already set.
#[allow(clippy::result_unit_err)]
pub fn set_redirect(target: alloc::sync::Arc<dyn crate::FileOps>) -> Result<(), ()> {
    let mut redirect = REDIRECT.lock();
    if redirect.is_some() {
        return Err(());
    }
    *redirect = Some(target);
    Ok(())
}

/// `TIOCCONS` on `/dev/console` itself: stop redirecting. The target's
/// reference is returned so the caller drops it outside the lock.
pub fn take_redirect() -> Option<alloc::sync::Arc<dyn crate::FileOps>> {
    REDIRECT.lock().take()
}

/// A tty hangup: Linux `__tty_hangup` drops the redirect when it points at
/// the tty being hung up, so console output does not keep going to a pty
/// whose master is gone.
pub fn clear_redirect_to_tty(tty_id: u32) -> Option<alloc::sync::Arc<dyn crate::FileOps>> {
    let mut redirect = REDIRECT.lock();
    if redirect.as_ref().and_then(|f| f.tty_id()) == Some(tty_id) {
        redirect.take()
    } else {
        None
    }
}
