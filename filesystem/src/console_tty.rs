//! The single system-console tty.
//!
//! Historically NARF had *two* divergent console implementations: the
//! `ConsoleFile` behind fd 0/1/2 (in the userspace crate, serial-only,
//! its own `termios`) and the `/dev/console` `DevConsole` node (here in
//! filesystem, keyboard + serial, *another* `termios`). They reported a
//! cooked tty to `isatty()` but both read RAW, and their two termios
//! copies could drift. This module is the one place that owns the
//! console's terminal state and line discipline; both front-ends route
//! their `read`/`block_on_input`/termios-ioctls through here so there is
//! exactly one `termios`, one input stream, and one line discipline.
//!
//! Input source: the unified `narf_input` rings — serial RX bytes
//! (`pop_ascii_byte`) *and* translated keyboard keys (`pop_key` →
//! `key_to_ascii`). Either ring's producer wakes a parked reader via the
//! shared input waker (see `narf_input::push_global`).
//!
//! Line discipline: when `ICANON` is set (the cooked default) input is
//! buffered into lines — printable bytes echo (if `ECHO`), backspace
//! erases, `^U` kills the line, Enter completes it, `^D` flushes or
//! signals EOF — and `read` returns only completed lines. With `ICANON`
//! clear (raw mode: vi, readline, a PTY-less full-screen app) every byte
//! is immediately readable. When `ISIG` is set, the `c_cc[VINTR/VQUIT/
//! VSUSP]` chars are handed to the signal hook instead of the reader.
//!
//! Linux ref: `drivers/tty/n_tty.c` (`n_tty_receive_buf`, `n_tty_read`).

use crate::devfs_pty::Termios;
use crate::ntty::{self, LineState};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

static TERMIOS: IrqSafeSpinLock<Option<Termios>> = IrqSafeSpinLock::new(None);
static WINSIZE: IrqSafeSpinLock<(u16, u16)> = IrqSafeSpinLock::new((24, 80));
static DISCIPLINE: IrqSafeSpinLock<LineState> = IrqSafeSpinLock::new(LineState::new());

/// `fn(u8) -> bool` installed by userspace: given a control byte, returns
/// `true` iff it was consumed as a signal (SIGINT/SIGQUIT/SIGTSTP to the
/// foreground pgrp) and must NOT appear in the read buffer. Stored as a
/// raw `usize` so this crate needs no dep on userspace's signal table.
static SIGNAL_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the signal-character hook. See `SIGNAL_HOOK`. NULL disables.
pub fn install_signal_hook(hook: fn(u8) -> bool) {
    SIGNAL_HOOK.store(hook as usize, Ordering::Release);
}

/// Snapshot the current termios wire image (cooked default until a
/// program `TCSETS`es its own).
pub fn termios() -> [u8; 60] {
    TERMIOS.lock().get_or_insert_with(Termios::default).raw
}

/// Replace the termios wire image (TCSETS/TCSETSW/TCSETSF).
pub fn set_termios(raw: [u8; 60]) {
    TERMIOS.lock().get_or_insert_with(Termios::default).raw = raw;
}

/// `(rows, cols)` for TIOCGWINSZ.
pub fn winsize() -> (u16, u16) {
    *WINSIZE.lock()
}

/// Update `(rows, cols)` (TIOCSWINSZ).
pub fn set_winsize(rows: u16, cols: u16) {
    *WINSIZE.lock() = (rows, cols);
}

/// Echo one byte back to the console. `\n` is translated to `\r\n` by the
/// UART backend, so a bare `\n` is fine here.
fn echo_byte(b: u8) {
    if b.is_ascii() {
        // SAFETY: single byte < 0x80 is always valid UTF-8.
        narf_console::write_str(unsafe {
            core::str::from_utf8_unchecked(core::slice::from_ref(&b))
        });
    }
}

/// Ask the installed signal hook whether `b` should be consumed as a
/// signal. Returns `false` when no hook is installed.
fn signal_hook_consumes(b: u8) -> bool {
    let raw = SIGNAL_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: `raw` was stored by `install_signal_hook` from a
    // `fn(u8) -> bool`; transmuting the identical signature back is sound
    // (fn pointers and usize share size/alignment).
    let hook: fn(u8) -> bool = unsafe { core::mem::transmute(raw) };
    hook(b)
}

/// Pull the next available console-input byte from the unified stream:
/// serial RX first (so a paste isn't starved by held keys), then a
/// translated keypress. `None` when both rings are dry.
fn next_input_byte() -> Option<u8> {
    if let Some(b) = narf_input::pop_ascii_byte() {
        return Some(b);
    }
    // Drain key events until one yields a printable byte (key-ups and
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

/// Drain both input rings through the shared n_tty discipline into the
/// console's `LineState`. Echo goes to the UART; ISIG chars to the
/// console's foreground process group via the installed signal hook.
fn pump(state: &mut LineState) {
    let t = *TERMIOS.lock().get_or_insert_with(Termios::default);
    // Bound the loop by the rings' combined capacity so a fast producer
    // can't wedge us; whatever's left is picked up on the next read.
    let mut budget = 1024usize;
    while budget > 0 {
        budget -= 1;
        let b = match next_input_byte() {
            Some(b) => b,
            None => break,
        };
        ntty::feed_byte(state, &t, b, &mut |c| echo_byte(c), &mut |x| {
            signal_hook_consumes(x)
        });
    }
}

/// Read console input through the line discipline into `buf`. Returns the
/// number of bytes produced — 0 when nothing is ready yet (the caller
/// parks via `block_on_input`) or at a freshly-raised EOF.
pub fn read_into(buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let mut state = DISCIPLINE.lock();
    pump(&mut state);
    if state.readable() == 0 {
        // Distinguish a pending EOF (^D) from "no input yet": consume the
        // EOF latch and report 0 with no parking.
        state.take_eof();
        return 0;
    }
    state.drain_into(buf)
}

/// Should a console `read` that produced 0 bytes park (vs. return EOF)?
/// True when no completed input is buffered and no EOF is pending — i.e.
/// the reader should sleep until the input waker fires.
pub fn block_on_input() -> bool {
    DISCIPLINE.lock().would_block()
}

/// Bytes immediately readable without blocking — completed line-discipline
/// output plus raw input still queued in the rings. Used by FIONREAD and
/// `poll(2)` readiness.
pub fn readable_bytes() -> usize {
    DISCIPLINE.lock().readable() + narf_input::pending_input()
}

/// Test-only: clear the line-discipline buffers and set the console to a
/// canonical (cooked) termios. The discipline is process-global, so
/// console tests reset it before exercising a specific mode (mirrors
/// `narf_input::__reset_global_ring_for_test`).
#[doc(hidden)]
pub fn __test_reset_cooked() {
    *DISCIPLINE.lock() = LineState::new();
    *TERMIOS.lock() = Some(Termios::default());
}

/// Test-only: clear the discipline and set a RAW termios (ICANON / ECHO /
/// ISIG cleared) so input surfaces byte-at-a-time with no echo or signal
/// interception — the behaviour the byte-drain tests assert.
#[doc(hidden)]
pub fn __test_reset_raw() {
    *DISCIPLINE.lock() = LineState::new();
    let mut t = Termios::default();
    // Clear ISIG|ICANON|ECHO in c_lflag (wire offset 12).
    let mut lf = u32::from_ne_bytes(t.raw[12..16].try_into().unwrap());
    lf &= !0x0000_000b; // ~(ISIG|ICANON|ECHO)
    t.raw[12..16].copy_from_slice(&lf.to_ne_bytes());
    *TERMIOS.lock() = Some(t);
}
