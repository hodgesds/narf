//! The n_tty line discipline — the one cooked/raw input engine shared by
//! every NARF tty: the system console (`console_tty`) and pseudoterminals
//! (`devfs_pty`).
//!
//! Given a `Termios` it buffers input into lines when `ICANON` is set —
//! echoing (when `ECHO`), applying backspace/`^U` editing, completing a
//! line on Enter, and raising EOF on `^D` — and routes `ISIG` control
//! chars (`^C`/`^\`/`^Z`) to a caller-supplied signal sink. With `ICANON`
//! clear it passes every byte straight through (raw mode). The buffers
//! (`LineState`) live with each tty; the per-byte logic (`feed_byte`) is
//! parameterised by an echo sink and a signal sink so the console (echo →
//! UART, signal → console fg pgrp) and a PTY (echo → master read side,
//! signal → that PTY's fg pgrp) share one implementation.
//!
//! Linux ref: `drivers/tty/n_tty.c` (`n_tty_receive_buf`, `n_tty_read`).

use crate::devfs_pty::Termios;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Cooked line-discipline buffers for one tty.
#[derive(Debug)]
pub struct LineState {
    /// Completed input ready for `read`: whole lines (cooked) or raw
    /// bytes (non-canonical), in FIFO order.
    pub ready: VecDeque<u8>,
    /// The cooked-mode line currently being edited (before Enter).
    pub line: Vec<u8>,
    /// A `^D` on an empty line raised EOF; the next read returns 0.
    pub eof: bool,
}

impl LineState {
    pub const fn new() -> Self {
        Self {
            ready: VecDeque::new(),
            line: Vec::new(),
            eof: false,
        }
    }

    /// Drain up to `buf.len()` ready bytes into `buf`; returns the count.
    pub fn drain_into(&mut self, buf: &mut [u8]) -> usize {
        let n = core::cmp::min(buf.len(), self.ready.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.ready.pop_front().unwrap();
        }
        n
    }

    /// Bytes immediately readable (completed line-discipline output).
    pub fn readable(&self) -> usize {
        self.ready.len()
    }

    /// True when no completed input is buffered (a reader should park
    /// rather than see EOF) and no `^D` EOF is pending.
    pub fn would_block(&self) -> bool {
        self.ready.is_empty() && !self.eof
    }

    /// Consume a pending `^D` EOF latch, if any. Returns true when an EOF
    /// was latched (the caller should report 0 / end-of-file once).
    pub fn take_eof(&mut self) -> bool {
        if self.eof {
            self.eof = false;
            true
        } else {
            false
        }
    }
}

impl Default for LineState {
    fn default() -> Self {
        Self::new()
    }
}

/// Feed one input byte `b` through the discipline governed by `t`.
///
/// - `echo`   — sink for echoed bytes (console: the UART; PTY: the master
///   read side). Called per byte; backspace erase emits BS, space, BS.
/// - `signal` — invoked with the raw byte when `ISIG` is set; returns
///   `true` iff the byte was consumed as a signal, in which case the
///   pending input line is flushed (Linux NOFLSH-clear default).
pub fn feed_byte(
    state: &mut LineState,
    t: &Termios,
    b: u8,
    echo: &mut dyn FnMut(u8),
    signal: &mut dyn FnMut(u8) -> bool,
) {
    let canon = t.icanon();
    let do_echo = t.echo();
    let isig = t.isig();
    let verase = t.cc(2);
    let vkill = t.cc(3);
    let veof = t.cc(4);

    // ISIG control chars (^C/^\/^Z) go to the signal sink; on a generated
    // signal Linux flushes the pending input line (the NOFLSH-clear
    // default) so the aborted line doesn't prepend to the next one.
    if isig && signal(b) {
        state.line.clear();
        return;
    }

    if !canon {
        // Raw / non-canonical: every byte is immediately readable.
        state.ready.push_back(b);
        if do_echo {
            echo(b);
        }
        return;
    }

    // Canonical (cooked) line editing.
    match b {
        // CR is mapped to NL on input (ICRNL); either ends the line.
        b'\r' | b'\n' => {
            state.line.push(b'\n');
            if do_echo {
                echo(b'\n');
            }
            state.ready.extend(state.line.drain(..));
        }
        // VERASE (DEL/^H): rub out the last char.
        _ if b == verase || b == 0x7f || b == 0x08 => {
            if state.line.pop().is_some() && do_echo {
                echo(0x08);
                echo(b' ');
                echo(0x08);
            }
        }
        // VKILL (^U): erase the whole pending line.
        _ if vkill != 0 && b == vkill => {
            if do_echo {
                for _ in 0..state.line.len() {
                    echo(0x08);
                    echo(b' ');
                    echo(0x08);
                }
            }
            state.line.clear();
        }
        // VEOF (^D): flush a partial line, or signal EOF if empty.
        _ if veof != 0 && b == veof => {
            if state.line.is_empty() {
                state.eof = true;
            } else {
                state.ready.extend(state.line.drain(..));
            }
        }
        // Printable / accepted control (tab): buffer + echo.
        _ if b >= 0x20 || b == b'\t' => {
            state.line.push(b);
            if do_echo {
                echo(b);
            }
        }
        // Other control bytes: drop in cooked mode.
        _ => {}
    }
}
