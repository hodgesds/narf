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
    /// VLNEXT (`^V`) was seen: the next byte is taken literally, with no
    /// special meaning. Linux `ldata->lnext`.
    pub lnext: bool,
    /// Output stopped by VSTOP (`^S`) under IXON; VSTART (`^Q`) — or any
    /// byte under IXANY — restarts it. Linux `tty->flow.stopped`.
    pub stopped: bool,
    /// Mid-erase under ECHOPRT: a `\` has been echoed and the matching `/`
    /// is still owed. Linux `ldata->erasing`, closed by `finish_erasing`.
    pub erasing: bool,
}

impl LineState {
    pub const fn new() -> Self {
        Self {
            ready: VecDeque::new(),
            line: Vec::new(),
            eof: false,
            lnext: false,
            stopped: false,
            erasing: false,
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

/// Output-side line-discipline state: the column tracking `do_output_char`
/// needs for ONOCR, tab expansion and backspace.
///
/// Linux keeps this in `n_tty_data` alongside the input buffers; it is
/// split out here because a PTY's input and output halves are driven from
/// opposite ends of the pair and are locked independently.
#[derive(Debug, Default)]
pub struct OutputState {
    /// `ldata->column` — the current output column.
    pub column: u32,
    /// `ldata->canon_column` — column at the start of the canonical line.
    pub canon_column: u32,
}

impl OutputState {
    pub const fn new() -> Self {
        Self {
            column: 0,
            canon_column: 0,
        }
    }
}

/// UTF-8 continuation byte, which must not advance the column.
///
/// Linux `is_continuation`: `(c & 0xc0) == 0x80 && I_IUTF8(tty)`.
fn is_continuation(c: u8, t: &Termios) -> bool {
    c & 0xc0 == 0x80 && t.iutf8()
}

/// Run one byte through OPOST processing, emitting the processed bytes.
///
/// A faithful transcription of `do_output_char`
/// (`drivers/tty/n_tty.c:402`). The output side is where a terminal
/// emulator lives or dies: with ONLCR unapplied every `\n` reaches the
/// emulator as a bare line feed, which moves down a row without returning
/// to column 0, so output staircases down the screen.
///
/// Note the ordering quirks that are easy to get wrong and are Linux's
/// actual behaviour: ONLRET zeroes the column but does NOT itself emit a
/// CR; ONOCR suppresses a CR only when already at column 0; and OCRNL
/// turns CR into NL *without* the ONLCR expansion, because the switch has
/// already been entered on `\r`.
pub fn output_byte(out: &mut OutputState, t: &Termios, c: u8, emit: &mut dyn FnMut(u8)) {
    if !t.opost() {
        emit(c);
        return;
    }
    let mut c = c;
    match c {
        b'\n' => {
            if t.onlret() {
                out.column = 0;
            }
            if t.onlcr() {
                out.canon_column = 0;
                out.column = 0;
                emit(b'\r');
                emit(b'\n');
                return;
            }
            out.canon_column = out.column;
        }
        b'\r' => {
            if t.onocr() && out.column == 0 {
                // Already at column 0: Linux emits nothing at all.
                return;
            }
            if t.ocrnl() {
                c = b'\n';
                if t.onlret() {
                    out.canon_column = 0;
                    out.column = 0;
                }
            } else {
                out.canon_column = 0;
                out.column = 0;
            }
        }
        b'\t' => {
            let spaces = 8 - (out.column & 7);
            if t.xtabs() {
                out.column += spaces;
                for _ in 0..spaces {
                    emit(b' ');
                }
                return;
            }
            out.column += spaces;
        }
        0x08 => {
            if out.column > 0 {
                out.column -= 1;
            }
        }
        _ => {
            // `!iscntrl(c)` — C0 controls and DEL do not advance a column.
            if !(c < 0x20 || c == 0x7f) {
                if t.olcuc() {
                    c = c.to_ascii_uppercase();
                }
                if !is_continuation(c, t) {
                    out.column += 1;
                }
            }
        }
    }
    emit(c);
}

/// Run a buffer through OPOST processing.
pub fn process_output(out: &mut OutputState, t: &Termios, buf: &[u8], emit: &mut dyn FnMut(u8)) {
    for &c in buf {
        output_byte(out, t, c, emit);
    }
}

/// Maximum bytes held in one canonical line, Linux's `N_TTY_BUF_SIZE`.
const N_TTY_BUF_SIZE: usize = 4096;

/// Echo one byte the way `echo_char` does: a control character is shown as
/// `^X` when ECHOCTL is set, except TAB and NL which always echo raw.
///
/// Linux ref: `drivers/tty/n_tty.c` `echo_char` / `echo_char_raw`.
fn echo_char(t: &Termios, c: u8, echo: &mut dyn FnMut(u8)) {
    if c == b'\t' || c == b'\n' {
        echo(c);
        return;
    }
    if t.echoctl() && (c < 0x20 || c == 0x7f) {
        echo(b'^');
        echo(c ^ 0x40);
        return;
    }
    echo(c);
}

/// Width of a byte as echoed, so ECHOE rubs out the right number of cells.
/// A control shown as `^X` occupies two.
fn echo_width(t: &Termios, c: u8) -> usize {
    if c == b'\t' {
        // Linux re-derives tab stops from the canonical column; NARF's
        // editor has no column for the input side, so a tab erases as one
        // cell. Documented rather than silently approximated.
        1
    } else if t.echoctl() && (c < 0x20 || c == 0x7f) {
        2
    } else {
        1
    }
}

/// Close an ECHOPRT erase run: the `\` opened one, this emits the `/`.
///
/// Linux `finish_erasing` (`drivers/tty/n_tty.c:905`):
///
/// ```c
/// if (ldata->erasing) { echo_char_raw('/', ldata); ldata->erasing = 0; }
/// ```
fn finish_erasing(state: &mut LineState, echo: &mut dyn FnMut(u8)) {
    if state.erasing {
        echo(b'/');
        state.erasing = false;
    }
}

/// Rub out `n` display cells.
fn erase_cells(n: usize, echo: &mut dyn FnMut(u8)) {
    for _ in 0..n {
        echo(0x08);
        echo(b' ');
        echo(0x08);
    }
}

/// Feed one input byte `b` through the discipline governed by `t`.
///
/// A transcription of Linux's receive path — `n_tty_receive_buf_standard`
/// and `n_tty_receive_char_special` (`drivers/tty/n_tty.c:1340-1600`) — in
/// its order, which is load-bearing:
///
///   1. ISTRIP masks the 8th bit, then IUCLC (gated on IEXTEN) lowercases.
///   2. IXON flow control consumes VSTOP/VSTART; under IXANY any byte
///      restarts stopped output.
///   3. ISIG turns INTR/QUIT/SUSP into signals, flushing the pending line
///      unless NOFLSH.
///   4. CR/NL translation: IGNCR drops CR outright, else ICRNL maps it to
///      NL; INLCR maps NL to CR. IGNCR is checked BEFORE ICRNL.
///   5. Canonical editing, or raw pass-through.
///
/// - `echo`   — sink for echoed bytes (console: the UART; PTY: the master
///   read side).
/// - `signal` — invoked with the raw byte when `ISIG` is set; returns
///   `true` iff the byte was consumed as a signal.
pub fn feed_byte(
    state: &mut LineState,
    t: &Termios,
    b: u8,
    echo: &mut dyn FnMut(u8),
    signal: &mut dyn FnMut(u8) -> bool,
) {
    // EXTPROC: the discipline runs in userspace; the kernel must not
    // interpret anything. Linux `n_tty_receive_buf_common` hands the data
    // straight to the reader.
    if t.extproc() {
        state.ready.push_back(b);
        return;
    }

    let mut b = b;
    // 1. ISTRIP then IUCLC (IUCLC is gated on IEXTEN — `n_tty.c:1426`).
    if t.istrip() {
        b &= 0x7f;
    }
    if t.iuclc() && t.iexten() {
        b = b.to_ascii_lowercase();
    }

    let canon = t.icanon();
    let do_echo = t.echo();
    let iexten = t.iexten();

    // A byte held literal by a preceding VLNEXT skips every special case
    // below — that is the entire point of `^V`.
    let literal = core::mem::replace(&mut state.lnext, false);

    if !literal {
        // 2. IXON flow control.
        if t.ixon() {
            let vstop = t.cc(crate::devfs_pty::VSTOP);
            let vstart = t.cc(crate::devfs_pty::VSTART);
            if vstop != 0 && b == vstop {
                state.stopped = true;
                return;
            }
            if vstart != 0 && b == vstart {
                state.stopped = false;
                return;
            }
            // IXANY: any other byte restarts output, and is still
            // processed normally afterwards.
            if state.stopped && t.ixany() {
                state.stopped = false;
            }
        }

        // 3. ISIG. On a generated signal Linux flushes the pending input
        // unless NOFLSH is set.
        if t.isig() && signal(b) {
            if !t.noflsh() {
                state.line.clear();
                state.ready.clear();
            }
            return;
        }

        // 4. CR/NL translation. IGNCR before ICRNL, per `n_tty.c:1355`.
        if b == b'\r' {
            if t.igncr() {
                return;
            }
            if t.icrnl() {
                b = b'\n';
            }
        } else if b == b'\n' && t.inlcr() {
            b = b'\r';
        }
    }

    if !canon {
        // Raw / non-canonical: every byte is immediately readable. VMIN and
        // VTIME govern how many the READER waits for, not what is stored.
        state.ready.push_back(b);
        if do_echo {
            echo_char(t, b, echo);
        }
        return;
    }

    // ── Canonical (cooked) line editing ──────────────────────────────
    let verase = t.cc(crate::devfs_pty::VERASE);
    let vkill = t.cc(crate::devfs_pty::VKILL);
    let veof = t.cc(crate::devfs_pty::VEOF);
    let veol = t.cc(crate::devfs_pty::VEOL);
    let veol2 = t.cc(crate::devfs_pty::VEOL2);
    let vwerase = t.cc(crate::devfs_pty::VWERASE);
    let vreprint = t.cc(crate::devfs_pty::VREPRINT);
    let vlnext = t.cc(crate::devfs_pty::VLNEXT);

    if !literal {
        // VLNEXT (^V): take the NEXT byte literally. IEXTEN-gated.
        if iexten && vlnext != 0 && b == vlnext {
            state.lnext = true;
            if do_echo && t.echoctl() {
                // Linux echoes `^` then backs over it, so the next
                // character lands in its place.
                echo(b'^');
                echo(0x08);
            }
            return;
        }

        // VERASE: rub out the last character.
        if verase != 0 && b == verase {
            if let Some(c) = state.line.pop() {
                if do_echo {
                    if t.echoprt() {
                        // Hardcopy-style erase: open the run with `\\` and
                        // then echo the character being rubbed out, so the
                        // record shows what was deleted instead of hiding
                        // it. `eraser()` (`n_tty.c:982-989`).
                        if !state.erasing {
                            echo(b'\\');
                            state.erasing = true;
                        }
                        echo_char(t, c, echo);
                    } else if t.echoe() {
                        erase_cells(echo_width(t, c), echo);
                    } else {
                        echo_char(t, b, echo);
                    }
                }
            }
            return;
        }

        // VWERASE (^W): rub out the last word. IEXTEN-gated.
        if iexten && vwerase != 0 && b == vwerase {
            // Trailing whitespace first, then the word itself — Linux
            // `eraser()`'s WERASE arm.
            let mut cells = 0usize;
            let mut erased = alloc::vec::Vec::new();
            while let Some(&c) = state.line.last() {
                if c != b' ' && c != b'\t' {
                    break;
                }
                cells += echo_width(t, c);
                erased.push(c);
                state.line.pop();
            }
            while let Some(&c) = state.line.last() {
                if c == b' ' || c == b'\t' {
                    break;
                }
                cells += echo_width(t, c);
                erased.push(c);
                state.line.pop();
            }
            if do_echo {
                if t.echoprt() {
                    if !state.erasing {
                        echo(b'\\');
                        state.erasing = true;
                    }
                    // `erased` came off the end, so replay it in the order
                    // the characters were typed.
                    for &c in erased.iter().rev() {
                        echo_char(t, c, echo);
                    }
                } else if t.echoe() {
                    erase_cells(cells, echo);
                }
            }
            return;
        }

        // VKILL (^U): discard the whole pending line.
        if vkill != 0 && b == vkill {
            if do_echo {
                if t.echoke() {
                    let cells: usize = state.line.iter().map(|&c| echo_width(t, c)).sum();
                    erase_cells(cells, echo);
                } else if t.echok() {
                    // Echo the kill char, then a newline.
                    echo_char(t, b, echo);
                    echo(b'\n');
                }
            }
            state.line.clear();
            return;
        }

        // VREPRINT (^R): redraw the pending line. IEXTEN-gated.
        if iexten && vreprint != 0 && b == vreprint {
            if do_echo {
                echo_char(t, b, echo);
                echo(b'\n');
                let pending: alloc::vec::Vec<u8> = state.line.clone();
                for c in pending {
                    echo_char(t, c, echo);
                }
            }
            return;
        }

        // VEOF (^D): deliver a partial line, or EOF when the line is empty.
        if veof != 0 && b == veof {
            if state.line.is_empty() {
                state.eof = true;
            } else {
                state.ready.extend(state.line.drain(..));
            }
            return;
        }
    }

    // Line terminators. NL always terminates; VEOL/VEOL2 additionally do,
    // and unlike NL they are themselves part of the delivered line.
    let is_eol = b == b'\n' || (veol != 0 && b == veol) || (veol2 != 0 && b == veol2);
    if is_eol && !literal {
        state.line.push(b);
        if do_echo || t.echonl() {
            // `n_tty_receive_char`: `if (L_ECHO(tty)) { finish_erasing(...)`
            // — any echoed character closes an open ECHOPRT run.
            finish_erasing(state, echo);
            // ECHONL echoes a newline even with ECHO off (`n_tty.c`
            // `L_ECHONL`), which is how a password prompt still moves to
            // the next line.
            if b == b'\n' {
                echo(b'\n');
            } else if do_echo {
                echo_char(t, b, echo);
            }
        }
        state.ready.extend(state.line.drain(..));
        return;
    }

    // Ordinary byte: buffer it. IMAXBEL rings the bell instead of silently
    // dropping input once the line is full (`n_tty.c` `I_IMAXBEL`).
    if state.line.len() >= N_TTY_BUF_SIZE {
        if t.imaxbel() {
            echo(0x07);
        }
        return;
    }
    state.line.push(b);
    if do_echo {
        finish_erasing(state, echo);
        echo_char(t, b, echo);
    }
}
