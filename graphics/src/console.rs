//! Framebuffer-backed text console.
//!
//! `FbConsole` wraps a `Framebuffer` with a glyph-grid cursor. It
//! exposes `write_bytes` which: draws each printable byte as an
//! 8×8 glyph at the cursor, advances the cursor, handles `\n` and
//! `\r`, and scrolls the visible area up by one row when the cursor
//! falls off the bottom.
//!
//! Scroll shifts the character grid in RAM and paints changed cells only.
//! It never reads pixels from device memory. Palette changes and external
//! drawing through `fb_mut` force the next scroll to repaint every cell.

use core::fmt;

use alloc::vec;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{font8x8, Framebuffer, Pixel32};

const GLYPH_W: u32 = 8;
const GLYPH_H: u32 = 8;
/// Vertical offset from the top of the framebuffer to the first
/// glyph row. The top 32 px are the build stripe + beacon row,
/// painted by `narf_memory::beacon`. The console below the offset
/// stays free for text. Without this offset, beacons overwrite
/// the first text row constantly and the boot log looks blank.
const TOP_PX_OFFSET: u32 = 32;

#[derive(Debug)]
pub struct FbConsole {
    fb: Framebuffer,
    cols: u32,
    rows: u32,
    /// Cursor in glyph-cell coordinates (col, row).
    cur_col: u32,
    cur_row: u32,
    pub fg: Pixel32,
    pub bg: Pixel32,
    /// Glyph character shadow — `cols * rows` bytes, ASCII per cell.
    /// 0x00 means "no glyph" (clear cell, background colour).
    /// Scroll compares adjacent rows here before writing device memory.
    chars: Vec<u8>,
    scroll_palette: (Pixel32, Pixel32),
    repaint_scroll: bool,
}

impl FbConsole {
    /// Wrap a framebuffer. The console paints a `bg`-coloured
    /// background and starts the cursor at (0, 0).
    pub fn new(mut fb: Framebuffer, fg: Pixel32, bg: Pixel32) -> Self {
        let cols = fb.width / GLYPH_W;
        // Reserve the top TOP_PX_OFFSET px for the beacon strip;
        // text rows operate below that band only.
        let rows = (fb.height.saturating_sub(TOP_PX_OFFSET)) / GLYPH_H;
        // Clear ONLY the text region — the top band (build stripe
        // + beacons) was painted by the boot path before this
        // console got installed and contains useful diagnostic
        // state. A full `fb.clear(bg)` would wipe all of it.
        let text_h = rows * GLYPH_H;
        fb.fill_rect(0, TOP_PX_OFFSET, fb.width, text_h, bg);
        let chars = vec![0u8; (cols * rows) as usize];
        Self {
            fb,
            cols,
            rows,
            cur_col: 0,
            cur_row: 0,
            fg,
            bg,
            chars,
            scroll_palette: (fg, bg),
            repaint_scroll: false,
        }
    }

    pub fn cols(&self) -> u32 {
        self.cols
    }
    pub fn rows(&self) -> u32 {
        self.rows
    }
    pub fn cursor(&self) -> (u32, u32) {
        (self.cur_col, self.cur_row)
    }
    /// Borrow the underlying framebuffer mutably. Used by the splash
    /// composer to draw a title bar background underneath the text
    /// the console will paint over the top.
    pub fn fb_mut(&mut self) -> &mut crate::Framebuffer {
        self.repaint_scroll = true;
        &mut self.fb
    }
    /// Reset the cursor to the top-left without clearing the FB.
    pub fn home(&mut self) {
        self.cur_col = 0;
        self.cur_row = 0;
    }
    /// Clear + reset cursor.
    pub fn reset_with_bg(&mut self, bg: crate::Pixel32) {
        self.bg = bg;
        self.fb.clear(bg);
        self.repaint_scroll = true;
        self.cur_col = 0;
        self.cur_row = 0;
    }

    /// Write a single byte, handling control characters and wrap.
    pub fn write_byte(&mut self, b: u8) {
        // Remember even a temporary palette change: a caller may draw with
        // a different colour, then restore the old palette before scrolling.
        self.repaint_scroll |= self.scroll_palette != (self.fg, self.bg);
        match b {
            b'\n' => self.newline(),
            b'\r' => {
                self.cur_col = 0;
            }
            b'\t' => {
                // Advance to next 8-cell tab stop.
                let next = (self.cur_col + 8) & !7;
                while self.cur_col < next.min(self.cols) {
                    self.write_byte(b' ');
                }
            }
            // Backspace — useful for shells later.
            0x08 => {
                if self.cur_col > 0 {
                    self.cur_col -= 1;
                    let x = self.cur_col * GLYPH_W;
                    let y = TOP_PX_OFFSET + self.cur_row * GLYPH_H;
                    self.fb.fill_rect(x, y, GLYPH_W, GLYPH_H, self.bg);
                    let idx = (self.cur_row * self.cols + self.cur_col) as usize;
                    if let Some(c) = self.chars.get_mut(idx) {
                        *c = 0;
                    }
                }
            }
            _ => {
                if self.cur_col >= self.cols {
                    self.newline();
                }
                let x = self.cur_col * GLYPH_W;
                let y = TOP_PX_OFFSET + self.cur_row * GLYPH_H;
                let g = font8x8::lookup(b);
                self.fb.draw_glyph_8x8(x, y, &g, self.fg, self.bg);
                let idx = (self.cur_row * self.cols + self.cur_col) as usize;
                if let Some(c) = self.chars.get_mut(idx) {
                    *c = b;
                }
                self.cur_col += 1;
            }
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }
}

impl fmt::Write for FbConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

impl FbConsole {
    fn newline(&mut self) {
        self.cur_col = 0;
        if self.rows == 0 {
            return;
        }
        if self.cur_row + 1 >= self.rows {
            // Screen full — scroll up one glyph row. The previous
            // wrap-to-row-0 behaviour was cheap but unreadable on
            // real-HW boot ("newest line is somewhere on screen
            // depending on where the cursor was at wrap time").
            //
            // Compare character rows in RAM before painting. Repainting
            // every blank cell of a 4K screen for each boot-log newline
            // makes console output itself a substantial synchronous wait.
            self.scroll_up_one_row();
            // cur_row stays at rows-1; cursor returns to bottom-
            // left for the next line.
        } else {
            self.cur_row += 1;
            // Clear the row we're about to write to so old text
            // doesn't bleed through.
            let y = TOP_PX_OFFSET + self.cur_row * GLYPH_H;
            self.fb.fill_rect(0, y, self.fb.width, GLYPH_H, self.bg);
        }
    }

    /// Scroll from the RAM character grid, without device-memory reads or
    /// writes to cells whose rendered contents remain the same.
    fn scroll_up_one_row(&mut self) {
        self.scroll_up_one_row_with(Self::paint_cell);
    }

    // The paint callback lets tests count actual cell redraws without adding
    // counters or hooks to the production console. Production monomorphizes
    // this with the direct framebuffer painter above.
    fn scroll_up_one_row_with(
        &mut self,
        mut paint: impl FnMut(&mut Framebuffer, u32, u32, u8, Pixel32, Pixel32),
    ) {
        if self.rows == 0 {
            return;
        }
        let cols = self.cols as usize;
        let rows = self.rows as usize;
        let repaint = self.repaint_scroll || self.scroll_palette != (self.fg, self.bg);
        for row in 0..rows {
            let y = TOP_PX_OFFSET + (row as u32) * GLYPH_H;
            for col in 0..cols {
                let x = (col as u32) * GLYPH_W;
                let idx = row * cols + col;
                let old = self.chars[idx];
                // Traverse top to bottom: the source row has not moved yet.
                let next = if row + 1 < rows {
                    self.chars[idx + cols]
                } else {
                    0
                };
                let blank = |b| b == 0 || b == b' ';
                if repaint || !(old == next || (blank(old) && blank(next))) {
                    paint(&mut self.fb, x, y, next, self.fg, self.bg);
                }
                self.chars[idx] = next;
            }
        }
        self.scroll_palette = (self.fg, self.bg);
        self.repaint_scroll = false;
        // Cursor lands at the (now-cleared) bottom row.
        self.cur_row = self.rows - 1;
    }

    fn paint_cell(fb: &mut Framebuffer, x: u32, y: u32, b: u8, fg: Pixel32, bg: Pixel32) {
        if b == 0 || b == b' ' {
            fb.fill_rect(x, y, GLYPH_W, GLYPH_H, bg);
        } else {
            fb.draw_glyph_8x8(x, y, &font8x8::lookup(b), fg, bg);
        }
    }
}

mod scroll_tests;

/// Process-wide console writer registered by the boot path. Held
/// behind a coarse IRQ-safe lock so `console::write_str` can fan
/// out to it without re-entry hazards.
pub static GLOBAL_FB_CONSOLE: IrqSafeSpinLock<Option<FbConsole>> = IrqSafeSpinLock::new(None);
/// Shared monotonic boot framebuffer publication gate. A closed gate never
/// reopens, and withdrawal never erases its registration history.
#[derive(Debug)]
pub struct BootFramebufferAdmission {
    ever: bool,
    closed: bool,
}
impl BootFramebufferAdmission {
    pub const fn new() -> Self {
        Self {
            ever: false,
            closed: false,
        }
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    pub fn publish(&mut self) -> bool {
        if self.closed {
            return false;
        }
        self.ever = true;
        true
    }
    pub fn close_if_never(&mut self, clear: bool) -> bool {
        if self.closed {
            return true;
        }
        if self.ever || !clear {
            return false;
        }
        self.closed = true;
        true
    }
}
impl Default for BootFramebufferAdmission {
    fn default() -> Self {
        Self::new()
    }
}
static BOOT_CONSOLE_ADMISSION: IrqSafeSpinLock<BootFramebufferAdmission> =
    IrqSafeSpinLock::new(BootFramebufferAdmission::new());
/// One-way serial-boot exclusion, serialized with console publication. It
/// succeeds only before any framebuffer console was ever installed.
pub fn close_boot_framebuffer_console() -> bool {
    let mut admission = BOOT_CONSOLE_ADMISSION.lock();
    admission.close_if_never(GLOBAL_FB_CONSOLE.lock().is_none())
}

/// True iff a global FbConsole is currently installed. Used by
/// `frame::bare_main`'s Late `fb-console-install` initcall to avoid
/// re-installing on top of a working early-install (which would
/// clear the FB, wiping all the boot output above the FB-console
/// area — beacons, build stripe, and the kernel init log).
pub fn is_installed() -> bool {
    GLOBAL_FB_CONSOLE.lock().is_some()
}

/// Install a framebuffer console; subsequent calls to `write_str`
/// (via the hook below) will mirror kernel logs onto it. If a
/// console is already installed, the new one replaces it.
///
/// The console's text grid is published to `narf_console`, which passes it
/// on to the console tty's `TIOCGWINSZ` (Linux: `vc_do_resize` →
/// `tty_do_resize`). That happens after the lock is dropped: the grid hook
/// may signal the tty's foreground process group.
pub fn install_fb_console(c: FbConsole) {
    let (cols, rows) = (c.cols(), c.rows());
    {
        let mut admission = BOOT_CONSOLE_ADMISSION.lock();
        if !admission.publish() {
            return;
        }
        *GLOBAL_FB_CONSOLE.lock() = Some(c);
    }
    narf_console::set_text_grid(cols, rows);
}

/// Rebase the installed FbConsole's underlying pixel buffer in
/// place. Used by `frame::bare_main`'s Stage::Late
/// `fb-wc-remap` initcall — after ioremap-WC produces a fresh
/// write-combining virt for the framebuffer, this points the
/// existing FbConsole at the new mapping so subsequent text
/// writes get burst-transactioned instead of crawling through
/// uncached MMIO. Preserves cursor position + scrollback (the
/// pre-existing pixels at the old virt remain but are no longer
/// reached by FbConsole).
///
/// No-op if no FbConsole is installed.
///
/// # Safety
/// `new_base` must point at a writable mapping of at least
/// `stride * height * 4` bytes for the active console; the new
/// mapping must outlive the console.
pub unsafe fn rebase_installed(new_base: *mut u32) {
    let mut g = GLOBAL_FB_CONSOLE.lock();
    if let Some(c) = g.as_mut() {
        // SAFETY: forwarding caller's contract; Framebuffer's
        // `set_base` does the same mapping-lifetime check.
        // SAFETY: Valid memory or trusted environment
        unsafe { c.fb.set_base(new_base) };
    }
}

/// Hook for `narf-console` / kernel-log fan-out. Bytes go through
/// the same path as a serial write — no formatting on this side.
pub fn write_bytes(bytes: &[u8]) {
    let mut g = GLOBAL_FB_CONSOLE.lock();
    if let Some(c) = g.as_mut() {
        c.write_bytes(bytes);
    }
}

/// Test-only: tear down the global console.
#[doc(hidden)]
pub fn __reset_for_test() {
    *GLOBAL_FB_CONSOLE.lock() = None;
    narf_console::set_text_grid(0, 0);
}
