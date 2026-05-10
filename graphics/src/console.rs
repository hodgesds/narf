//! Framebuffer-backed text console.
//!
//! `FbConsole` wraps a `Framebuffer` with a glyph-grid cursor. It
//! exposes `write_bytes` which: draws each printable byte as an
//! 8×8 glyph at the cursor, advances the cursor, handles `\n` and
//! `\r`, and scrolls the visible area up by one row when the cursor
//! falls off the bottom.
//!
//! Scroll is a memmove of stride*(rows-1)*8 pixels through the FB,
//! followed by clearing the bottom row. Cheap on the few-K-bytes /
//! second cadence kernel logs run at; far from optimal for a real
//! TTY but this isn't one yet.

use core::{fmt, ptr};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{font8x8, Framebuffer, Pixel32};

const GLYPH_W: u32 = 8;
const GLYPH_H: u32 = 8;

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
}

impl FbConsole {
    /// Wrap a framebuffer. The console paints a `bg`-coloured
    /// background and starts the cursor at (0, 0).
    pub fn new(mut fb: Framebuffer, fg: Pixel32, bg: Pixel32) -> Self {
        let cols = fb.width / GLYPH_W;
        let rows = fb.height / GLYPH_H;
        fb.clear(bg);
        Self {
            fb,
            cols,
            rows,
            cur_col: 0,
            cur_row: 0,
            fg,
            bg,
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
        self.cur_col = 0;
        self.cur_row = 0;
    }

    /// Write a single byte, handling control characters and wrap.
    pub fn write_byte(&mut self, b: u8) {
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
                    let y = self.cur_row * GLYPH_H;
                    self.fb.fill_rect(x, y, GLYPH_W, GLYPH_H, self.bg);
                }
            }
            _ => {
                if self.cur_col >= self.cols {
                    self.newline();
                }
                let x = self.cur_col * GLYPH_W;
                let y = self.cur_row * GLYPH_H;
                let g = font8x8::lookup(b);
                self.fb.draw_glyph_8x8(x, y, &g, self.fg, self.bg);
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
        if self.cur_row + 1 >= self.rows {
            // Screen full. The previous behaviour memmoved the
            // entire framebuffer up one row (~8 MiB on 1080p)
            // through write-uncached MMIO — hundreds of ms per
            // newline on real HW, the visible cause of "one
            // line per second" boot output.
            //
            // Wrap the cursor back to row 0 instead and clear
            // the new line. Loses scrollback (the next ~135
            // lines overwrite the prior screen), but boot
            // throughput stops being framebuffer-bound. Real
            // scrollback wants a shadow buffer + page-flip,
            // separate work.
            self.cur_row = 0;
        } else {
            self.cur_row += 1;
        }
        // Clear the row we're about to write to so old text
        // doesn't bleed through.
        let y = self.cur_row * GLYPH_H;
        self.fb.fill_rect(0, y, self.fb.width, GLYPH_H, self.bg);
    }
}

/// Process-wide console writer registered by the boot path. Held
/// behind a coarse IRQ-safe lock so `console::write_str` can fan
/// out to it without re-entry hazards.
pub static GLOBAL_FB_CONSOLE: IrqSafeSpinLock<Option<FbConsole>> = IrqSafeSpinLock::new(None);

/// Install a framebuffer console; subsequent calls to `write_str`
/// (via the hook below) will mirror kernel logs onto it. If a
/// console is already installed, the new one replaces it.
pub fn install_fb_console(c: FbConsole) {
    *GLOBAL_FB_CONSOLE.lock() = Some(c);
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
}
