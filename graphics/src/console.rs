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
    /// Used by `scroll_up_one_row` to avoid reading from the FB,
    /// which is catastrophically slow on real-HW WC-mapped GPU
    /// framebuffers (~500 KB/s reads on Renoir's iGPU FB).
    ///
    /// On scroll we shift this Vec up by one row in cached RAM
    /// (~ns) and redraw the cells from the shadow to the FB
    /// (write-only, hits the WC combine buffers, ~GB/s on iGPU).
    /// Net effect: scroll drops from ~200 ms per line (read-bound)
    /// to ~5 ms per line (write-bound). 5 lines/sec → ~200/sec.
    chars: Vec<u8>,
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
            // Cost of this memmove on a 1280×800 GOP FB at UC-MMIO
            // write speed: ~40 ms (792 source rows × 1280 px × 4 B
            // = 4 MB) per newline. The bring-up workflow needs
            // readability more than throughput, and once the screen
            // settles at the shell prompt scrolls happen only on
            // user input cadence.
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

    /// Scroll the text region up by one glyph row. Walks the
    /// `chars` shadow grid (cached RAM, ~ns access) instead of
    /// reading from the FB. The previous implementation did
    /// `ptr::copy(src, dst, width)` where both `src` and `dst`
    /// were FB addresses — on real-HW Renoir's WC-mapped iGPU FB
    /// those READS run at ~500 KB/s, making each scroll cost
    /// ~200 ms (= 5 lines/sec on `ls /`).
    ///
    /// New algorithm:
    ///   1. Shift `chars[cols..]` to `chars[0..]` — cached RAM,
    ///      sub-millisecond.
    ///   2. Zero the last row in `chars`.
    ///   3. Redraw every cell from the shadow to the FB. Each
    ///      cell write is a `draw_glyph_8x8` which is WRITE-only
    ///      to the FB (WC combine buffers → ~GB/s on iGPU).
    ///   4. Cells whose shadow byte is 0 are painted as bg
    ///      (cleared) via a fill_rect; printable bytes go through
    ///      the font8x8 lookup.
    fn scroll_up_one_row(&mut self) {
        if self.rows == 0 {
            return;
        }
        let cols = self.cols as usize;
        let rows = self.rows as usize;
        // 1. Shift the shadow grid one row up.
        // SAFETY: `chars` is at least `cols * rows` bytes long;
        // copy of `(rows-1) * cols` from `cols..` to `0..` stays
        // within bounds.
        if rows > 1 {
            let total = cols * rows;
            // Use Vec methods to keep this safe + simple.
            self.chars.copy_within(cols..total, 0);
        }
        // 2. Clear the last row in the shadow.
        if let Some(last) = self.chars.get_mut(cols * (rows - 1)..cols * rows) {
            for c in last {
                *c = 0;
            }
        }
        // 3. Redraw the entire text region from the shadow to
        //    the FB. This is the only path that needs to touch
        //    FB memory; everything else is cached RAM.
        for row in 0..rows {
            let y = TOP_PX_OFFSET + (row as u32) * GLYPH_H;
            for col in 0..cols {
                let x = (col as u32) * GLYPH_W;
                let idx = row * cols + col;
                let b = self.chars[idx];
                if b == 0 || b == b' ' {
                    self.fb.fill_rect(x, y, GLYPH_W, GLYPH_H, self.bg);
                } else {
                    let g = font8x8::lookup(b);
                    self.fb.draw_glyph_8x8(x, y, &g, self.fg, self.bg);
                }
            }
        }
        // Cursor lands at the (now-cleared) bottom row.
        self.cur_row = self.rows - 1;
    }
}

/// Process-wide console writer registered by the boot path. Held
/// behind a coarse IRQ-safe lock so `console::write_str` can fan
/// out to it without re-entry hazards.
pub static GLOBAL_FB_CONSOLE: IrqSafeSpinLock<Option<FbConsole>> = IrqSafeSpinLock::new(None);

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
pub fn install_fb_console(c: FbConsole) {
    *GLOBAL_FB_CONSOLE.lock() = Some(c);
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
}
