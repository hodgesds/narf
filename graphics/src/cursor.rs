//! Mouse cursor sprite + position tracking.
//!
//! `Cursor` carries a small monochrome sprite (8×12 — a classic
//! arrow shape) and an `(x, y)` position in pixel coordinates. The
//! sprite is XRGB-formatted but only two values are used: the
//! cursor's foreground colour for "on" pixels and a fully-transparent
//! sentinel for "skip — leave underlying FB content alone."
//!
//! Today's blit is destructive (no save/restore of underneath
//! pixels), so a moving cursor leaves a trail unless the caller
//! re-paints. The framebuffer console redraws the affected glyph
//! cells when the cursor moves over them; that's the path commit 5
//! will wire up.

use crate::{Framebuffer, Pixel32};

/// Bytes of the 8×12 arrow sprite. Each row is 8 bits, MSB = leftmost
/// pixel. 1 = foreground, 0 = transparent.
const ARROW_8X12: [u8; 12] = [
    0b10000000, 0b11000000, 0b11100000, 0b11110000, 0b11111000, 0b11111100, 0b11111110, 0b11111100,
    0b11011000, 0b10001100, 0b00000110, 0b00000110,
];

#[derive(Copy, Clone, Debug)]
pub struct Cursor {
    pub x: i32,
    pub y: i32,
    pub fg: Pixel32,
    /// For edge-detect tests: every blit bumps this counter.
    pub draw_count: u64,
}

impl Cursor {
    pub const fn new(x: i32, y: i32, fg: Pixel32) -> Self {
        Self {
            x,
            y,
            fg,
            draw_count: 0,
        }
    }

    /// Cursor sprite dimensions.
    pub const W: u32 = 8;
    pub const H: u32 = 12;

    /// Update position by a relative `(dx, dy)`, clamped to the
    /// framebuffer's bounds.
    pub fn move_relative(&mut self, dx: i32, dy: i32, fb_w: u32, fb_h: u32) {
        self.x = (self.x + dx).clamp(0, fb_w.saturating_sub(1) as i32);
        self.y = (self.y + dy).clamp(0, fb_h.saturating_sub(1) as i32);
    }

    /// Set absolute position, clamped to the framebuffer's bounds.
    pub fn set(&mut self, x: i32, y: i32, fb_w: u32, fb_h: u32) {
        self.x = x.clamp(0, fb_w.saturating_sub(1) as i32);
        self.y = y.clamp(0, fb_h.saturating_sub(1) as i32);
    }

    /// Draw the sprite at the current position. Pixels where the
    /// sprite bit is 0 are left alone; pixels where it's 1 are
    /// overwritten with `fg`.
    pub fn draw_at(&mut self, fb: &mut Framebuffer) {
        for (row, byte) in ARROW_8X12.iter().enumerate() {
            for col in 0..8u32 {
                if (byte >> (7 - col)) & 1 == 0 {
                    continue;
                }
                let px = self.x + col as i32;
                let py = self.y + row as i32;
                if px < 0 || py < 0 {
                    continue;
                }
                fb.draw_pixel(px as u32, py as u32, self.fg);
            }
        }
        self.draw_count += 1;
    }
}
