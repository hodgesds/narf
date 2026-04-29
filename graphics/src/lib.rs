//! narf-graphics — framebuffer + pixel + drawing primitives.
//!
//! This crate stays neutral on which device backs the framebuffer
//! (bochs-display, virtio-gpu, ramfb, …). Display drivers construct
//! a `Framebuffer` view over the device's linear scanout buffer; the
//! kernel-side compositor / console / driver writes through the
//! primitives below.
//!
//! Pixel format: 32-bit XRGB8888 (the bit layout most QEMU
//! framebuffers expose by default). The high byte is the unused /
//! alpha channel; we keep it 0xFF.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use core::ptr;

/// 32-bit XRGB8888 pixel.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Pixel32(pub u32);

impl Pixel32 {
    pub const BLACK:   Self = Self::rgb(0x00, 0x00, 0x00);
    pub const WHITE:   Self = Self::rgb(0xFF, 0xFF, 0xFF);
    pub const RED:     Self = Self::rgb(0xFF, 0x00, 0x00);
    pub const GREEN:   Self = Self::rgb(0x00, 0xFF, 0x00);
    pub const BLUE:    Self = Self::rgb(0x00, 0x00, 0xFF);
    pub const CYAN:    Self = Self::rgb(0x00, 0xFF, 0xFF);
    pub const YELLOW:  Self = Self::rgb(0xFF, 0xFF, 0x00);
    pub const MAGENTA: Self = Self::rgb(0xFF, 0x00, 0xFF);
    pub const NARF_BG: Self = Self::rgb(0x10, 0x10, 0x18);
    pub const NARF_FG: Self = Self::rgb(0xC0, 0xE0, 0xFF);

    #[inline]
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self(0xFF00_0000 | (r as u32) << 16 | (g as u32) << 8 | b as u32)
    }

    #[inline] pub const fn raw(self) -> u32 { self.0 }
}

/// Linear-framebuffer view. The driver supplies the virtual address
/// of the scanout buffer plus its logical dimensions and stride
/// (pixels-per-row, which can exceed `width` for hardware-aligned
/// rows). `Framebuffer` writes through `*mut Pixel32` directly; the
/// caller must hold an exclusive reference for the lifetime of any
/// drawing call.
#[derive(Debug)]
pub struct Framebuffer {
    /// Virtual address of pixel (0, 0). Pixels are 32-bit, so this
    /// is `*mut u32`.
    base:   *mut u32,
    /// Visible logical dimensions in pixels.
    pub width:  u32,
    pub height: u32,
    /// Pixels per row. May be ≥ `width` for stride alignment; iter
    /// over `0..width` only when drawing.
    pub stride: u32,
}

// SAFETY: Framebuffer holds a raw pointer into MMIO that is owned
// exclusively by the display driver. Sharing the framebuffer across
// threads is the driver's responsibility (e.g. via IrqSafeSpinLock).
unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    /// # Safety
    /// `base` must point at a writable mapping of at least
    /// `stride * height * 4` bytes; the mapping must outlive the
    /// `Framebuffer`.
    pub const unsafe fn new(base: *mut u32, width: u32, height: u32, stride: u32) -> Self {
        Self { base, width, height, stride }
    }

    pub fn base(&self) -> *mut u32 { self.base }

    /// Set every pixel to `p`.
    pub fn clear(&mut self, p: Pixel32) {
        for y in 0..self.height {
            // SAFETY: stride*height in-bounds by construction.
            unsafe { self.fill_row_unchecked(y, 0, self.width, p); }
        }
    }

    /// Set a single pixel. Out-of-bounds calls are silently ignored
    /// — drawing helpers are clipping by design.
    #[inline]
    pub fn draw_pixel(&mut self, x: u32, y: u32, p: Pixel32) {
        if x >= self.width || y >= self.height { return; }
        // SAFETY: bounds-checked above; stride*y + x < buffer size.
        unsafe {
            let off = (y * self.stride + x) as isize;
            ptr::write_volatile(self.base.offset(off), p.raw());
        }
    }

    /// Fill a rectangle clipped to the visible area. `w` and `h` are
    /// the rectangle's dimensions; `x` and `y` its top-left.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, p: Pixel32) {
        if x >= self.width || y >= self.height { return; }
        let x_end = x.saturating_add(w).min(self.width);
        let y_end = y.saturating_add(h).min(self.height);
        for row in y..y_end {
            // SAFETY: clipping guarantees stride*row + (x_end-1) < buffer.
            unsafe { self.fill_row_unchecked(row, x, x_end - x, p); }
        }
    }

    /// Draw an opaque 8x8 monochrome glyph: bit 7..=0 of byte `n` is
    /// row `n` left-to-right, MSB = leftmost pixel.
    pub fn draw_glyph_8x8(&mut self, x: u32, y: u32, glyph: &[u8; 8], fg: Pixel32, bg: Pixel32) {
        for (row, byte) in glyph.iter().enumerate() {
            for col in 0..8 {
                let on = (byte >> (7 - col)) & 1 != 0;
                let p = if on { fg } else { bg };
                self.draw_pixel(x + col as u32, y + row as u32, p);
            }
        }
    }

    /// Draw a string of 8x8 glyphs starting at `(x, y)`. Each char
    /// advances `x` by 8 pixels; `\n` advances `y` by 8 and resets
    /// `x` to the original. Characters not in the font render as a
    /// solid 8x8 block.
    pub fn draw_string_8x8(&mut self, x: u32, y: u32, s: &str, fg: Pixel32, bg: Pixel32) {
        let mut cx = x;
        let mut cy = y;
        for ch in s.bytes() {
            if ch == b'\n' { cx = x; cy += 8; continue; }
            let glyph = font8x8::lookup(ch);
            self.draw_glyph_8x8(cx, cy, &glyph, fg, bg);
            cx += 8;
        }
    }

    /// Internal: fill a row segment without bounds-checking.
    ///
    /// # Safety
    /// `y < height`, `x_start + len <= width`, `stride >= width`.
    #[inline]
    unsafe fn fill_row_unchecked(&mut self, y: u32, x_start: u32, len: u32, p: Pixel32) {
        for i in 0..len {
            // SAFETY: per the function contract.
            unsafe {
                let off = (y * self.stride + x_start + i) as isize;
                ptr::write_volatile(self.base.offset(off), p.raw());
            }
        }
    }
}

pub mod font8x8;
