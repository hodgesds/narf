//! NARF boot logo (the sloth).
//!
//! The kernel carries no image decoder (deliberate: a PNG decoder in
//! Ring 0 is attack surface for no benefit at boot). The artwork is
//! decoded at authoring time by `graphics/tools/gen_boot_logo.py`
//! from `graphics/assets/narf-sloth-grid.png` into raw RGB565
//! little-endian pixel blobs, which this module `include_bytes!`s.
//! Regenerate with the script; `--check` verifies the checked-in
//! blobs match a fresh regeneration byte-for-byte.
//!
//! Two assets:
//! * `BOOT_TILE` — the "lying" sloth quadrant, 64x64. One tile per
//!   online CPU, Tux-style, tiled left-to-right across the top of
//!   the end-of-boot panel (`splash::render`). `BootInfo::cpu_count`
//!   drives the count.
//! * `SPLASH_CIRCLE` — the orange-circle quadrant, 256x256. Single
//!   centered logo for the virtio-gpu early splash, where no CPU
//!   count is in play yet.
//!
//! Blits are opaque: the tile keeps its cream ground and the circle
//! its black ground. There is no colour key — keying out the cream
//! would eat the sloth's cream face (near-identical colour), and the
//! black `narf` wordmark needs a light ground to stay legible on the
//! dark panel. The opaque tiles read as deliberate stickers.
//!
//! Cost: the blit is one pass of per-pixel volatile writes, the same
//! shape as `Framebuffer::fill_row_unchecked` — once at boot, ~8 KiB
//! per tile and 128 KiB for the circle, the same order as a dozen
//! console lines the boot already pays.

use crate::{Framebuffer, Pixel32};

/// A boot logo: raw RGB565 little-endian pixels, row-major, no header.
#[derive(Copy, Clone, Debug)]
pub struct Logo {
    pub width: u32,
    pub height: u32,
    /// `width * height * 2` bytes.
    pub pixels: &'static [u8],
}

/// Per-CPU tile: the lying sloth, 64x64. 8,192 bytes.
pub const BOOT_TILE: Logo = Logo {
    width: 64,
    height: 64,
    pixels: include_bytes!("../assets/boot-tile.rgb565"),
};

/// Centered early-splash logo: the orange circle, 256x256. 131,072 bytes.
pub const SPLASH_CIRCLE: Logo = Logo {
    width: 256,
    height: 256,
    pixels: include_bytes!("../assets/splash-circle.rgb565"),
};

/// Side of one CPU tile, in pixels. Tux-scale: large enough that the
/// sloth still reads (verified by rendering the 64px tile on the host),
/// small enough that a 1024-wide framebuffer fits 14 of them.
pub const TILE_SIZE: u32 = 64;
/// Gap between adjacent tiles, in pixels.
pub const TILE_GAP: u32 = 8;

/// Expand one RGB565 pixel to XRGB8888. Channel expansion replicates
/// the top bits into the low bits (`r5 -> r8 = r5<<3 | r5>>2`) so
/// full-scale stays full-scale.
pub const fn rgb565_to_pixel32(v: u16) -> Pixel32 {
    let r5 = ((v >> 11) & 0x1F) as u32;
    let g6 = ((v >> 5) & 0x3F) as u32;
    let b5 = (v & 0x1F) as u32;
    let r = ((r5 << 3) | (r5 >> 2)) as u8;
    let g = ((g6 << 2) | (g6 >> 4)) as u8;
    let b = ((b5 << 3) | (b5 >> 2)) as u8;
    Pixel32::rgb(r, g, b)
}

fn pixel_at(logo: &Logo, x: u32, y: u32) -> Pixel32 {
    debug_assert!(x < logo.width && y < logo.height);
    let off = ((y * logo.width + x) * 2) as usize;
    let lo = logo.pixels[off] as u16;
    let hi = logo.pixels[off + 1] as u16;
    rgb565_to_pixel32(lo | (hi << 8))
}

/// Blit `logo` opaque at (`x0`, `y0`). Pixels landing outside the
/// framebuffer are dropped by `draw_pixel` — the blit never writes
/// out of bounds, even on a framebuffer smaller than the logo.
pub fn blit(fb: &mut Framebuffer, logo: &Logo, x0: u32, y0: u32) {
    // A truncated blob (bad regeneration) must not panic the boot
    // path: refuse to draw instead. The fixture tests fail loudly
    // if a checked-in blob ever shortens.
    if logo.pixels.len() < (logo.width * logo.height * 2) as usize {
        return;
    }
    for y in 0..logo.height {
        for x in 0..logo.width {
            fb.draw_pixel(x0 + x, y0 + y, pixel_at(logo, x, y));
        }
    }
}

/// Blit `logo` centered in the framebuffer. A logo larger than the
/// framebuffer in either dimension is centered anyway and clipped by
/// `draw_pixel`.
pub fn blit_centered(fb: &mut Framebuffer, logo: &Logo) {
    let x0 = fb.width.saturating_sub(logo.width) / 2;
    let y0 = fb.height.saturating_sub(logo.height) / 2;
    blit(fb, logo, x0, y0);
}

/// How many 64px tiles fit across a framebuffer `width` pixels wide,
/// laid out left-to-right with an 8px gap between tiles (no trailing
/// gap after the last tile). Zero when not even one tile fits.
pub const fn tiles_that_fit(fb_width: u32) -> u32 {
    if fb_width < TILE_SIZE {
        return 0;
    }
    (fb_width + TILE_GAP) / (TILE_SIZE + TILE_GAP)
}

/// Draw one sloth tile per CPU in a row at vertical offset `y`, and
/// return how many tiles were drawn.
///
/// Linux rule, adapted: the count is `cpu_count`, capped at what fits
/// across the framebuffer width — tiles are never shrunk to squeeze
/// more in, and never wrapped to a second row. An unknown count
/// (`cpu_count == 0`) draws one tile. A single tile is centered
/// horizontally (a lone 64px tile in the corner reads as a rendering
/// bug); two or more start at the left edge, Tux-style.
pub fn draw_cpu_tiles(fb: &mut Framebuffer, cpu_count: u32, y: u32) -> u32 {
    let want = cpu_count.max(1);
    let count = want.min(tiles_that_fit(fb.width));
    if count == 0 {
        return 0;
    }
    let row_width = count * TILE_SIZE + (count - 1) * TILE_GAP;
    let x0 = if count == 1 {
        fb.width.saturating_sub(TILE_SIZE) / 2
    } else {
        0
    };
    // `row_width <= fb.width` by the `tiles_that_fit` cap, so every
    // tile's x-range is in bounds; `blit` still clips defensively.
    debug_assert!(x0 + row_width <= fb.width);
    for i in 0..count {
        blit(fb, &BOOT_TILE, x0 + i * (TILE_SIZE + TILE_GAP), y);
    }
    count
}
