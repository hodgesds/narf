//! Generic Linear Framebuffer driver.
//!
//! Consumes framebuffer parameters provided by the bootloader (UEFI GOP, VBE, etc.)
//! and exposes them to the `narf-fb` subsystem.

use narf_fb::{FbScanout, PixelFormat};
use narf_graphics::{Framebuffer, Pixel32};
use narf_memory::PhysAddr;

#[derive(Debug)]
pub struct GenericFb {
    addr: u64,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u8,
}

impl GenericFb {
    pub const fn new(addr: u64, width: u32, height: u32, pitch: u32, bpp: u8) -> Self {
        Self {
            addr,
            width,
            height,
            pitch,
            bpp,
        }
    }
}

impl FbScanout for GenericFb {
    fn width(&self) -> u32 {
        self.width
    }
    fn height(&self) -> u32 {
        self.height
    }
    fn stride(&self) -> u32 {
        self.pitch / (self.bpp as u32 / 8)
    }
    fn format(&self) -> PixelFormat {
        // For Stage 4, we assume XRGB8888 (32-bit).
        PixelFormat::XRGB8888
    }
    fn name(&self) -> &'static str {
        "generic-fb"
    }

    fn flush(&self, _x: u32, _y: u32, _w: u32, _h: u32) {
        // Linear framebuffers are always "live".
    }

    unsafe fn framebuffer<'a>(&'a self) -> Framebuffer {
        // SAFETY: caller asserts the physical range is mapped and exclusive.
        unsafe { Framebuffer::new(self.addr, self.width, self.height, self.pitch) }
    }
}
