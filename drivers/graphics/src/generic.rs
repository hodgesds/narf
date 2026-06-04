//! Generic Linear Framebuffer parameters.
//!
//! Consumes framebuffer parameters provided by the bootloader (UEFI GOP, VBE, etc.).
//! The `FbScanout` implementation lives in `narf-fb` to avoid circular dependencies.

use narf_graphics::Framebuffer;

#[derive(Debug, Copy, Clone)]
pub struct GenericFb {
    pub addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
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

    /// Returns the logical stride in pixels.
    pub fn stride(&self) -> u32 {
        self.pitch / (self.bpp as u32 / 8)
    }

    /// Returns a Framebuffer handle.
    ///
    /// # Safety
    /// Caller asserts the physical range is mapped and exclusive.
    pub unsafe fn framebuffer(&self) -> Framebuffer {
        // `Framebuffer::new` takes stride in PIXELS per row, not
        // bytes per row. Convert pitch (bytes) → stride (pixels)
        // via `self.stride()`. Passing pitch directly was a 4×
        // overshoot at 32bpp: pixels painted in the wrong place
        // and writes ran off the end of the FB. Visible on real
        // HW where the FB has no slack; QEMU's larger FB partly
        // hid the bug.
        // SAFETY: caller assertion.
        unsafe {
            Framebuffer::new(
                self.addr as *mut u32,
                self.width,
                self.height,
                self.stride(),
            )
        }
    }
}
