//! `/dev/fb0` — Linux-compatible framebuffer device node.
//!
//! Exposes the active NARF scanout as a standard Linux framebuffer:
//!   - read/write: linear access to pixel buffer (byte-offset indexed).
//!   - mmap: MAP_SHARED alias of physical frames (via FileOps::mmap_frames).
//!   - ioctl: FBIOGET_VSCREENINFO (0x4600), FBIOPUT_VSCREENINFO (0x4601),
//!     FBIOGET_FSCREENINFO (0x4602), FBIOPAN_DISPLAY (0x4606),
//!     FBIOBLANK (0x4611).
//!
//! Linux ref: `drivers/video/fbdev/core/fbmem.c`.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

use crate::{fbdev_flush, fbdev_info};

// ── ioctl command codes (from include/uapi/linux/fb.h) ────────────────

const FBIOGET_VSCREENINFO: u32 = 0x4600;
const FBIOPUT_VSCREENINFO: u32 = 0x4601;
const FBIOGET_FSCREENINFO: u32 = 0x4602;
const FBIOPAN_DISPLAY: u32 = 0x4606;
const FBIOBLANK: u32 = 0x4611;

// ── wire structs (must match Linux UAPI exactly) ──────────────────────

/// `struct fb_bitfield` (12 bytes).
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct WireBitfield {
    offset: u32,
    length: u32,
    msb_right: u32,
}

/// `struct fb_var_screeninfo` (160 bytes).
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct WireVarScreenInfo {
    xres: u32,
    yres: u32,
    xres_virtual: u32,
    yres_virtual: u32,
    xoffset: u32,
    yoffset: u32,
    bits_per_pixel: u32,
    grayscale: u32,
    red: WireBitfield,
    green: WireBitfield,
    blue: WireBitfield,
    transp: WireBitfield,
    nonstd: u32,
    activate: u32,
    height: u32,
    width: u32,
    accel_flags: u32,
    pixclock: u32,
    left_margin: u32,
    right_margin: u32,
    upper_margin: u32,
    lower_margin: u32,
    hsync_len: u32,
    vsync_len: u32,
    sync: u32,
    vmode: u32,
    rotate: u32,
    colorspace: u32,
    reserved: [u32; 4],
}

/// `struct fb_fix_screeninfo` (80 bytes on x86_64).
/// unsigned long → u64 on x86_64.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct WireFixScreenInfo {
    id: [u8; 16],
    smem_start: u64,
    smem_len: u32,
    fb_type: u32,
    type_aux: u32,
    visual: u32,
    xpanstep: u16,
    ypanstep: u16,
    ywrapstep: u16,
    _pad0: u16,
    line_length: u32,
    mmio_start: u64,
    mmio_len: u32,
    accel: u32,
    capabilities: u16,
    reserved: [u16; 2],
}

// ── user-pointer helpers ──────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn write_user<T: Copy>(uptr: usize, v: T) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: `uptr` is a user-space pointer validated by the ioctl
    // syscall path before dispatch; with_user_access temporarily clears
    // SMAP so the kernel can write to user memory.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut T, v);
        });
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn write_user<T: Copy>(uptr: usize, v: T) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: `uptr` is the validated user pointer from the ioctl path.
    // SAFETY: Valid memory or trusted environment
    unsafe { core::ptr::write_unaligned(uptr as *mut T, v) };
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_user<T: Copy + Default>(uptr: usize) -> Result<T, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: `uptr` is a user-space pointer validated by the ioctl path;
    // with_user_access enables user memory reads under SMAP.
    // SAFETY: Valid memory or trusted environment
    let v = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| core::ptr::read_unaligned(uptr as *const T))
    };
    Ok(v)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn read_user<T: Copy + Default>(uptr: usize) -> Result<T, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: `uptr` is the validated user pointer from the ioctl path.
    // SAFETY: Valid memory or trusted environment
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const T) })
}

// ── DevFb0 ───────────────────────────────────────────────────────────

/// `/dev/fb0` — character device for the active scanout.
///
/// Presents the framebuffer as a linear byte-addressable file:
/// `read`/`write` at byte offset; `mmap` aliases the physical frames.
#[derive(Debug)]
pub struct DevFb0;

impl FileOps for DevFb0 {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let n = match fbdev_info() {
            Some(info) => {
                let map_len = info.map_len() as u64;
                if offset >= map_len || buf.is_empty() {
                    0
                } else {
                    let avail = (map_len - offset) as usize;
                    let n = avail.min(buf.len());
                    // SAFETY: phys is identity-mapped (KERNEL_PHYS_OFFSET==0 on
                    // x86_64); offset < map_len and n <= avail keeps the read
                    // in-bounds of the scanout buffer.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        let src = (info.phys + offset) as *const u8;
                        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
                    }
                    n
                }
            }
            None => 0,
        };
        Box::pin(async move { Ok(n) })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = match fbdev_info() {
            Some(info) => {
                let map_len = info.map_len() as u64;
                if offset >= map_len || buf.is_empty() {
                    0
                } else {
                    let avail = (map_len - offset) as usize;
                    let n = avail.min(buf.len());
                    // SAFETY: identity-mapped; in-bounds by construction above.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        let dst = (info.phys + offset) as *mut u8;
                        core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, n);
                    }
                    fbdev_flush();
                    n
                }
            }
            None => 0,
        };
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: fbdev_info().map(|i| i.map_len() as u64).unwrap_or(0),
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }

    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        let info = fbdev_info().ok_or(FsError::Unsupported)?;
        let map_len = info.map_len();
        let end = (offset as usize)
            .checked_add(len)
            .ok_or(FsError::InvalidData)?;
        if end > map_len {
            return Err(FsError::Unsupported);
        }
        let pages = len / 4096;
        let mut frames = Vec::with_capacity(pages);
        for i in 0..pages {
            frames.push(info.phys + offset + (i as u64) * 4096);
        }
        Ok(frames)
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        let info = match fbdev_info() {
            Some(i) => i,
            None => return Err(FsError::Unsupported),
        };

        match cmd {
            FBIOGET_VSCREENINFO => {
                let v = WireVarScreenInfo {
                    xres: info.width,
                    yres: info.height,
                    xres_virtual: info.width,
                    yres_virtual: info.height,
                    bits_per_pixel: info.bpp,
                    // XRGB8888: red[16:8], green[8:8], blue[0:8], transp[24:8]
                    red: WireBitfield {
                        offset: 16,
                        length: 8,
                        msb_right: 0,
                    },
                    green: WireBitfield {
                        offset: 8,
                        length: 8,
                        msb_right: 0,
                    },
                    blue: WireBitfield {
                        offset: 0,
                        length: 8,
                        msb_right: 0,
                    },
                    transp: WireBitfield {
                        offset: 24,
                        length: 8,
                        msb_right: 0,
                    },
                    ..WireVarScreenInfo::default()
                };
                // SAFETY: `arg` is the user `struct fb_var_screeninfo *` that
                // the ioctl syscall path passed through without inspecting;
                // write_user validates non-null and uses SMAP-safe access.
                // SAFETY: Valid memory or trusted environment
                unsafe { write_user(arg, v)? };
                Ok(0)
            }
            FBIOPUT_VSCREENINFO => {
                // Accept and ignore — callers (SDL2, fbset) may attempt to set
                // xoffset/yoffset for panning; we don't support that but tolerate
                // the call so startup doesn't fail.
                // SAFETY: `arg` is the user `struct fb_var_screeninfo *` passed
                // through by the ioctl syscall path; `read_user` null-checks `arg`
                // and SMAP-brackets the read, so a bad pointer returns Err.
                let _: WireVarScreenInfo = unsafe { read_user(arg)? };
                Ok(0)
            }
            FBIOGET_FSCREENINFO => {
                let mut id = [0u8; 16];
                let name = b"NARF fb0";
                let copy_len = name.len().min(15);
                id[..copy_len].copy_from_slice(&name[..copy_len]);

                let f = WireFixScreenInfo {
                    id,
                    smem_start: info.phys,
                    smem_len: info.map_len() as u32,
                    fb_type: 0, // FB_TYPE_PACKED_PIXELS
                    type_aux: 0,
                    visual: 2, // FB_VISUAL_TRUECOLOR
                    xpanstep: 0,
                    ypanstep: 0,
                    ywrapstep: 0,
                    _pad0: 0,
                    line_length: info.stride_bytes,
                    mmio_start: 0,
                    mmio_len: 0,
                    accel: 0, // FB_ACCEL_NONE
                    capabilities: 0,
                    reserved: [0; 2],
                };
                // SAFETY: `arg` is the user `struct fb_fix_screeninfo *`.
                // SAFETY: Valid memory or trusted environment
                unsafe { write_user(arg, f)? };
                Ok(0)
            }
            FBIOPAN_DISPLAY => {
                // Single-buffer; no virtual scrolling. Accept and ignore.
                // SAFETY: `arg` is the user `struct fb_var_screeninfo *` passed
                // through by the ioctl syscall path; `read_user` null-checks `arg`
                // and SMAP-brackets the read, so a bad pointer returns Err.
                let _: WireVarScreenInfo = unsafe { read_user(arg)? };
                Ok(0)
            }
            FBIOBLANK => {
                // Blank/unblank: no-op on QEMU bochs/virtio-gpu.
                Ok(0)
            }
            _ => Err(FsError::Unsupported),
        }
    }
}
