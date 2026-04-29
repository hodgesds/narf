//! narf-fb — framebuffer scanout abstraction.
//!
//! Sits between the kernel-level display drivers (bochs-display,
//! virtio-gpu) and any consumer that wants to push pixels: the
//! Narf-Ring draw protocol in commit B, the userspace testbin in
//! commit C, future Wayland-shaped compositors.
//!
//! Surface:
//!
//!   * `FbScanout` — trait every backend implements. Exposes
//!     dimensions, format, and a `flush(rect)` hook (no-op for
//!     bochs; TRANSFER+FLUSH on virtio-gpu).
//!   * `select_active() -> Option<&'static dyn FbScanout>` — the
//!     scanout-picker. Prefers bochs (lowest latency, no command
//!     queue) when its BAR is reachable; falls back to virtio-gpu.
//!   * `FbWriter` — bounds-checking Fill/Blit/Flush primitives.
//!     Carries the active scanout reference; its constructor takes
//!     a `Cap<FbScanout, Write>` so unauthorised callers cannot
//!     instantiate one.
//!
//! Cap typing — `FbScanoutCap`:
//!     `Cap<FbScanoutCap, Read>`  — query dimensions only
//!     `Cap<FbScanoutCap, Write>` — full draw access
//!
//! No syscalls live here. The `bootstrap_authority` mints the
//! initial Write cap; subsequent producers narrow rights via the
//! capability lattice.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod cmd_ring;
pub use cmd_ring::{DrawCmd, DrawRing, RING_DEPTH, TAG_FILL, TAG_FLUSH};

use core::sync::atomic::{AtomicUsize, Ordering};

use narf_capabilities::{Cap, CapKind, CapType, Read, Write};
use narf_graphics::{Framebuffer, Pixel32};

/// Pixel format the kernel exposes to consumers. Today we only
/// vend XRGB8888 — both bochs and virtio-gpu's chosen mode use it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    XRGB8888,
}

/// Backend-agnostic scanout view. Implementations are zero-cost
/// wrappers over the underlying driver's framebuffer view.
pub trait FbScanout: Send + Sync + core::fmt::Debug {
    fn width(&self) -> u32;
    fn height(&self) -> u32;
    fn stride(&self) -> u32;
    fn format(&self) -> PixelFormat;
    /// Identifier — "bochs", "virtio-gpu". Used by the picker log
    /// and by tests that want to assert which backend won.
    fn name(&self) -> &'static str;
    /// Push a rectangle from the scanout buffer to the host display.
    /// No-op for direct-FB backends (bochs); on virtio-gpu it issues
    /// TRANSFER_TO_HOST_2D + RESOURCE_FLUSH.
    fn flush(&self, x: u32, y: u32, w: u32, h: u32);
    /// Borrow a `narf_graphics::Framebuffer` view for direct
    /// per-pixel writes. Caller is responsible for serialisation.
    ///
    /// # Safety
    /// Caller must hold a `Cap<FbScanoutCap, Write>` and ensure no
    /// other writer is in flight. The returned Framebuffer aliases
    /// the scanout buffer; lifetime is tied to the scanout's
    /// lifetime (which today is `'static`).
    unsafe fn framebuffer<'a>(&'a self) -> Framebuffer;
}

// ── bochs-display backend ───────────────────────────────────────────

#[derive(Debug)]
struct BochsScanout;

impl FbScanout for BochsScanout {
    fn width(&self)  -> u32 {
        narf_graphics_driver::bochs::with_controller(|d| d.width).unwrap_or(0)
    }
    fn height(&self) -> u32 {
        narf_graphics_driver::bochs::with_controller(|d| d.height).unwrap_or(0)
    }
    fn stride(&self) -> u32 { self.width() }
    fn format(&self) -> PixelFormat { PixelFormat::XRGB8888 }
    fn name(&self)   -> &'static str { "bochs" }
    fn flush(&self, _x: u32, _y: u32, _w: u32, _h: u32) {
        // bochs is direct-MMIO — pixels appear as soon as they're
        // written. No host-side blit needed.
    }
    unsafe fn framebuffer(&self) -> Framebuffer {
        // SAFETY: caller-asserted exclusive write access via the cap.
        // bochs::with_controller's framebuffer() returns a fresh
        // pointer view; we replicate it here so the closure's
        // borrow doesn't escape.
        narf_graphics_driver::bochs::with_controller(|d| {
            // SAFETY: same.
            unsafe { d.framebuffer() }
        }).expect("bochs scanout selected without controller")
    }
}

// ── virtio-gpu backend ──────────────────────────────────────────────

#[derive(Debug)]
struct VirtioGpuScanout;

impl FbScanout for VirtioGpuScanout {
    fn width(&self)  -> u32 {
        narf_drivers_virtio::gpu_pci::with_controller(|d| d.mode.width).unwrap_or(0)
    }
    fn height(&self) -> u32 {
        narf_drivers_virtio::gpu_pci::with_controller(|d| d.mode.height).unwrap_or(0)
    }
    fn stride(&self) -> u32 { self.width() }
    fn format(&self) -> PixelFormat { PixelFormat::XRGB8888 }
    fn name(&self)   -> &'static str { "virtio-gpu" }
    fn flush(&self, _x: u32, _y: u32, _w: u32, _h: u32) {
        // M0: flush always covers the full scanout. Per-rect flush
        // is a future TRANSFER_TO_HOST_2D + RESOURCE_FLUSH dance.
        let _ = narf_drivers_virtio::gpu_pci::with_controller_mut(|d| {
            // SAFETY: bring_up complete; caller serialised via cap.
            unsafe { d.flush() }
        });
    }
    unsafe fn framebuffer(&self) -> Framebuffer {
        narf_drivers_virtio::gpu_pci::with_controller(|d| {
            // SAFETY: caller holds Write cap.
            unsafe { d.framebuffer() }
        }).expect("virtio-gpu scanout selected without controller")
    }
}

// ── active-scanout picker ───────────────────────────────────────────

static BOCHS:      BochsScanout      = BochsScanout;
static VIRTIO_GPU: VirtioGpuScanout  = VirtioGpuScanout;

/// Picker. Prefers bochs (no command-queue tax) when its BAR is
/// reachable; otherwise falls back to virtio-gpu. Returns `None`
/// when neither backend has probed successfully.
pub fn select_active() -> Option<&'static dyn FbScanout> {
    if narf_graphics_driver::bochs::is_probed() {
        let reachable = narf_graphics_driver::bochs::with_controller(|d| d.fb_reachable())
            .unwrap_or(false);
        if reachable {
            return Some(&BOCHS);
        }
    }
    if narf_drivers_virtio::gpu_pci::is_probed() {
        let ready = narf_drivers_virtio::gpu_pci::with_controller(|d| d.ready)
            .unwrap_or(false);
        if ready {
            return Some(&VIRTIO_GPU);
        }
    }
    None
}

// ── cap typing ──────────────────────────────────────────────────────

/// Capability subject for FbScanout. `Cap<FbScanoutCap, Write>`
/// gives draw access; `Cap<FbScanoutCap, Read>` gives query-only.
#[derive(Debug)]
pub enum FbScanoutCap {}

impl CapType for FbScanoutCap {
    const KIND: CapKind = CapKind::FbScanout;
}

/// Mint a fresh write-capable FbScanout cap via the bootstrap
/// authority. Later cap holders narrow rights via the lattice
/// (e.g. derive `Read` from this `Write`).
pub fn bootstrap_writer() -> Cap<FbScanoutCap, Write> {
    Cap::<FbScanoutCap, Write>::bootstrap()
}

// ── bounds-checked drawing primitives ───────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub const fn new(x: u32, y: u32, w: u32, h: u32) -> Self { Self { x, y, w, h } }
    /// Clip this rect against the supplied bounds. Returns the
    /// intersection or `None` if the rects don't overlap.
    pub fn clip(self, fb_w: u32, fb_h: u32) -> Option<Self> {
        if self.x >= fb_w || self.y >= fb_h || self.w == 0 || self.h == 0 {
            return None;
        }
        let x_end = self.x.saturating_add(self.w).min(fb_w);
        let y_end = self.y.saturating_add(self.h).min(fb_h);
        Some(Self { x: self.x, y: self.y, w: x_end - self.x, h: y_end - self.y })
    }
}

/// Fail kinds for `FbWriter` operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FbWriteError {
    NoActiveScanout,
    OutOfBounds,
}

/// Cap-gated writer. Holders can fill rectangles and flush regions
/// to the active scanout.
#[derive(Debug)]
pub struct FbWriter {
    scanout: &'static dyn FbScanout,
    /// Holding the cap by-value ensures the writer can only exist
    /// while the cap is live; cap revocation invalidates this
    /// writer at construction time (we re-check at every op).
    cap:     Cap<FbScanoutCap, Write>,
}

impl FbWriter {
    /// Construct from an existing Write cap. Returns
    /// `NoActiveScanout` if no backend has probed.
    pub fn new(cap: Cap<FbScanoutCap, Write>) -> Result<Self, FbWriteError> {
        let scanout = select_active().ok_or(FbWriteError::NoActiveScanout)?;
        Ok(Self { scanout, cap })
    }

    pub fn width(&self)  -> u32 { self.scanout.width() }
    pub fn height(&self) -> u32 { self.scanout.height() }
    pub fn name(&self)   -> &'static str { self.scanout.name() }

    /// Validate cap is still live; returns `Err` if revoked.
    fn check_live(&self) -> Result<(), FbWriteError> {
        self.cap.check_live().map_err(|_| FbWriteError::NoActiveScanout)
    }

    /// Fill a rectangle with `pixel`. Out-of-bounds rects are clipped;
    /// fully-off-screen rects return `OutOfBounds` rather than silently
    /// no-op'ing — callers should detect this at the API boundary.
    pub fn fill(&self, rect: Rect, pixel: Pixel32) -> Result<(), FbWriteError> {
        self.check_live()?;
        let clipped = rect.clip(self.scanout.width(), self.scanout.height())
            .ok_or(FbWriteError::OutOfBounds)?;
        // SAFETY: cap-checked above; FbWriter owns exclusive Write.
        let mut fb = unsafe { self.scanout.framebuffer() };
        fb.fill_rect(clipped.x, clipped.y, clipped.w, clipped.h, pixel);
        Ok(())
    }

    /// Push a rect to the host display (matters on virtio-gpu).
    pub fn flush(&self, rect: Rect) -> Result<(), FbWriteError> {
        self.check_live()?;
        let clipped = rect.clip(self.scanout.width(), self.scanout.height())
            .ok_or(FbWriteError::OutOfBounds)?;
        self.scanout.flush(clipped.x, clipped.y, clipped.w, clipped.h);
        Ok(())
    }
}

/// Read-only view of the active scanout's geometry. Doesn't take a
/// cap because dimensions are not sensitive — callers needing
/// stricter access mint a `Cap<FbScanoutCap, Read>`.
#[derive(Copy, Clone, Debug)]
pub struct ScanoutInfo {
    pub width:  u32,
    pub height: u32,
    pub stride: u32,
    pub format: PixelFormat,
    pub name:   &'static str,
}

pub fn info() -> Option<ScanoutInfo> {
    let s = select_active()?;
    Some(ScanoutInfo {
        width: s.width(), height: s.height(), stride: s.stride(),
        format: s.format(), name: s.name(),
    })
}

/// Stage::Late initcall: log which backend won the picker.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "fb-scanout-picker", || {
        if let Some(s) = select_active() {
            let _ = s.width(); // touch the call surface
            // Successful pick — log via the init crate's log hook
            // when one is set; otherwise quietly return Ok.
            INIT_BACKEND_NAME.store(s.name().as_ptr() as usize, Ordering::Release);
            INIT_BACKEND_LEN.store(s.name().len(),               Ordering::Release);
            InitResult::Ok
        } else {
            InitResult::NotPresent
        }
    });
}

/// Test helper: record the picked backend name during init so
/// smokes can assert without re-running the picker.
static INIT_BACKEND_NAME: AtomicUsize = AtomicUsize::new(0);
static INIT_BACKEND_LEN:  AtomicUsize = AtomicUsize::new(0);

pub fn last_picked_backend() -> Option<&'static str> {
    let p = INIT_BACKEND_NAME.load(Ordering::Acquire) as *const u8;
    let l = INIT_BACKEND_LEN.load(Ordering::Acquire);
    if p.is_null() || l == 0 { return None; }
    // SAFETY: the AtomicUsize pair was published from a `&'static str`
    // whose pointer + length stay valid for the kernel's lifetime.
    unsafe {
        let slice = core::slice::from_raw_parts(p, l);
        Some(core::str::from_utf8_unchecked(slice))
    }
}

// Read-cap stub for completeness; used by future audit smokes.
#[allow(dead_code)]
fn _read_cap_demo(_c: Cap<FbScanoutCap, Read>) {}
