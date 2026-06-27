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

pub mod client;
pub mod cmd_ring;
pub mod cursor;
pub mod drain_task;
pub mod fbdev;
pub mod gop;
pub mod registry;
pub mod status;
pub mod vbe;

mod tests;
pub use client::{allocate_singleton_ring, FbClient};
pub use cmd_ring::{DrawCmd, DrawRing, RING_DEPTH, TAG_BLIT, TAG_FILL, TAG_FLUSH};
pub use drain_task::{drain_once, stats as drain_stats, DrainTask};
pub use registry::{
    connect as registry_connect, disconnect as registry_disconnect,
    disconnect_all_for_pid as registry_disconnect_all_for_pid, ConnectError,
};

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
    /// Physical base address of the scanout pixel buffer, if it is a
    /// plain physically-contiguous buffer that can be safely aliased
    /// into a userspace `mmap` (the Linux `/dev/fb0` model). Returns
    /// `None` for backends whose scanout is not directly mappable that
    /// way (e.g. a rebased/ioremapped generic FB). Used by the fbdev
    /// device node — see [`fbdev_info`].
    fn phys_base(&self) -> Option<u64> {
        None
    }
    /// Borrow a `narf_graphics::Framebuffer` view for direct
    /// per-pixel writes. Caller is responsible for serialisation.
    ///
    /// # Safety
    /// Caller must hold a `Cap<FbScanoutCap, Write>` and ensure no
    /// other writer is in flight. The returned Framebuffer aliases
    /// the scanout buffer; lifetime is tied to the scanout's
    /// lifetime (which today is `'static`).
    unsafe fn framebuffer(&self) -> Framebuffer;
}

// ── bochs-display backend ───────────────────────────────────────────

#[derive(Debug)]
struct BochsScanout;

impl FbScanout for BochsScanout {
    fn width(&self) -> u32 {
        narf_graphics_driver::bochs::with_controller(|d| d.width).unwrap_or(0)
    }
    fn height(&self) -> u32 {
        narf_graphics_driver::bochs::with_controller(|d| d.height).unwrap_or(0)
    }
    fn stride(&self) -> u32 {
        self.width()
    }
    fn format(&self) -> PixelFormat {
        PixelFormat::XRGB8888
    }
    fn name(&self) -> &'static str {
        "bochs"
    }
    fn flush(&self, _x: u32, _y: u32, _w: u32, _h: u32) {
        // bochs is direct-MMIO — pixels appear as soon as they're
        // written. No host-side blit needed.
    }
    fn phys_base(&self) -> Option<u64> {
        // BAR0 phys; `fb_reachable()` already proved it's <4 GiB and
        // thus covered by the x86_64 identity map.
        narf_graphics_driver::bochs::with_controller(|d| {
            if d.fb_reachable() {
                Some(d.fb_phys())
            } else {
                None
            }
        })
        .flatten()
    }
    unsafe fn framebuffer(&self) -> Framebuffer {
        // SAFETY: caller-asserted exclusive write access via the cap.
        // bochs::with_controller's framebuffer() returns a fresh
        // pointer view; we replicate it here so the closure's
        // borrow doesn't escape.
        narf_graphics_driver::bochs::with_controller(|d| {
            // SAFETY: same.
            unsafe { d.framebuffer() }
        })
        .expect("bochs scanout selected without controller")
    }
}

// ── Test backend: in-memory scanout ────────────────────────────────
//
// A heap-backed FbScanout used by smokes that want to exercise the
// drain + writer surface without a real display. Only one
// `TestScanout` lives at a time — the global slot is None until
// `install_test_scanout(width, height)` runs, at which point
// `select_active()` returns it (overriding the bochs / virtio-gpu
// preferences). `clear_test_scanout()` removes it.
//
// Used primarily on aarch64, where neither bochs (x86-only) nor
// virtio-gpu (deferred behind ioremap) probes today.

use alloc::vec::Vec;

#[derive(Debug)]
struct TestScanoutInner {
    width: u32,
    height: u32,
    /// Heap pixel buffer. Aliased through `framebuffer()`'s
    /// raw-pointer view — caller-side write semantics handled by
    /// FbWriter's check_live + the smoke's exclusive scope.
    buf: Vec<u32>,
}

#[derive(Debug)]
pub struct TestScanout(narf_lib::sync::IrqSafeSpinLock<TestScanoutInner>);

impl FbScanout for TestScanout {
    fn width(&self) -> u32 {
        self.0.lock().width
    }
    fn height(&self) -> u32 {
        self.0.lock().height
    }
    fn stride(&self) -> u32 {
        self.width()
    }
    fn format(&self) -> PixelFormat {
        PixelFormat::XRGB8888
    }
    fn name(&self) -> &'static str {
        "test"
    }
    fn phys_base(&self) -> Option<u64> {
        // Heap pixel buffer; on the low-4-GiB identity map (x86_64
        // KERNEL_PHYS_OFFSET == 0) its kernel-virtual pointer doubles
        // as the physical base, so the fbdev smokes can exercise
        // mmap_frames without a real display backend.
        Some(self.0.lock().buf.as_ptr() as u64)
    }
    fn flush(&self, _x: u32, _y: u32, _w: u32, _h: u32) {}
    unsafe fn framebuffer(&self) -> Framebuffer {
        let g = self.0.lock();
        // SAFETY: Vec stays alive for the scanout's lifetime;
        // pointer is 4-byte aligned (Vec<u32>); caller's Cap +
        // FbWriter exclusivity gates concurrent writers.
        // SAFETY: Valid memory or trusted environment
        unsafe { Framebuffer::new(g.buf.as_ptr() as *mut u32, g.width, g.height, g.width) }
    }
}

static TEST_SCANOUT: narf_lib::sync::IrqSafeSpinLock<Option<TestScanout>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Install a test scanout of the given dimensions. Subsequent
/// `select_active()` calls return it (overriding the
/// bochs / virtio-gpu picker). `clear_test_scanout()` undoes.
///
/// # Safety
/// Test-only. Smokes call this synchronously to set up the
/// surface, then tear it down with `clear_test_scanout` before
/// returning.
pub fn install_test_scanout(width: u32, height: u32) {
    let buf = alloc::vec![0u32; (width * height) as usize];
    *TEST_SCANOUT.lock() = Some(TestScanout(narf_lib::sync::IrqSafeSpinLock::new(
        TestScanoutInner { width, height, buf },
    )));
}

pub fn clear_test_scanout() {
    *TEST_SCANOUT.lock() = None;
}

/// Read a pixel from the test scanout. Used by smokes to verify
/// that drained Fill commands actually wrote the expected pixel.
pub fn test_scanout_pixel(x: u32, y: u32) -> Option<Pixel32> {
    let g = TEST_SCANOUT.lock();
    let s = g.as_ref()?;
    let inner = s.0.lock();
    if x >= inner.width || y >= inner.height {
        return None;
    }
    let p = inner.buf[(y * inner.width + x) as usize];
    Some(Pixel32(p))
}

// ── virtio-gpu backend ──────────────────────────────────────────────

#[derive(Debug)]
struct VirtioGpuScanout;

impl FbScanout for VirtioGpuScanout {
    fn width(&self) -> u32 {
        narf_drivers_virtio::gpu_pci::with_controller(|d| d.mode.width).unwrap_or(0)
    }
    fn height(&self) -> u32 {
        narf_drivers_virtio::gpu_pci::with_controller(|d| d.mode.height).unwrap_or(0)
    }
    fn stride(&self) -> u32 {
        self.width()
    }
    fn format(&self) -> PixelFormat {
        PixelFormat::XRGB8888
    }
    fn name(&self) -> &'static str {
        "virtio-gpu"
    }
    fn phys_base(&self) -> Option<u64> {
        narf_drivers_virtio::gpu_pci::with_controller(|d| d.scanout_phys())
    }
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
        })
        .expect("virtio-gpu scanout selected without controller")
    }
}

// ── amdgpu backend ──────────────────────────────────────────────────

#[derive(Debug)]
struct AmdgpuScanout;

impl FbScanout for AmdgpuScanout {
    fn width(&self) -> u32 {
        narf_drivers_gpu::amdgpu::with_controller(|d| {
            d.current_mode().map(|m| m.width).unwrap_or(0)
        })
        .unwrap_or(0)
    }
    fn height(&self) -> u32 {
        narf_drivers_gpu::amdgpu::with_controller(|d| {
            d.current_mode().map(|m| m.height).unwrap_or(0)
        })
        .unwrap_or(0)
    }
    fn stride(&self) -> u32 {
        narf_drivers_gpu::amdgpu::with_controller(|d| {
            d.current_mode().map(|m| m.stride).unwrap_or(0)
        })
        .unwrap_or(0)
    }
    fn format(&self) -> PixelFormat {
        PixelFormat::XRGB8888
    }
    fn name(&self) -> &'static str {
        "amdgpu"
    }
    fn flush(&self, _x: u32, _y: u32, _w: u32, _h: u32) {
        // amdgpu is a direct-FB backend (CPU writes to VRAM via
        // the BAR0 MMIO mapping; the DCN scanout DMA's from VRAM
        // straight to the panel). No host-side flush needed —
        // matches the bochs path.
    }
    unsafe fn framebuffer(&self) -> Framebuffer {
        narf_drivers_gpu::amdgpu::with_controller(|d| {
            let mode = d.current_mode().expect("amdgpu scanout without mode");
            let base = d.vram_info().base as *mut u32;
            // SAFETY: amdgpu's BAR0 is mapped + DCN configured to
            // scan out from `base`; the caller holds the FbScanout
            // cap that serializes writers. Stride is in pixels.
            // SAFETY: Valid memory or trusted environment
            unsafe { Framebuffer::new(base, mode.width, mode.height, mode.stride) }
        })
        .expect("amdgpu scanout selected without controller")
    }
}

// ── intel-gpu backend ───────────────────────────────────────────────

#[derive(Debug)]
struct IntelGpuScanout;

impl FbScanout for IntelGpuScanout {
    fn width(&self) -> u32 {
        narf_drivers_gpu::intel_gpu::with_controller(|d| {
            d.current_mode().map(|m| m.width).unwrap_or(0)
        })
        .unwrap_or(0)
    }
    fn height(&self) -> u32 {
        narf_drivers_gpu::intel_gpu::with_controller(|d| {
            d.current_mode().map(|m| m.height).unwrap_or(0)
        })
        .unwrap_or(0)
    }
    fn stride(&self) -> u32 {
        narf_drivers_gpu::intel_gpu::with_controller(|d| {
            d.current_mode().map(|m| m.stride_bytes / 4).unwrap_or(0)
        })
        .unwrap_or(0)
    }
    fn format(&self) -> PixelFormat {
        PixelFormat::XRGB8888
    }
    fn name(&self) -> &'static str {
        "intel-gpu"
    }
    fn flush(&self, _x: u32, _y: u32, _w: u32, _h: u32) {
        // Direct-FB backend. No host-side flush needed.
    }
    unsafe fn framebuffer(&self) -> Framebuffer {
        narf_drivers_gpu::intel_gpu::with_controller(|d| {
            let mode = d.current_mode().expect("intel-gpu scanout without mode");
            // GMADR is mapped in the CPU, we offset it by the active scanout offset.
            let base = (d.gmadr.phys.as_u64() + mode.gtt_offset as u64) as *mut u32;
            // SAFETY: `base` points into the CPU-mapped GMADR aperture at the
            // active scanout's `gtt_offset`; the aperture is 4-byte aligned and
            // covers `width*height` pixels at `stride_bytes/4` pixels per row.
            // The caller holds the FbScanout cap that serializes writers.
            // SAFETY: Valid memory or trusted environment
            unsafe { Framebuffer::new(base, mode.width, mode.height, mode.stride_bytes / 4) }
        })
        .expect("intel-gpu scanout selected without controller")
    }
}

// ── active-scanout picker ───────────────────────────────────────────

static BOCHS: BochsScanout = BochsScanout;
static VIRTIO_GPU: VirtioGpuScanout = VirtioGpuScanout;
static AMDGPU: AmdgpuScanout = AmdgpuScanout;
static INTEL_GPU: IntelGpuScanout = IntelGpuScanout;
static GENERIC: GenericScanout = GenericScanout;

/// Global registration for the bootloader-provided linear framebuffer.
static GENERIC_FB: narf_lib::sync::IrqSafeSpinLock<
    Option<narf_graphics_driver::generic::GenericFb>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn register_generic(fb: narf_graphics_driver::generic::GenericFb) {
    *GENERIC_FB.lock() = Some(fb);
}

/// Rebase the generic-FB's base address to a remapped virt (e.g.
/// the WC ioremap result). Preserves width/height/pitch/bpp;
/// future `framebuffer()` calls will return a Framebuffer that
/// writes to `new_addr` instead of the original bus-phys.
///
/// No-op when no GenericFb is registered. Single-threaded boot
/// context only.
pub fn rebase_generic(new_addr: u64) {
    if let Some(fb) = GENERIC_FB.lock().as_mut() {
        fb.addr = new_addr;
    }
}

/// Original bus-phys of the generic FB, before any rebase.
/// Returns `None` if no GenericFb is registered, or if rebase
/// already happened (caller's responsibility to read this BEFORE
/// calling `rebase_generic`).
pub fn generic_phys() -> Option<u64> {
    GENERIC_FB.lock().as_ref().map(|f| f.addr)
}

/// Backend-agnostic scanout view for the boot-provided linear FB.
#[derive(Debug)]
struct GenericScanout;

impl FbScanout for GenericScanout {
    fn width(&self) -> u32 {
        GENERIC_FB.lock().as_ref().map(|f| f.width).unwrap_or(0)
    }
    fn height(&self) -> u32 {
        GENERIC_FB.lock().as_ref().map(|f| f.height).unwrap_or(0)
    }
    fn stride(&self) -> u32 {
        GENERIC_FB.lock().as_ref().map(|f| f.stride()).unwrap_or(0)
    }
    fn format(&self) -> PixelFormat {
        PixelFormat::XRGB8888
    }
    fn name(&self) -> &'static str {
        "generic-fb"
    }
    fn flush(&self, _x: u32, _y: u32, _w: u32, _h: u32) {}
    unsafe fn framebuffer(&self) -> Framebuffer {
        GENERIC_FB
            .lock()
            .as_ref()
            .map(|f| {
                // SAFETY: register_generic caller asserts addr/size validity.
                unsafe { f.framebuffer() }
            })
            .expect("generic-fb scanout selected without device")
    }
}

/// Picker. Prefers a test scanout (when installed) for hermetic
/// smokes; otherwise bochs (no command-queue tax) when its BAR is
/// reachable; otherwise virtio-gpu. Returns `None` when none of
/// the above is available.
///
/// The test-scanout branch leaks a 'static reference via a
/// trick: we re-cast the lock contents' address. Since the
/// TEST_SCANOUT static lives forever and the contained TestScanout
/// is moved-only via `install_test_scanout` / `clear_test_scanout`
/// (no other path mutates the slot), the resulting `&'static`
/// stays valid until clear_test_scanout runs.
pub fn select_active() -> Option<&'static dyn FbScanout> {
    {
        let g = TEST_SCANOUT.lock();
        if let Some(s) = g.as_ref() {
            let ptr: *const TestScanout = s as *const TestScanout;
            // SAFETY: `ptr` points at the `Some(...)` interior of the static
            // TEST_SCANOUT IrqSafeSpinLock<Option<TestScanout>>. The static
            // lives forever and the slot is only mutated by
            // install_test_scanout / clear_test_scanout, so the `&'static`
            // re-cast stays valid while the slot remains Some. Smokes
            // install + use + clear within a single single-CPU test boundary,
            // so no concurrent mutation of the slot occurs.
            // SAFETY: Valid memory or trusted environment
            return Some(unsafe { &*ptr });
        }
    }
    // Native AMD GPU wins over QEMU bochs / virtio-gpu when both
    // Prefer the Limine GOP "generic-fb" scanout when registered:
    // the bootloader already painted into it at known-good
    // dimensions, and the kernel's early-fb console install has
    // verified it's writeable from the BSP. amdgpu's `current_mode`
    // returns Some on a UEFI-passive mode regardless of whether
    // DCN bring-up actually wired the scanout, which on real Zen2
    // silicon makes the FB-console hook re-bind at Stage::Late to
    // an amdgpu scanout whose backing isn't actually live —
    // observable as "boot reaches `scheduler: spawning 1 task`
    // then no further FB output, no shell prompt". Keep using
    // GENERIC until amdgpu can prove it owns a working scanout
    // (firmware-loaded + post-set_mode), tracked separately.
    if GENERIC_FB.lock().is_some() {
        return Some(&GENERIC);
    }
    if narf_drivers_gpu::amdgpu::is_probed() {
        let mode_ok = narf_drivers_gpu::amdgpu::with_controller(|d| d.current_mode().is_some())
            .unwrap_or(false);
        if mode_ok {
            return Some(&AMDGPU);
        }
    }
    if narf_graphics_driver::bochs::is_probed() {
        let reachable =
            narf_graphics_driver::bochs::with_controller(|d| d.fb_reachable()).unwrap_or(false);
        if reachable {
            return Some(&BOCHS);
        }
    }
    if narf_drivers_virtio::gpu_pci::is_probed() {
        let ready = narf_drivers_virtio::gpu_pci::with_controller(|d| d.ready).unwrap_or(false);
        if ready {
            return Some(&VIRTIO_GPU);
        }
    }
    if narf_drivers_gpu::intel_gpu::is_probed() {
        let mode_ok = narf_drivers_gpu::intel_gpu::with_controller(|d| d.current_mode().is_some())
            .unwrap_or(false);
        if mode_ok {
            return Some(&INTEL_GPU);
        }
    }
    None
}

// ── fbdev (`/dev/fb0`) backing ──────────────────────────────────────

/// Geometry + physical backing of the active scanout, for the Linux
/// `/dev/fb0` framebuffer device. All fields describe the live
/// scanout the picker selected; `phys` is the base of the pixel
/// buffer to alias into a userspace `mmap`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FbdevInfo {
    /// Physical base address of the scanout pixel buffer.
    pub phys: u64,
    /// Visible width in pixels.
    pub width: u32,
    /// Visible height in pixels.
    pub height: u32,
    /// Bytes per scanline (`stride_pixels * 4` for XRGB8888).
    pub stride_bytes: u32,
    /// Bits per pixel (32 — XRGB8888).
    pub bpp: u32,
}

impl FbdevInfo {
    /// Total bytes of the scanout buffer (`stride_bytes * height`),
    /// rounded up to a page — the size a `/dev/fb0` mmap covers.
    pub fn map_len(&self) -> usize {
        let raw = self.stride_bytes as usize * self.height as usize;
        (raw + 0xFFF) & !0xFFF
    }
}

/// Query the active scanout for `/dev/fb0`. Returns `None` when no
/// scanout is selected yet, or the selected backend can't expose a
/// directly-mappable physical buffer (`phys_base() == None`).
pub fn fbdev_info() -> Option<FbdevInfo> {
    let s = select_active()?;
    let phys = s.phys_base()?;
    let width = s.width();
    let height = s.height();
    if width == 0 || height == 0 {
        return None;
    }
    Some(FbdevInfo {
        phys,
        width,
        height,
        stride_bytes: s.stride().checked_mul(4)?,
        bpp: 32,
    })
}

/// Flush the whole active scanout to the host display. No-op for
/// direct-MMIO backends (bochs); on virtio-gpu this issues
/// TRANSFER_TO_HOST_2D + RESOURCE_FLUSH so a `/dev/fb0` writer's
/// pixels become visible.
pub fn fbdev_flush() {
    if let Some(s) = select_active() {
        s.flush(0, 0, s.width(), s.height());
    }
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
    pub const fn new(x: u32, y: u32, w: u32, h: u32) -> Self {
        Self { x, y, w, h }
    }
    /// Clip this rect against the supplied bounds. Returns the
    /// intersection or `None` if the rects don't overlap.
    pub fn clip(self, fb_w: u32, fb_h: u32) -> Option<Self> {
        if self.x >= fb_w || self.y >= fb_h || self.w == 0 || self.h == 0 {
            return None;
        }
        let x_end = self.x.saturating_add(self.w).min(fb_w);
        let y_end = self.y.saturating_add(self.h).min(fb_h);
        Some(Self {
            x: self.x,
            y: self.y,
            w: x_end - self.x,
            h: y_end - self.y,
        })
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
    cap: Cap<FbScanoutCap, Write>,
}

impl FbWriter {
    /// Construct from an existing Write cap. Returns
    /// `NoActiveScanout` if no backend has probed.
    pub fn new(cap: Cap<FbScanoutCap, Write>) -> Result<Self, FbWriteError> {
        let scanout = select_active().ok_or(FbWriteError::NoActiveScanout)?;
        Ok(Self { scanout, cap })
    }

    pub fn width(&self) -> u32 {
        self.scanout.width()
    }
    pub fn height(&self) -> u32 {
        self.scanout.height()
    }
    pub fn name(&self) -> &'static str {
        self.scanout.name()
    }

    /// Validate cap is still live; returns `Err` if revoked.
    fn check_live(&self) -> Result<(), FbWriteError> {
        self.cap
            .check_live()
            .map_err(|_| FbWriteError::NoActiveScanout)
    }

    /// Fill a rectangle with `pixel`. Out-of-bounds rects are clipped;
    /// fully-off-screen rects return `OutOfBounds` rather than silently
    /// no-op'ing — callers should detect this at the API boundary.
    pub fn fill(&self, rect: Rect, pixel: Pixel32) -> Result<(), FbWriteError> {
        self.check_live()?;
        let clipped = rect
            .clip(self.scanout.width(), self.scanout.height())
            .ok_or(FbWriteError::OutOfBounds)?;
        // SAFETY: cap-checked above; FbWriter owns exclusive Write.
        let mut fb = unsafe { self.scanout.framebuffer() };
        fb.fill_rect(clipped.x, clipped.y, clipped.w, clipped.h, pixel);
        Ok(())
    }

    /// Push a rect to the host display (matters on virtio-gpu).
    pub fn flush(&self, rect: Rect) -> Result<(), FbWriteError> {
        self.check_live()?;
        let clipped = rect
            .clip(self.scanout.width(), self.scanout.height())
            .ok_or(FbWriteError::OutOfBounds)?;
        self.scanout
            .flush(clipped.x, clipped.y, clipped.w, clipped.h);
        Ok(())
    }

    /// Blit a row-major XRGB8888 source buffer into `rect`.
    /// `src.len()` must equal `rect.w * rect.h`. Out-of-bounds
    /// rects are clipped; the source is sub-sampled accordingly
    /// (top-left aligned at the unclipped origin).
    ///
    /// Kernel-side primitive for callers that already have the
    /// pixels in a `&[Pixel32]`. Userspace producers go through
    /// `blit_from_shmem` via `TAG_BLIT` instead.
    pub fn blit(&self, rect: Rect, src: &[Pixel32]) -> Result<(), FbWriteError> {
        self.check_live()?;
        if src.len() != (rect.w as usize) * (rect.h as usize) {
            return Err(FbWriteError::OutOfBounds);
        }
        let clipped = rect
            .clip(self.scanout.width(), self.scanout.height())
            .ok_or(FbWriteError::OutOfBounds)?;
        // Offsets into `src` accounting for the clip. Clipping can
        // shrink the rect from any edge; preserve the unclipped
        // origin so a partially-offscreen blit still places its
        // visible pixels at the right place.
        let dx = (clipped.x - rect.x) as usize;
        let dy = (clipped.y - rect.y) as usize;
        // SAFETY: cap-checked above; FbWriter owns exclusive Write.
        let mut fb = unsafe { self.scanout.framebuffer() };
        for row in 0..clipped.h {
            for col in 0..clipped.w {
                let s = src[(dy + row as usize) * (rect.w as usize) + (dx + col as usize)];
                fb.draw_pixel(clipped.x + col, clipped.y + row, s);
            }
        }
        Ok(())
    }

    /// Blit from a `narf-shmem` region. `buffer` is the shmem
    /// handle; `src_offset` is the byte offset of the top-left
    /// source pixel; `src_stride` is bytes per source row
    /// (typically `w * 4`, but may be larger to blit a sub-rect
    /// of a wider image). The source format is XRGB8888.
    ///
    /// Out-of-bounds destination rects are clipped; clipped
    /// pixels skip the source read so an off-screen edge of the
    /// blit doesn't fault on a missing shmem byte.
    pub fn blit_from_shmem(
        &self,
        rect: Rect,
        buffer: u64,
        src_offset: u32,
        src_stride: u32,
    ) -> Result<(), FbWriteError> {
        self.check_live()?;
        if src_stride < rect.w.saturating_mul(4) {
            return Err(FbWriteError::OutOfBounds);
        }
        let clipped = rect
            .clip(self.scanout.width(), self.scanout.height())
            .ok_or(FbWriteError::OutOfBounds)?;
        let dx = clipped.x - rect.x;
        let dy = clipped.y - rect.y;
        // Pre-validate the deepest source byte: if the buffer is
        // too small or the handle is bogus, fail before any pixel
        // lands on the scanout.
        let last_row = dy + clipped.h - 1;
        let last_col = dx + clipped.w - 1;
        let last_off =
            src_offset as u64 + last_row as u64 * src_stride as u64 + last_col as u64 * 4 + 3;
        if narf_shmem::phys_at(buffer, last_off).is_none() {
            return Err(FbWriteError::OutOfBounds);
        }
        // SAFETY: cap-checked above; FbWriter owns exclusive Write.
        let mut fb = unsafe { self.scanout.framebuffer() };
        for row in 0..clipped.h {
            let row_base =
                src_offset as u64 + (dy + row) as u64 * src_stride as u64 + dx as u64 * 4;
            for col in 0..clipped.w {
                let off = row_base + col as u64 * 4;
                // SAFETY: identity-mapped low-RAM frame; we
                // pre-validated `last_off`, so every (row, col)
                // pair within the clipped region maps to a valid
                // phys we own (kernel-allocated shmem frames).
                let phys = match narf_shmem::phys_at(buffer, off) {
                    Some(p) => p,
                    None => return Err(FbWriteError::OutOfBounds),
                };
                // SAFETY: `phys` was just resolved by `phys_at` for this in-bounds
                // (row, col) offset, so it is a valid identity-mapped address of a
                // kernel-allocated shmem frame we own; the 4-byte u32 read is within
                // that frame and naturally aligned (offset is a multiple of 4).
                // SAFETY: Valid memory or trusted environment
                let pix = unsafe { core::ptr::read_volatile(phys as *const u32) };
                fb.draw_pixel(clipped.x + col, clipped.y + row, Pixel32(pix));
            }
        }
        Ok(())
    }
}

/// Read-only view of the active scanout's geometry. Doesn't take a
/// cap because dimensions are not sensitive — callers needing
/// stricter access mint a `Cap<FbScanoutCap, Read>`.
#[derive(Copy, Clone, Debug)]
pub struct ScanoutInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: PixelFormat,
    pub name: &'static str,
}

pub fn info() -> Option<ScanoutInfo> {
    let s = select_active()?;
    Some(ScanoutInfo {
        width: s.width(),
        height: s.height(),
        stride: s.stride(),
        format: s.format(),
        name: s.name(),
    })
}

/// Cached `FbWriter` for the synchronous drain pump. Constructed
/// **once** at boot via `init_pump_writer` (under
/// `register_initcalls`'s `fb-drain-task` step). The pump reads
/// it through `UnsafeCell` because `FbWriter` is not `Sync` —
/// safety relies on the pump-call discipline below.
///
/// Why static: `Cap::bootstrap()` allocates a fresh object-table
/// slot on every call. The pump fires from `sys_sleep`'s busy-
/// wait at ~3 kHz; minting a cap per call grows the cap table
/// without bound and eventually wedges allocation.
static PUMP_WRITER: PumpWriterCell = PumpWriterCell::new();

struct PumpWriterCell(core::cell::UnsafeCell<Option<FbWriter>>);

// SAFETY: PUMP_WRITER is written exactly once during boot
// (single-threaded init), then read-only thereafter from sys_sleep
// pump callers. Concurrent pump invocations only call
// `drain_task::drain_once(&FbWriter)` which takes `&self`; no
// mutation crosses cores.
unsafe impl Sync for PumpWriterCell {}

impl PumpWriterCell {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(None))
    }
}

/// Synchronous drain pump for the userspace `sys_sleep` hook.
/// Reads the boot-cached writer and runs one drain pass; cheap
/// on empty rings.
fn fb_drain_pump() {
    // SAFETY: PUMP_WRITER is initialised once at boot before any
    // user task calls sys_sleep (the FB-drain initcall runs in
    // Stage::Late which precedes user-task spawn). After that
    // it's read-only.
    // SAFETY: Valid memory or trusted environment
    let opt = unsafe { &*PUMP_WRITER.0.get() };
    if let Some(w) = opt.as_ref() {
        let _ = drain_task::drain_once(w);
    }
}

/// One-shot initialiser for `PUMP_WRITER`. Called from the
/// `fb-drain-task` initcall after `FbWriter::new` succeeds for
/// the spawned drain future. Idempotent: only the first call
/// stores; subsequent calls are silently dropped.
fn init_pump_writer(writer: FbWriter) {
    static DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if DONE
        .compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    {
        // SAFETY: first-and-only writer; no concurrent reader yet
        // (the pump can't fire before `register_initcalls`
        // completes Stage::Late).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            *PUMP_WRITER.0.get() = Some(writer);
        }
    }
}

/// Borrow the boot-cached pump writer if one was installed.
/// `None` before `fb-drain-task` runs, or when no scanout was
/// active. Used by the cursor sleep-pump tick to avoid minting a
/// fresh `Cap::bootstrap()` per call.
pub(crate) fn pump_writer_ref() -> Option<&'static FbWriter> {
    // SAFETY: PUMP_WRITER is initialised once at boot; subsequent
    // accesses are read-only. The returned reference is valid for
    // the lifetime of the static.
    // SAFETY: Valid memory or trusted environment
    unsafe { (&*PUMP_WRITER.0.get()).as_ref() }
}

impl FbWriter {
    /// Acquire the underlying `Framebuffer` view for the cursor
    /// renderer's read-pixel pass. `pub(crate)` because direct
    /// framebuffer access bypasses the cap-checked write helpers
    /// (fill / blit / flush) — only the cursor save-restore loop
    /// is allowed to use it, and it only reads.
    ///
    /// # Safety
    /// Caller must ensure no other agent holds a `Framebuffer`
    /// view of the same scanout for the lifetime of the returned
    /// value (FbWriter is the FB owner; concurrent draws by other
    /// FbWriters race the underlying MMIO).
    pub(crate) unsafe fn scanout_for_cursor(&self) -> narf_graphics::Framebuffer {
        // SAFETY: forwarded to caller — see method docs.
        unsafe { self.scanout.framebuffer() }
    }

    /// Mutable variant for the status panel's `draw_string_8x8`
    /// pass (which takes `&mut Framebuffer`). Same exclusivity
    /// caveat as `scanout_for_cursor`; called once at end of boot
    /// before user tasks tighten contention.
    ///
    /// # Safety
    /// Same as `scanout_for_cursor`.
    pub(crate) unsafe fn scanout_for_cursor_mut(&self) -> narf_graphics::Framebuffer {
        // SAFETY: forwarded to caller.
        unsafe { self.scanout.framebuffer() }
    }
}

/// Stage::Late initcall: log which backend won the picker, then
/// run a small kernel-resident producer→ring→consumer→FB demo
/// that proves the architectural chain end-to-end. The demo is
/// the same pattern a userspace process will eventually use over
/// an mmap'd DrawRing; only the page-source differs.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    // Install the userspace FB syscall vtable now so a userspace
    // process can SYS_FB_CONNECT as soon as it runs. (Stage::Subsys
    // runs before Stage::Late, but install_core_syscalls also
    // hasn't run yet; the vtable install is idempotent and
    // userspace can't dispatch into FB syscalls until both are in
    // place.)
    narf_init::register(Stage::Subsys, "fb-syscall-vtable", || {
        narf_userspace::handlers::install_fb_syscall_vtable(registry::syscall_vtable());
        InitResult::Ok
    });
    // Process-exit observer: reap any FB connections the dying
    // process held. Without this, a crashed userspace leaks ring
    // pages + handle entries until reboot.
    narf_init::register(Stage::Subsys, "fb-exit-observer", || {
        narf_userspace::user_task::register_exit_observer(|pid, _tid| {
            let _ = registry::disconnect_all_for_pid(pid);
        });
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "fb-scanout-picker", || {
        if let Some(s) = select_active() {
            INIT_BACKEND_NAME.store(s.name().as_ptr() as usize, Ordering::Release);
            INIT_BACKEND_LEN.store(s.name().len(), Ordering::Release);
            InitResult::Ok
        } else {
            InitResult::NotPresent
        }
    });
    // Install the DRM fbdev hook so the GPU driver's dumb-buffer SETCRTC
    // can blit into the live scanout without a circular crate dependency.
    // The hook is a function pointer; installing it once during Stage::Late
    // (single-CPU, non-IRQ) is safe.
    narf_init::register(Stage::Late, "drm-fb-hook", || {
        fn query() -> Option<narf_drivers_gpu::drm_fb_hook::ScanoutGeom> {
            let info = fbdev_info()?;
            Some(narf_drivers_gpu::drm_fb_hook::ScanoutGeom {
                phys: info.phys,
                width: info.width,
                height: info.height,
                stride_bytes: info.stride_bytes,
            })
        }
        fn flush() {
            fbdev_flush();
        }
        // SAFETY: single-CPU Stage::Late initcall; no concurrent reader.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            narf_drivers_gpu::drm_fb_hook::install_drm_fb_hook(query, flush);
        }
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "fb-drain-task", || {
        if select_active().is_none() {
            return InitResult::NotPresent;
        }
        let cap = bootstrap_writer();
        let writer = match FbWriter::new(cap) {
            Ok(w) => w,
            Err(_) => return InitResult::Error("FbWriter::new"),
        };
        let pump_cap = bootstrap_writer();
        if let Ok(pump_writer) = FbWriter::new(pump_cap) {
            init_pump_writer(pump_writer);
            narf_userspace::handlers::sleep_pumps::register(fb_drain_pump);
        }
        // Timer-driven drain loop: drains all registered FB
        // command rings + repaints the status panel at ~60 Hz.
        // Sleeps between frames so init/shell/driver pumps run
        // in the gaps. Replaces the old self-wake (wake_by_ref
        // + Pending) shape that busy-looped the executor — on
        // QEMU the scheduler had enough slack to interleave;
        // on real silicon where MMIO costs orders of magnitude
        // more per write, the self-wake starved init and the
        // shell prompt never appeared. Preempt-from-trap was
        // capping the symptom on QEMU but couldn't on real HW.
        let _ = narf_scheduler::spawn_stackful(drain_task::drain_loop(writer));
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "fb-status-refresh", || {
        if select_active().is_none() {
            return InitResult::NotPresent;
        }
        let cap = bootstrap_writer();
        let writer = match FbWriter::new(cap) {
            Ok(w) => w,
            Err(_) => return InitResult::Error("FbWriter::new"),
        };
        // status::paint is now LOCK-FREE — every value rendered is
        // an atomic load. The previous "registry::list().len()" /
        // "with_controller(...)" / "find_all_devices_by_hid" path
        // wedged real HW because IrqSafeSpinLock disables IF on
        // the waiter; a driver mid-MMIO holding any registry lock
        // froze the whole executor's CPU. The atomic-snapshot
        // rewrite means this task can paint every 250 ms without
        // ever blocking init/shell.
        narf_scheduler::spawn_stackful(async move {
            loop {
                // Suppress the kernel status panel while a userspace
                // compositor (DRM master) owns the scanout — otherwise it
                // bleeds kernel chrome over the desktop.
                if !narf_console::fb_user_owned() {
                    status::paint(&writer);
                }
                narf_time::sleep_cycles(800_000_000).await;
            }
        });
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "fb-cursor-pump", || {
        if select_active().is_none() {
            return InitResult::NotPresent;
        }
        // Sleep-pump tick wires the cursor into the sys_sleep
        // busy-wait so the pointer keeps moving while a user
        // task is parked.
        narf_userspace::handlers::sleep_pumps::register(cursor::sleep_pump_tick);
        let cap = bootstrap_writer();
        let writer = match FbWriter::new(cap) {
            Ok(w) => w,
            Err(_) => return InitResult::Error("FbWriter::new"),
        };
        // Timer-driven cursor pump (60 Hz refresh via sleep_cycles).
        let _ = narf_scheduler::spawn_stackful(cursor::pump(writer));
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "fb-client-demo", || {
        if select_active().is_none() {
            return InitResult::NotPresent;
        }
        let cap = bootstrap_writer();
        let writer = match FbWriter::new(cap) {
            Ok(w) => w,
            Err(_) => return InitResult::Error("FbWriter::new"),
        };
        // SAFETY: SPSC contract — local ring, locally-scoped halves.
        let (_ring, producer, mut consumer) = unsafe { client::allocate_singleton_ring() };
        let mut c = client::FbClient::new(producer);
        let mut total = 0u32;
        // Three fills + a flush so flush also crosses the wire.
        let _ = c.fill(Rect::new(0, 0, 4, 4), Pixel32::rgb(0xC0, 0x10, 0x10).raw());
        let _ = c.fill(Rect::new(8, 0, 4, 4), Pixel32::rgb(0x10, 0xC0, 0x10).raw());
        let _ = c.fill(Rect::new(16, 0, 4, 4), Pixel32::rgb(0x10, 0x10, 0xC0).raw());
        let _ = c.flush(Rect::new(0, 0, 24, 4));
        let (ok, err) = cmd_ring::drain(&mut consumer, &writer);
        total += ok;
        let _ = err;
        if total >= 3 {
            InitResult::Ok
        } else {
            InitResult::Error("drain stalled")
        }
    });
    // Register /dev/fb0 once a mappable scanout exists. NotPresent on
    // headless CI (no backend exposes a physical buffer).
    narf_init::register(Stage::Late, "fb-devfs", || {
        if fbdev_info().is_none() {
            return InitResult::NotPresent;
        }
        narf_filesystem::devfs::register_fb0(alloc::sync::Arc::new(crate::fbdev::DevFb0));
        InitResult::Ok
    });
}

/// Test helper: record the picked backend name during init so
/// smokes can assert without re-running the picker.
static INIT_BACKEND_NAME: AtomicUsize = AtomicUsize::new(0);
static INIT_BACKEND_LEN: AtomicUsize = AtomicUsize::new(0);

pub fn last_picked_backend() -> Option<&'static str> {
    let p = INIT_BACKEND_NAME.load(Ordering::Acquire) as *const u8;
    let l = INIT_BACKEND_LEN.load(Ordering::Acquire);
    if p.is_null() || l == 0 {
        return None;
    }
    // SAFETY: the AtomicUsize pair was published from a `&'static str`
    // whose pointer + length stay valid for the kernel's lifetime.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let slice = core::slice::from_raw_parts(p, l);
        Some(core::str::from_utf8_unchecked(slice))
    }
}

// Read-cap stub for completeness; used by future audit smokes.
#[allow(dead_code)]
fn _read_cap_demo(_c: Cap<FbScanoutCap, Read>) {}
