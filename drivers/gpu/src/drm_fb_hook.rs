//! DRM ↔ fbdev hook — registered by the `narf_fb` crate at Stage::Late
//! so the DRM ioctl bridge can blit dumb buffers into the active scanout
//! without creating a circular `narf-drivers-gpu` → `narf-fb` dep.
//!
//! The `narf-fb` crate (which already depends on `narf-drivers-gpu` for
//! the GPU colour-mixing logic) calls `install_drm_fb_hook` during its
//! `Stage::Late` initcall, after which `blit_to_scanout` and
//! `flush_scanout` forward to the real `narf_fb` implementations.
//!
//! ## Geometry hook
//!
//! `query_scanout_info` is a separate read-only hook; it fills the
//! caller's `ScanoutGeom` without taking a write lock. Used by
//! `dispatch_mmap` to confirm the dumb buffer fits the scanout.
//!
//! ## Safety
//!
//! The hooks are installed exactly once during `Stage::Late` (single-CPU
//! init context); subsequently they are read-only. The `UnsafeCell`
//! wrapper lets us store a plain function pointer in a `static`.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

// ── Hook types ────────────────────────────────────────────────────────

/// Geometry of the active scanout (returned by the query hook).
#[derive(Copy, Clone, Debug, Default)]
pub struct ScanoutGeom {
    /// Physical base address of the scanout pixel buffer.
    pub phys: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per scanline.
    pub stride_bytes: u32,
}

type QueryFn = fn() -> Option<ScanoutGeom>;
type FlushFn = fn();

struct HookCell(UnsafeCell<Option<QueryFn>>, UnsafeCell<Option<FlushFn>>);

// SAFETY: installed once at Stage::Late (single-CPU); subsequently read-only.
unsafe impl Sync for HookCell {}

static HOOKS: HookCell = HookCell(UnsafeCell::new(None), UnsafeCell::new(None));
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the fbdev query + flush hooks. Called once from `narf_fb`
/// at `Stage::Late` after the scanout backend has been selected.
///
/// # Safety
/// Must be called from a single-CPU, non-IRQ context (Stage::Late init).
pub unsafe fn install_drm_fb_hook(query: QueryFn, flush: FlushFn) {
    // SAFETY: single-writer, single-CPU init path; no concurrent reader.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        *HOOKS.0.get() = Some(query);
        *HOOKS.1.get() = Some(flush);
    }
    INSTALLED.store(true, Ordering::Release);
}

/// Query the active scanout geometry. Returns `None` if the hook has
/// not been installed yet (headless CI / early-boot).
pub fn query_scanout() -> Option<ScanoutGeom> {
    if !INSTALLED.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: hook was installed before INSTALLED became true; read-only
    // access is safe after the store-release / load-acquire pair.
    // SAFETY: Valid memory or trusted environment
    let f = unsafe { (*HOOKS.0.get())? };
    f()
}

/// Flush the active scanout to the host display. No-op if the hook has
/// not been installed.
pub fn flush_scanout() {
    if !INSTALLED.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: as above.
    // SAFETY: Valid memory or trusted environment
    if let Some(f) = unsafe { *HOOKS.1.get() } {
        f();
    }
}
