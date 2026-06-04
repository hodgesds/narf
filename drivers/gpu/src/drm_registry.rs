//! DRM card registry — global `Arc<dyn DrmCard>` table.
//!
//! Every GPU driver calls `register_drm_card` at probe success and gets
//! back a card-index that determines the `/dev/dri/card<N>` minor number
//! and the `/sys/class/drm/card<N>/` kobject name.
//!
//! Thread-safety: registration happens at `Stage::Subsys` (single-threaded
//! kernel init). Reads can occur from any context.
//!
//! ## Linux reference
//!
//! - `drivers/gpu/drm/drm_drv.c::drm_dev_register` — card index assignment
//!   and minor allocation.
//! - `include/drm/drm_device.h::drm_device` — the Linux analogue of
//!   `DrmCard`.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

// ── DrmCard trait ──────────────────────────────────────────────────────────

/// Trait implemented by every registered DRM card.
///
/// The trait provides the fields that the sysfs bridge and devfs bridge
/// need. Implementations live in the per-driver source files
/// (`BochsCard` in `drm_devfs_bridge.rs`, `AmdgpuCard` inline in
/// `amdgpu.rs`, etc.).
///
/// Linux analogue: `struct drm_device` + `struct drm_driver`.
pub trait DrmCard: Send + Sync {
    /// Short name, e.g. `"card0"`. Assigned at registration time.
    fn name(&self) -> &str;

    /// Driver short-name, e.g. `"amdgpu"` or `"bochs"`.
    ///
    /// Linux ref: `drm_driver::name`.
    fn driver(&self) -> &str;

    /// PCI vendor id (16-bit), e.g. `0x1002` (AMD) or `0x1234` (bochs).
    fn vendor_id(&self) -> u16;

    /// PCI device id, e.g. `0x1636` (Renoir) or `0x1111` (bochs).
    fn device_id(&self) -> u16;

    /// PCI subsystem vendor id. `0x0000` when unknown.
    fn subsystem_vendor(&self) -> u16;

    /// PCI subsystem device id. `0x0000` when unknown.
    fn subsystem_device(&self) -> u16;

    /// VBIOS version string if the driver read it, else `None`.
    ///
    /// Linux ref: `amdgpu_device_get_vbios_version` →
    /// `/sys/class/drm/card0/device/vbios_version`.
    fn vbios_version(&self) -> Option<&str>;

    /// Current GPU busy percentage (0–100). `None` when the driver
    /// can't measure it (pre-firmware, bochs, etc.).
    ///
    /// Linux ref: `amdgpu_sysfs_get_gpu_busy_percent`.
    fn gpu_busy_percent(&self) -> Option<u32>;

    /// Current power state string, e.g. `"D0"`.
    ///
    /// Linux ref: `amdgpu_pm_info_read` → `power_dpm_state`.
    fn power_state(&self) -> &str;
}

// ── Global registry ────────────────────────────────────────────────────────

/// One entry in the global DRM card table.
pub struct DrmCardEntry {
    /// Assigned card index (0-based). Determines `/dev/dri/card<N>`.
    pub index: u32,
    /// The card object.
    pub card: Arc<dyn DrmCard>,
    /// Per-card mode-setting state (CRTCs / connectors / encoders /
    /// framebuffers / GEM objects). The ioctl layer takes the spin-
    /// lock for the duration of a single DRM_IOCTL_* dispatch.
    ///
    /// Optional because the registry is also used by drivers that
    /// haven't yet built a `drm::card::Card` (early bring-up). The
    /// DRM ioctl path returns ENOTSUP for those cards.
    pub mode_state: Option<Arc<IrqSafeSpinLock<crate::drm::card::Card>>>,
}

impl core::fmt::Debug for DrmCardEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DrmCardEntry")
            .field("index", &self.index)
            .field("card_name", &self.card.name())
            .finish_non_exhaustive()
    }
}

static REGISTRY: IrqSafeSpinLock<Vec<DrmCardEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Register a DRM card and return its assigned index.
///
/// The card index is determined by the current registry length
/// (registration order). The mode-setting state is left at `None` —
/// drivers that need ioctl dispatch call `attach_mode_state` after.
///
/// Linux ref: `drm_dev_register` (drivers/gpu/drm/drm_drv.c).
pub fn register_drm_card(card: Arc<dyn DrmCard>) -> u32 {
    let mut g = REGISTRY.lock();
    let index = g.len() as u32;
    g.push(DrmCardEntry {
        index,
        card,
        mode_state: None,
    });
    index
}

/// Register a DRM card with its mode-setting state in one go.
///
/// Callers that have already built a `drm::card::Card` (with CRTCs,
/// connectors, encoders enumerated) pass it here so DRM_IOCTL_*
/// dispatch works against this card from the moment of registration.
pub fn register_drm_card_with_state(
    card: Arc<dyn DrmCard>,
    mode_state: crate::drm::card::Card,
) -> u32 {
    let mut g = REGISTRY.lock();
    let index = g.len() as u32;
    g.push(DrmCardEntry {
        index,
        card,
        mode_state: Some(Arc::new(IrqSafeSpinLock::new(mode_state))),
    });
    index
}

/// Attach (or replace) the mode-setting state for a previously
/// registered card. Returns `true` on success, `false` if `index`
/// is out of range.
pub fn attach_mode_state(index: u32, mode_state: crate::drm::card::Card) -> bool {
    let mut g = REGISTRY.lock();
    if let Some(entry) = g.get_mut(index as usize) {
        entry.mode_state = Some(Arc::new(IrqSafeSpinLock::new(mode_state)));
        true
    } else {
        false
    }
}

/// Look up the mode-setting state Arc for a card index. Cheap clone
/// of an `Arc`; the caller holds the spin-lock only for the duration
/// of one ioctl dispatch.
pub fn mode_state(index: u32) -> Option<Arc<IrqSafeSpinLock<crate::drm::card::Card>>> {
    REGISTRY
        .lock()
        .get(index as usize)
        .and_then(|e| e.mode_state.clone())
}

/// Return a snapshot of all registered cards (clones the Arc pointers;
/// does not clone card state). The lock is held only for the clone.
pub fn cards() -> Vec<Arc<dyn DrmCard>> {
    REGISTRY.lock().iter().map(|e| e.card.clone()).collect()
}

/// Number of registered DRM cards.
pub fn count() -> usize {
    REGISTRY.lock().len()
}

/// Clear the registry. TEST USE ONLY.
#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}
