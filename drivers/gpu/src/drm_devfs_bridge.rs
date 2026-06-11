//! DRM devfs bridge — `/dev/dri/card<N>` + `/dev/dri/renderD<N+128>`.
//!
//! Installs a `DriDir` delegate via `narf_filesystem::devfs::register_dri_dir`
//! so that `/dev/dri/` resolves through `DirOps` backed by the DRM card
//! registry.
//!
//! Two `FileOps` per card:
//!
//! - `DriCardFile`   — full DRM master access (modeset privileged).
//!   `stat` returns `FileType::Special`, mode `0o620` (crw--w----).
//! - `DriRenderFile` — render-only (no modeset; for Mesa render worker).
//!   `stat` returns `FileType::Special`, mode `0o666`.
//!
//! Both are placeholder FileOps for now. Real `DRM_IOCTL_*` dispatch needs
//! a kernel ioctl path which is deferred (NARF has no ioctl gate yet).
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_drv.c::drm_dev_register` — minor allocation.
//! - `drivers/gpu/drm/drm_file.c::drm_open` — open dispatch.
//! - `include/uapi/linux/major.h` — DRM_MAJOR = 226.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};

// ── DriCardFile ────────────────────────────────────────────────────────────

/// Placeholder file for `/dev/dri/card<N>` (DRM master node).
///
/// Read returns 0 (EOF). Write returns `InvalidData` — real DRM
/// operations go through ioctl (deferred). Stat mode is `0o620`
/// matching Linux's `DRM_DEV_MODE` for the primary node.
///
/// Linux ref: `drivers/gpu/drm/drm_drv.c` + `include/uapi/linux/major.h`.
#[derive(Debug)]
pub struct DriCardFile {
    index: u32,
}

impl FileOps for DriCardFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::InvalidData) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                // crw--w---- 0o620: DRM card node — full master.
                // Linux: DRM_DEV_MODE (include/drm/drm_dev.h).
                perms: 0o620,
            },
            mtime_cycles: 0,
        }
    }

    /// DRM_IOCTL_* dispatch for `/dev/dri/card<N>`. Primary-node fd
    /// implies authenticated master per `DrmFileCtx::primary_master`
    /// so the modesetting ioctls are reachable.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        crate::drm_ioctl_bridge::dispatch_card(self.index, cmd, arg, /*render*/ false)
    }
}

// ── DriRenderFile ──────────────────────────────────────────────────────────

/// Placeholder file for `/dev/dri/renderD<N+128>` (render-only node).
///
/// Mesa opens this for compute and render without needing DRM master.
/// Mode `0o666` matches Linux's render-node permissions.
///
/// Linux ref: `drivers/gpu/drm/drm_drv.c::drm_dev_register` render branch.
#[derive(Debug)]
pub struct DriRenderFile {
    index: u32,
}

impl FileOps for DriRenderFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::InvalidData) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                // crw-rw-rw- 0o666: render node — accessible to all.
                // Linux: RENDER_DEV_MODE (include/drm/drm_dev.h).
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }

    /// DRM_IOCTL_* dispatch for `/dev/dri/renderD<N+128>`. Render-node
    /// fd implies `DrmFileCtx::render_client` so the dispatcher rejects
    /// modesetting ioctls with PermissionDenied (→ EACCES at the
    /// syscall layer).
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        crate::drm_ioctl_bridge::dispatch_card(self.index, cmd, arg, /*render*/ true)
    }
}

// ── DriDir ─────────────────────────────────────────────────────────────────

/// The `/dev/dri/` directory delegate.
///
/// `lookup("card0")` → `DriCardFile { index: 0 }`
/// `lookup("renderD128")` → `DriRenderFile { index: 0 }`
///
/// Linux ref: `drivers/gpu/drm/drm_drv.c::drm_dev_register` allocates
/// `DRM_MINOR_PRIMARY` at index N and `DRM_MINOR_RENDER` at N+128.
#[derive(Debug)]
pub struct DriDir;

impl DirOps for DriDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // card<N>
        if let Some(rest) = name.strip_prefix("card") {
            if let Ok(idx) = rest.parse::<u32>() {
                // Only expose registered cards.
                if (idx as usize) < crate::drm_registry::count() {
                    return Some(Arc::new(DriCardFile { index: idx }));
                }
            }
        }
        // renderD<N+128>
        if let Some(rest) = name.strip_prefix("renderD") {
            if let Ok(render_idx) = rest.parse::<u32>() {
                if render_idx >= 128 {
                    let idx = render_idx - 128;
                    if (idx as usize) < crate::drm_registry::count() {
                        return Some(Arc::new(DriRenderFile { index: idx }));
                    }
                }
            }
        }
        None
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // `iter` only works with `&'static str` names; use `enumerate`
        // for dynamic entries. Return empty iterator here.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let count = crate::drm_registry::count();
        let mut all: Vec<(String, FileType)> = Vec::with_capacity(count * 2);
        for idx in 0..count as u32 {
            all.push((format!("card{}", idx), FileType::Special));
            all.push((format!("renderD{}", idx + 128), FileType::Special));
        }
        all.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        let v = self.enumerate(cursor, max);
        Box::pin(async move { Ok(v) })
    }
}

// ── BochsCard ─────────────────────────────────────────────────────────────

/// `DrmCard` implementation for the bochs-display driver.
///
/// Populated from `narf_drivers_graphics::bochs` at probe success.
#[derive(Debug)]
pub struct BochsCard {
    pub name_str: String,
}

impl BochsCard {
    pub fn new(card_name: String) -> Self {
        BochsCard {
            name_str: card_name,
        }
    }
}

impl crate::drm_registry::DrmCard for BochsCard {
    fn name(&self) -> &str {
        &self.name_str
    }
    fn driver(&self) -> &str {
        "bochs"
    }
    fn vendor_id(&self) -> u16 {
        0x1234
    }
    fn device_id(&self) -> u16 {
        0x1111
    }
    fn subsystem_vendor(&self) -> u16 {
        // QEMU bochs-display: Red Hat, Inc. PCI subsystem vendor.
        // cfg+0x2C = 0x1AF4 on all QEMU bochs-display instances.
        0x1AF4
    }
    fn subsystem_device(&self) -> u16 {
        // QEMU bochs-display subsystem device ID.
        // cfg+0x2E = 0x1100 on all QEMU bochs-display instances.
        0x1100
    }
    fn vbios_version(&self) -> Option<&str> {
        None
    }
    fn gpu_busy_percent(&self) -> Option<u32> {
        None
    }
    fn power_state(&self) -> &str {
        "D0"
    }
}

// ── AmdgpuCard ────────────────────────────────────────────────────────────

/// `DrmCard` implementation for the AMDGPU driver.
///
/// Populated from `amdgpu::probe` at probe success.
#[derive(Debug)]
pub struct AmdgpuCard {
    pub name_str: String,
    pub vid: u16,
    pub did: u16,
    pub subsystem_vid: u16,
    pub subsystem_did: u16,
    pub vbios_ver: Option<String>,
}

impl AmdgpuCard {
    pub fn new(
        card_name: String,
        vid: u16,
        did: u16,
        subsystem_vid: u16,
        subsystem_did: u16,
        vbios_ver: Option<String>,
    ) -> Self {
        AmdgpuCard {
            name_str: card_name,
            vid,
            did,
            subsystem_vid,
            subsystem_did,
            vbios_ver,
        }
    }
}

impl crate::drm_registry::DrmCard for AmdgpuCard {
    fn name(&self) -> &str {
        &self.name_str
    }
    fn driver(&self) -> &str {
        "amdgpu"
    }
    fn vendor_id(&self) -> u16 {
        self.vid
    }
    fn device_id(&self) -> u16 {
        self.did
    }
    fn subsystem_vendor(&self) -> u16 {
        self.subsystem_vid
    }
    fn subsystem_device(&self) -> u16 {
        self.subsystem_did
    }
    fn vbios_version(&self) -> Option<&str> {
        self.vbios_ver.as_deref()
    }
    fn gpu_busy_percent(&self) -> Option<u32> {
        // Live measurement requires SMU telemetry — deferred.
        Some(0)
    }
    fn power_state(&self) -> &str {
        "D0"
    }
}

// ── Installation helper ────────────────────────────────────────────────────

/// Install the DRI directory delegate into devfs.
///
/// Called once from the GPU driver initcall so `/dev/dri/` becomes
/// accessible after probe.
///
/// Linux ref: `drm_dev_register` (drivers/gpu/drm/drm_drv.c).
pub fn install_dri_dir() {
    narf_filesystem::devfs::register_dri_dir(Arc::new(DriDir));
}
// ── IntelGpuCard ──────────────────────────────────────────────────────────

/// `DrmCard` implementation for the intel-gpu driver.
///
/// Populated from `intel_gpu::probe` at probe success.
#[derive(Debug)]
pub struct IntelGpuCard {
    pub name_str: String,
    pub vid: u16,
    pub did: u16,
    pub subsystem_vid: u16,
    pub subsystem_did: u16,
}

impl IntelGpuCard {
    pub fn new(
        card_name: String,
        vid: u16,
        did: u16,
        subsystem_vid: u16,
        subsystem_did: u16,
    ) -> Self {
        IntelGpuCard {
            name_str: card_name,
            vid,
            did,
            subsystem_vid,
            subsystem_did,
        }
    }
}

impl crate::drm_registry::DrmCard for IntelGpuCard {
    fn name(&self) -> &str {
        &self.name_str
    }
    fn driver(&self) -> &str {
        "intel-gpu"
    }
    fn vendor_id(&self) -> u16 {
        self.vid
    }
    fn device_id(&self) -> u16 {
        self.did
    }
    fn subsystem_vendor(&self) -> u16 {
        self.subsystem_vid
    }
    fn subsystem_device(&self) -> u16 {
        self.subsystem_did
    }
    fn vbios_version(&self) -> Option<&str> {
        None
    }
    fn gpu_busy_percent(&self) -> Option<u32> {
        None
    }
    fn power_state(&self) -> &str {
        "D0"
    }
}
