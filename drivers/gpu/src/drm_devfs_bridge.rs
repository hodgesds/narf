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

use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN,
};

/// `st_rdev` for `/dev/dri/card<N>` — `DRM_MAJOR`(226):minor(`index`).
/// dev_t = `(major << 8) | minor` for this small-number range.
///
/// Load-bearing: logind's `TakeDevice` (and `udevadm --name`, and libdrm's
/// device matching) resolve a node via `sd_device_new_from_devnum` on the
/// node's `st_rdev`. A 0 rdev makes that lookup fail — `TakeDevice` returns
/// ENODEV, so a session compositor (kwin/weston) can never obtain the GPU fd.
pub(crate) fn card_rdev(index: u32) -> u64 {
    (226u64 << 8) | index as u64
}

/// `st_rdev` for `/dev/dri/renderD<N+128>` — minor `128 + index`.
pub(crate) fn render_rdev(index: u32) -> u64 {
    (226u64 << 8) | (128 + index as u64)
}

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

/// Number of live `DriCardFile` (DRM master node) handles. When it falls
/// back to zero — the last compositor's `card<N>` fd closed (typically at
/// process exit) — we hand the framebuffer back to the kernel console so
/// post-compositor kernel logs are visible again.
static LIVE_CARD_FILES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

impl DriCardFile {
    fn new(index: u32) -> Self {
        LIVE_CARD_FILES.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        DriCardFile { index }
    }
}

impl Drop for DriCardFile {
    fn drop(&mut self) {
        // Last master node closed → release the framebuffer back to the
        // kernel console (no-op if a DRM client never took it over).
        if LIVE_CARD_FILES.fetch_sub(1, core::sync::atomic::Ordering::AcqRel) == 1 {
            narf_console::fb_release_from_user();
        }
    }
}

impl FileOps for DriCardFile {
    /// Drain one pending DRM event (`drm_event_vblank`) into `buf`. The
    /// compositor render loop poll/select()s the fd then read()s the
    /// flip-complete event here. Returns 0 when no event is queued.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let index = self.index;
        Box::pin(async move {
            if let Some(ms) = crate::drm_registry::mode_state(index) {
                let mut card = ms.lock();
                if let Some(ev) = card.events.pop_front() {
                    let n = ev.len().min(buf.len());
                    buf[..n].copy_from_slice(&ev[..n]);
                    return Ok(n);
                }
            }
            Ok(0)
        })
    }

    /// `POLL_IN` while flip-complete events are queued, so `select`/`poll`
    /// on the DRM fd wakes the render loop.
    fn poll_readiness(&self) -> u32 {
        match crate::drm_registry::mode_state(self.index) {
            Some(ms) if !ms.lock().events.is_empty() => POLL_IN,
            _ => 0,
        }
    }

    /// The DRM card fd is a PARKABLE readiness source: a poll/epoll set
    /// containing it may block instead of busy-spinning. Without this the
    /// fd defaulted "silent" (readiness_notifies == false), which poisons
    /// the whole poll set — a compositor's main-loop poll over {wayland,
    /// DRM, input, dbus} then busy-polls at 100% CPU and, under the
    /// cooperative own-stack scheduler, starves every same-CPU peer (the
    /// exact starvation that stalled kwin's launcher before plasmashell
    /// could paint; same class as the eventfd fix). Flip-complete events
    /// are queued synchronously by SETCRTC/PAGE_FLIP and read straight
    /// after the ioctl (not via a parked poll), and any parked poll self-
    /// heals within the ~10 ms backstop, so no explicit wake is required.
    fn readiness_notifies(&self) -> bool {
        true
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

    /// `st_rdev` = DRM_MAJOR(226):minor(card index). See [`card_rdev`].
    fn rdev(&self) -> u64 {
        card_rdev(self.index)
    }

    /// DRM_IOCTL_* dispatch for `/dev/dri/card<N>`. Primary-node fd
    /// implies authenticated master per `DrmFileCtx::primary_master`
    /// so the modesetting ioctls are reachable.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        crate::drm_ioctl_bridge::dispatch_card(self.index, cmd, arg, /*render*/ false)
    }

    /// DRM dumb-buffer mmap: resolve a MAP_DUMB fake offset to the
    /// physical frames of the dumb buffer. Called by `sys_mmap` for
    /// MAP_SHARED on this fd.
    ///
    /// `offset` is the value returned by DRM_IOCTL_MODE_MAP_DUMB
    /// (`gem_handle << 12`). `len` must be ≤ the buffer's allocation.
    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        crate::drm_ioctl_bridge::dispatch_mmap(self.index, offset, len)
    }

    /// This IS a DRM master card node — hand back its index so
    /// `sys_ioctl(DRM_IOCTL_PRIME_HANDLE_TO_FD)` can export a GEM handle
    /// on this card as a fresh dma-buf fd.
    fn as_drm_card_index(&self) -> Option<u32> {
        Some(self.index)
    }
}

// ── PrimeDmaBufFile ─────────────────────────────────────────────────────────

/// The fd handed back by `DRM_IOCTL_PRIME_HANDLE_TO_FD` — a dma-buf
/// exporting a dumb buffer's physical frames. Mesa GBM's `gbm_bo_get_fd`
/// needs this fd to CPU-mmap the buffer it renders into (the kwin QPainter
/// swapchain). The frames are the SAME contiguous pages the GEM handle's
/// dumb backing owns, so a client's writes land exactly where the scanout
/// blit (SETCRTC / page-flip) reads from.
///
/// The buffer memory stays owned by the Card's `DumbBacking` (freed on GEM
/// close); this file only borrows the frames for mmap, so Drop is a no-op.
#[derive(Debug)]
pub struct PrimeDmaBufFile {
    /// Physical base of the contiguous dumb allocation.
    phys: u64,
    /// Byte length (page-rounded).
    byte_len: usize,
    /// The GEM handle this dma-buf was exported from. `PRIME_FD_TO_HANDLE`
    /// re-imports the fd back to this same handle (single-card round-trip:
    /// a compositor exports its render buffer, then imports it to build a
    /// KMS framebuffer to scan out).
    gem_handle: u32,
}

impl FileOps for PrimeDmaBufFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // A dma-buf is not byte-readable; it is mmap'd. read() → 0 (EOF).
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::InvalidData) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.byte_len as u64,
            blocks: (self.byte_len as u64).div_ceil(512),
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    /// Alias the dumb buffer's contiguous frames into the caller's AS.
    /// `sys_mmap(MAP_SHARED)` calls this; the compositor then CPU-draws
    /// straight into the scanout-source frames. `offset` is a byte offset
    /// into the buffer (0 for a whole-buffer map, as gbm/kwin issue).
    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        if offset as usize + len > self.byte_len || offset % 4096 != 0 {
            return Err(FsError::InvalidData);
        }
        let pages = len / 4096;
        let base = self.phys + offset;
        Ok((0..pages as u64).map(|i| base + i * 4096).collect())
    }

    /// This fd is an exported DRM buffer — hand back the GEM handle it
    /// wraps so `PRIME_FD_TO_HANDLE` can re-import it.
    fn as_prime_gem_handle(&self) -> Option<u32> {
        Some(self.gem_handle)
    }
}

/// Export the dumb buffer named by `gem_handle` on card `card_index` as an
/// mmap-able dma-buf `FileOps` (the `DRM_IOCTL_PRIME_HANDLE_TO_FD` export
/// side). Registered as `narf_filesystem`'s DRM PRIME hook so the syscall
/// layer — which owns the fd table — can install it as a real fd. Returns
/// `None` if the handle has no dumb backing on that card.
pub fn prime_export_fileops(card_index: u32, gem_handle: u32) -> Option<Arc<dyn FileOps>> {
    let ms = crate::drm_registry::mode_state(card_index)?;
    let card = ms.lock();
    let backing = card.dumb_backing(gem_handle)?;
    Some(Arc::new(PrimeDmaBufFile {
        phys: backing.phys,
        byte_len: backing.byte_len,
        gem_handle,
    }))
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

    /// `st_rdev` = DRM_MAJOR(226):minor(128 + card index). See [`render_rdev`].
    fn rdev(&self) -> u64 {
        render_rdev(self.index)
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
                    return Some(Arc::new(DriCardFile::new(idx)));
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
