//! Bridge between the generic `FileOps::ioctl` syscall path and the
//! DRM-specific dispatcher in [`crate::drm::ioctl`].
//!
//! `sys_ioctl` hands us `(cmd, user_arg_ptr)`. We:
//!
//! 1. Strip the lower 8 bits of `cmd` to get the DRM sub-command number.
//! 2. Copy the inout struct from user-space into a kernel-owned buffer.
//! 3. Build a [`DrmFileCtx`] for the calling fd (primary vs render).
//! 4. Call [`crate::drm::ioctl::dispatch`] with the kernel buffer.
//! 5. Serialise the response back into the user buffer.
//!
//! Per-card mode-setting state is looked up via
//! [`crate::drm_registry::mode_state`]. Cards registered without a
//! `drm::card::Card` state attach return `ENOTSUP` for every DRM ioctl.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_ioctl.c::drm_ioctl` — top-level dispatcher
//!   that this module mirrors.
//! - `include/uapi/drm/drm.h` — UAPI struct definitions copied in
//!   [`crate::drm_uapi`].

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use narf_filesystem::FsError;
use narf_io::DmaBuffer;

use crate::drm::ioctl::{dispatch, DrmIoctlError, DrmIoctlResult, IoctlCmd};
use crate::drm::render_node::DrmFileCtx;
use crate::drm_uapi::{
    self, DrmModeAtomicUapi, DrmModeCardResUapi, DrmModeCreateDumbUapi, DrmModeCrtcUapi,
    DrmModeDestroyDumbUapi, DrmModeMapDumbUapi, DrmModePageFlipUapi, DrmVersionUapi,
};

// ── Copy helpers ──────────────────────────────────────────────────────
//
// These mirror the SMAP-bracketed helpers in `narf-userspace::handlers`
// but stay local so the GPU crate doesn't take a dependency on the
// syscall layer. The kernel-test smokes pass kernel-owned pointers
// here; production traffic goes through validated user ranges already
// gated by `sys_ioctl`.

/// Maximum per-ioctl payload size (1 MiB). Hard cap so a malicious
/// `count_objs` field can't be used to force a huge allocation.
const IOCTL_MAX_BUF: usize = 1024 * 1024;

/// Maximum opaque VirGL command stream accepted from one EXECBUFFER ioctl.
///
/// The control request staging buffer in `narf-drivers-virtio` is 64 KiB and
/// also carries the VirtIO-GPU submit header. Mesa's classic-VirGL screen
/// initialization sends streams larger than one page (4,136, 9,504, and
/// 18,412 bytes have all been observed), before it creates its first resource.
pub(crate) const VIRTGPU_EXECBUFFER_MAX_BYTES: usize =
    64 * 1024 - narf_drivers_virtio::gpu_pci::cmd::SUBMIT_3D_PREFIX_LEN;

/// Keep one userspace allocation bounded while allowing it to span the I/O
/// layer's 4 MiB maximum coherent segment. This was the existing intended
/// per-resource limit; the old single-segment implementation accidentally
/// made the effective limit 4 MiB instead.
const VIRTGPU_RESOURCE_MAX_BYTES: usize = 16 * 1024 * 1024;
const VIRTGPU_DMA_SEGMENT_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Per-open DRM client capability state (`struct drm_file` in Linux).
///
/// Atomic and cursor-hotspot negotiation is ordered: Linux returns `EINVAL`
/// for HOTSPOT unless that same file has already enabled ATOMIC.  Keep this
/// on the open file rather than the card so independent clients cannot grant
/// capabilities to one another.
#[derive(Debug)]
pub struct DrmClientCaps {
    atomic: AtomicBool,
}

impl DrmClientCaps {
    pub const fn new() -> Self {
        Self {
            atomic: AtomicBool::new(false),
        }
    }

    fn atomic(&self) -> bool {
        self.atomic.load(Ordering::Acquire)
    }

    fn set_atomic(&self, enabled: bool) {
        self.atomic.store(enabled, Ordering::Release);
    }
}

impl Default for DrmClientCaps {
    fn default() -> Self {
        Self::new()
    }
}

struct GuestBacking {
    segments: Vec<DmaBuffer>,
    /// Linux reports the GEM object's requested (page-rounded) size, not the
    /// sum of allocator power-of-two padding across its scatterlist entries.
    size: usize,
}

impl GuestBacking {
    fn entries(&self) -> Vec<narf_drivers_virtio::gpu_pci::cmd::MemEntry> {
        self.segments
            .iter()
            .map(|segment| narf_drivers_virtio::gpu_pci::cmd::MemEntry {
                addr: segment.dma_addr().raw(),
                length: segment.len() as u32,
            })
            .collect()
    }

    fn page_phys(&self, mut page: usize) -> u64 {
        for segment in &self.segments {
            let pages = segment.len() / 4096;
            if page < pages {
                return segment.dma_addr().raw() + page as u64 * 4096;
            }
            page -= pages;
        }
        0
    }
}

fn alloc_guest_backing(size: usize) -> Result<GuestBacking, FsError> {
    if size == 0 || size > VIRTGPU_RESOURCE_MAX_BYTES {
        return Err(FsError::OutOfMemory);
    }
    let size = size.div_ceil(4096) * 4096;
    let mut remaining = size;
    let mut segments = Vec::new();
    while remaining != 0 {
        let chunk = remaining.min(VIRTGPU_DMA_SEGMENT_MAX_BYTES);
        let segment = narf_io::alloc_coherent(chunk, narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| FsError::OutOfMemory)?;
        remaining = remaining.saturating_sub(segment.len());
        segments.push(segment);
    }
    Ok(GuestBacking { segments, size })
}

/// Where a resource's mappable memory lives.
enum ResourceBacking {
    /// Guest-physical coherent DMA pages (classic 3D resources and guest
    /// blobs). The host attaches these pages as the resource backing.
    Guest(GuestBacking),
    /// A slice of the host-visible PCI window (host3d mappable blobs). The
    /// host owns the memory; the guest maps `[window_phys+offset, +size)`.
    HostVisible {
        window_phys: u64,
        offset: u64,
        size: u64,
    },
    /// A host-only blob (e.g. non-mappable VRAM): no guest pages, no CPU
    /// mapping. The GPU references it by resource id; the guest never mmaps it.
    HostOnly { size: u64 },
}

/// One render-node object's private GEM-like resource. It is deliberately
/// owned by an open file, not the global DRM card: a process cannot submit or
/// map another process's handle merely by guessing its integer value.
pub(crate) struct VirtGpuResource {
    pub(crate) resource_id: u32,
    backing: Option<ResourceBacking>,
    /// Linux exposes the blob memory class through RESOURCE_INFO. `None`
    /// identifies a classic RESOURCE_CREATE object.
    blob_mem: Option<u32>,
    /// Host3D blobs accept explicit transfer strides; classic resources do
    /// not, and pure guest blobs reject 3D transfers entirely.
    host3d_blob: bool,
    /// False only for synthetic lifecycle tests that never created a host
    /// resource and therefore require no RESOURCE_UNREF command.
    host_owned: bool,
    /// Fence of the last EXECBUFFER that referenced this BO. VIRTGPU_WAIT
    /// consults it the way Linux waits on the GEM object's reservation.
    pub(crate) last_fence: narf_lib::sync::IrqSafeSpinLock<Option<Arc<VirtGpuFence>>>,
}

/// One driver-level fence shared by BO reservations, sync files, and binary
/// syncobjs. The transport owns the completion bit; this wrapper supplies the
/// two subsystem traits without making VFS depend on the VirtIO driver.
#[derive(Debug)]
pub(crate) struct VirtGpuFence {
    transport: Arc<narf_drivers_virtio::gpu_pci::SubmittedFence>,
    context: u64,
}

impl VirtGpuFence {
    fn new(
        transport: Arc<narf_drivers_virtio::gpu_pci::SubmittedFence>,
        context: u64,
    ) -> Arc<Self> {
        Arc::new(Self { transport, context })
    }

    fn is_device_signalled(&self) -> bool {
        narf_drivers_virtio::gpu_pci::probed_device()
            .map(|dev| dev.fence_signalled(&self.transport))
            // A removed device cannot make further progress. Treat its
            // abandoned fences as done so pollers do not wedge forever.
            .unwrap_or(true)
    }

    fn wait_device(&self, timeout_ms: u64) -> bool {
        narf_drivers_virtio::gpu_pci::probed_device()
            .map(|dev| dev.wait_fence(&self.transport, timeout_ms))
            .unwrap_or(true)
    }
}

impl crate::drm::syncobj::DmaFence for VirtGpuFence {
    fn is_signalled(&self) -> bool {
        self.is_device_signalled()
    }

    fn wait(&self, timeout_ns: u64) -> bool {
        if timeout_ns == 0 {
            return self.is_device_signalled();
        }
        self.wait_device(timeout_ns.saturating_add(999_999) / 1_000_000)
    }

    fn signal(&self) {
        self.transport.signal();
    }

    fn context(&self) -> Option<u64> {
        Some(self.context)
    }
}

impl narf_filesystem::DrmFence for VirtGpuFence {
    fn is_signalled(&self) -> bool {
        self.is_device_signalled()
    }

    fn wait(&self, timeout_ms: u64) -> bool {
        self.wait_device(timeout_ms)
    }

    fn context(&self) -> Option<u64> {
        Some(self.context)
    }
}

impl core::fmt::Debug for VirtGpuResource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtGpuResource")
            .field("resource_id", &self.resource_id)
            .field("len", &self.len())
            .field("blob_mem", &self.blob_mem)
            .finish_non_exhaustive()
    }
}

impl Drop for VirtGpuResource {
    fn drop(&mut self) {
        let Some(backing) = self.backing.take() else {
            return;
        };
        if !self.host_owned {
            drop(backing);
            return;
        }
        let released = narf_drivers_virtio::gpu_pci::probed_device()
            .map(|dev| dev.unref_virgl_resource(self.resource_id).is_ok())
            .unwrap_or(false);
        if released {
            drop(backing);
        } else {
            // The host may still DMA through its resource backing. Leaking is
            // bounded to the failed object and is safer than recycling pages.
            core::mem::forget(backing);
        }
    }
}

impl VirtGpuResource {
    /// Mappable byte length of the resource's backing.
    pub(crate) fn len(&self) -> usize {
        match self.backing.as_ref().expect("live VirtGpuResource backing") {
            ResourceBacking::Guest(backing) => backing.size,
            ResourceBacking::HostVisible { size, .. } => *size as usize,
            ResourceBacking::HostOnly { size } => *size as usize,
        }
    }

    /// Whether this resource is CPU-mmappable by the guest.
    pub(crate) fn is_cpu_mappable(&self) -> bool {
        !matches!(
            self.backing.as_ref(),
            Some(ResourceBacking::HostOnly { .. })
        )
    }

    fn is_guest_only_blob(&self) -> bool {
        self.blob_mem.is_some() && !self.host3d_blob
    }

    /// Guest-physical address of the `page`-th 4 KiB page of the backing.
    /// Only valid for CPU-mappable backings (`is_cpu_mappable`).
    pub(crate) fn page_phys(&self, page: usize) -> u64 {
        match self.backing.as_ref().expect("live VirtGpuResource backing") {
            ResourceBacking::Guest(backing) => backing.page_phys(page),
            ResourceBacking::HostVisible {
                window_phys,
                offset,
                ..
            } => window_phys + offset + page as u64 * 4096,
            ResourceBacking::HostOnly { .. } => 0,
        }
    }
}

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
pub(crate) fn test_virtgpu_resource(resource_id: u32, size: usize) -> Arc<VirtGpuResource> {
    Arc::new(VirtGpuResource {
        resource_id,
        backing: Some(ResourceBacking::HostOnly { size: size as u64 }),
        blob_mem: None,
        host3d_blob: false,
        host_owned: false,
        last_fence: narf_lib::sync::IrqSafeSpinLock::new(None),
    })
}

struct VirtGpuHandle {
    handle: u32,
    resource: Arc<VirtGpuResource>,
    /// Classic resources and PRIME imports were explicitly CTX_ATTACHed;
    /// blob creation associates ownership in its header and is not detached
    /// through CTX_DETACH on handle close.
    attached: bool,
}

/// Per-open state for `/dev/dri/renderD<N+128>` on the virtio_gpu card.
///
/// The state belongs to `DriRenderFile`; it is never shared across opens.
/// All mutable state is behind a lock because ioctl and mmap can arrive from
/// different threads sharing the same fd.
pub struct VirtGpuRenderState {
    resources: narf_lib::sync::IrqSafeSpinLock<Vec<VirtGpuHandle>>,
    next_handle: AtomicU32,
    /// This open's virtio-gpu render context id (unique per open).
    ctx_id: u32,
    /// Capset this open's context binds (0 = classic VirGL; 6 = DRM native).
    /// Set by CONTEXT_INIT before the context is created.
    context_capset: AtomicU32,
    /// Ring configuration supplied by CONTEXT_INIT. Classic VirGL normally
    /// leaves both zero; EXECBUFFER ring selection is valid only when the
    /// selected bit is within this configured set, matching Linux.
    context_num_rings: AtomicU32,
    context_ring_mask: AtomicU64,
    context_explicit_debug_name: AtomicBool,
    /// Whether this open's context has been created on the device yet.
    context_ready: AtomicBool,
    /// Per-open DRM syncobj table (like Linux's per-DRM-file syncobj IDR). The
    /// DRM native context creates syncobjs during device init and rendering.
    syncobjs: narf_lib::sync::IrqSafeSpinLock<crate::drm::syncobj::SyncObjTable>,
    /// Successful FENCE_FD_OUT submissions awaiting fd installation, keyed by
    /// the submitting task. The syscall layer consumes its own entry right
    /// after dispatch, so concurrent ioctls sharing one DRM fd cannot attach
    /// one another's sync_file fence.
    pending_execbuf_fences: narf_lib::sync::IrqSafeSpinLock<Vec<(u64, Arc<VirtGpuFence>)>>,
}

impl core::fmt::Debug for VirtGpuRenderState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtGpuRenderState").finish_non_exhaustive()
    }
}

impl VirtGpuRenderState {
    pub fn new() -> Self {
        Self {
            resources: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
            next_handle: AtomicU32::new(1),
            ctx_id: NEXT_VIRTGPU_CTX_ID.fetch_add(1, Ordering::Relaxed),
            context_capset: AtomicU32::new(0),
            context_num_rings: AtomicU32::new(0),
            context_ring_mask: AtomicU64::new(0),
            context_explicit_debug_name: AtomicBool::new(false),
            context_ready: AtomicBool::new(false),
            syncobjs: narf_lib::sync::IrqSafeSpinLock::new(crate::drm::syncobj::SyncObjTable::new()),
            pending_execbuf_fences: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
        }
    }

    /// Consume the calling task's FENCE_FD_OUT submission fence.
    pub(crate) fn take_execbuf_fence(&self) -> Option<Arc<dyn narf_filesystem::DrmFence>> {
        let task = narf_scheduler::current_task_id().raw();
        let mut pending = self.pending_execbuf_fences.lock();
        let index = pending.iter().rposition(|(owner, _)| *owner == task)?;
        let (_, fence) = pending.swap_remove(index);
        Some(fence)
    }

    pub(crate) fn execbuf_context(&self, ring_idx: u32) -> u64 {
        (u64::from(self.ctx_id) << 32) | u64::from(ring_idx)
    }

    /// Ensure this open's render context exists on the device, creating it once
    /// (bound to the capset chosen by CONTEXT_INIT, or classic VirGL by
    /// default). Idempotent per open.
    fn ensure_context(
        &self,
        dev: &narf_drivers_virtio::gpu_pci::VirtioGpuPci,
    ) -> Result<(), FsError> {
        if self.context_ready.load(Ordering::Acquire) {
            return Ok(());
        }
        let capset = self.context_capset.load(Ordering::Acquire);
        dev.create_context(self.ctx_id, capset)
            .map_err(map_gpu_transport_error)?;
        self.context_ready.store(true, Ordering::Release);
        Ok(())
    }

    fn find(&self, handle: u32) -> Option<Arc<VirtGpuResource>> {
        self.resources
            .lock()
            .iter()
            .find(|binding| binding.handle == handle)
            .map(|binding| Arc::clone(&binding.resource))
    }

    pub(crate) fn allocate_handle(&self) -> u32 {
        loop {
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed).max(1);
            if self.find(handle).is_none() {
                return handle;
            }
        }
    }

    pub(crate) fn export_resource(&self, handle: u32) -> Option<Arc<VirtGpuResource>> {
        self.find(handle)
    }

    pub(crate) fn handle_for_resource(&self, resource: &Arc<VirtGpuResource>) -> Option<u32> {
        self.resources
            .lock()
            .iter()
            .find(|binding| Arc::ptr_eq(&binding.resource, resource))
            .map(|binding| binding.handle)
    }

    fn rename_handle(&self, old_handle: u32, new_handle: u32) -> Result<(), FsError> {
        let mut resources = self.resources.lock();
        if resources.iter().any(|binding| binding.handle == new_handle) {
            return Err(FsError::AlreadyExists);
        }
        let binding = resources
            .iter_mut()
            .find(|binding| binding.handle == old_handle)
            .ok_or(FsError::NotFound)?;
        binding.handle = new_handle;
        Ok(())
    }

    fn bind(&self, handle: u32, resource: Arc<VirtGpuResource>, attached: bool) {
        self.resources.lock().push(VirtGpuHandle {
            handle,
            resource,
            attached,
        });
    }

    pub(crate) fn import_resource(
        &self,
        handle: u32,
        resource: Arc<VirtGpuResource>,
    ) -> Result<(), FsError> {
        if self.find(handle).is_some() {
            return Err(FsError::AlreadyExists);
        }
        let dev = narf_drivers_virtio::gpu_pci::probed_device().ok_or(FsError::InvalidData)?;
        self.ensure_context(dev)?;
        dev.attach_virgl_resource(self.ctx_id, resource.resource_id)
            .map_err(map_gpu_transport_error)?;
        self.bind(handle, resource, true);
        Ok(())
    }

    pub(crate) fn import_resource_new_handle(
        &self,
        resource: Arc<VirtGpuResource>,
    ) -> Result<u32, FsError> {
        if let Some(binding) = self
            .resources
            .lock()
            .iter()
            .find(|binding| Arc::ptr_eq(&binding.resource, &resource))
        {
            return Ok(binding.handle);
        }
        let handle = self.allocate_handle();
        self.import_resource(handle, resource)?;
        Ok(handle)
    }

    /// Test/small-resource helper retaining the historical single-buffer path.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn insert(&self, handle: u32, resource_id: u32, buffer: DmaBuffer) {
        let size = buffer.len();
        self.bind(
            handle,
            Arc::new(VirtGpuResource {
                resource_id,
                backing: Some(ResourceBacking::Guest(GuestBacking {
                    segments: vec![buffer],
                    size,
                })),
                blob_mem: None,
                host3d_blob: false,
                host_owned: false,
                last_fence: narf_lib::sync::IrqSafeSpinLock::new(None),
            }),
            true,
        );
    }

    fn insert_backing(&self, handle: u32, resource_id: u32, backing: GuestBacking) {
        self.bind(
            handle,
            Arc::new(VirtGpuResource {
                resource_id,
                backing: Some(ResourceBacking::Guest(backing)),
                blob_mem: None,
                host3d_blob: false,
                host_owned: true,
                last_fence: narf_lib::sync::IrqSafeSpinLock::new(None),
            }),
            true,
        );
    }

    fn insert_guest_blob(
        &self,
        handle: u32,
        resource_id: u32,
        backing: GuestBacking,
        blob_mem: u32,
        host3d_blob: bool,
    ) {
        self.bind(
            handle,
            Arc::new(VirtGpuResource {
                resource_id,
                backing: Some(ResourceBacking::Guest(backing)),
                blob_mem: Some(blob_mem),
                host3d_blob,
                host_owned: true,
                last_fence: narf_lib::sync::IrqSafeSpinLock::new(None),
            }),
            false,
        );
    }

    /// Record a host3d mappable blob backed by a slice of the host-visible
    /// PCI window (no guest DMA pages).
    pub(crate) fn insert_host_visible(
        &self,
        handle: u32,
        resource_id: u32,
        window_phys: u64,
        offset: u64,
        size: u64,
    ) {
        self.bind(
            handle,
            Arc::new(VirtGpuResource {
                resource_id,
                backing: Some(ResourceBacking::HostVisible {
                    window_phys,
                    offset,
                    size,
                }),
                blob_mem: Some(narf_drivers_virtio::gpu_pci::BLOB_MEM_HOST3D),
                host3d_blob: true,
                host_owned: true,
                last_fence: narf_lib::sync::IrqSafeSpinLock::new(None),
            }),
            false,
        );
    }

    /// Record a host-only blob (e.g. non-mappable VRAM) — no CPU mapping.
    pub(crate) fn insert_host_only(&self, handle: u32, resource_id: u32, size: u64) {
        self.bind(
            handle,
            Arc::new(VirtGpuResource {
                resource_id,
                backing: Some(ResourceBacking::HostOnly { size }),
                blob_mem: Some(narf_drivers_virtio::gpu_pci::BLOB_MEM_HOST3D),
                host3d_blob: true,
                host_owned: true,
                last_fence: narf_lib::sync::IrqSafeSpinLock::new(None),
            }),
            false,
        );
    }

    pub(crate) fn take(&self, handle: u32) -> Option<(Arc<VirtGpuResource>, bool)> {
        let mut resources = self.resources.lock();
        let pos = resources
            .iter()
            .position(|binding| binding.handle == handle)?;
        let binding = resources.swap_remove(pos);
        Some((binding.resource, binding.attached))
    }

    pub(crate) fn mapping_resource(&self, offset: u64, len: usize) -> Option<Arc<VirtGpuResource>> {
        if offset & 0xfff != 0 || len == 0 || len & 0xfff != 0 {
            return None;
        }
        let resource = self.find((offset >> 12) as u32)?;
        (len <= resource.len()).then_some(resource)
    }

    /// This open's render context id (for teardown detach/unref).
    pub(crate) fn ctx_id(&self) -> u32 {
        self.ctx_id
    }

    pub(crate) fn drain_resources(&self) -> Vec<(u32, Arc<VirtGpuResource>, bool)> {
        core::mem::take(&mut *self.resources.lock())
            .into_iter()
            .map(|binding| (binding.handle, binding.resource, binding.attached))
            .collect()
    }
}

impl Default for VirtGpuRenderState {
    fn default() -> Self {
        Self::new()
    }
}

static NEXT_VIRTGPU_RESOURCE_ID: AtomicU32 = AtomicU32::new(2);

/// Per-open render context ids. Each `/dev/dri/renderD*` open gets a distinct
/// virtio-gpu context (like Linux's per-DRM-file `ctx_id`): the DRM native
/// context allocates one host shmem per context, so a shared context id makes
/// the second client's shmem blob fail ("there can be only one"). Context 0 is
/// reserved (no context / pure guest blobs); real contexts start at 1.
static NEXT_VIRTGPU_CTX_ID: AtomicU32 = AtomicU32::new(1);

fn map_gpu_transport_error(error: narf_drivers_virtio::pci::VirtioPciError) -> FsError {
    match error {
        narf_drivers_virtio::pci::VirtioPciError::CompletionTimeout => FsError::Busy,
        _ => FsError::InvalidData,
    }
}

fn read_uapi<T: Copy>(arg: usize) -> Result<T, FsError> {
    // SAFETY: the ioctl caller supplied `arg`; copy_in constrains the exact
    // fixed UAPI size and opens an SMAP window for a user address.
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<T>())? };
    // SAFETY: bytes has exactly one T's byte length; read_unaligned accepts
    // the Vec<u8> alignment and T is Copy plain UAPI data at every callsite.
    Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

fn write_uapi<T: Copy>(arg: usize, value: T) -> Result<(), FsError> {
    // SAFETY: Copy UAPI structs are byte-stable and have exactly the source
    // object size. The same ioctl arg was read/validated before this write.
    let bytes = unsafe {
        core::slice::from_raw_parts(&value as *const T as *const u8, core::mem::size_of::<T>())
    };
    // SAFETY: see copy_out's contract; size is the fixed UAPI struct length.
    unsafe { copy_out(arg, bytes) }
}

#[derive(Copy, Clone)]
pub(crate) struct ExecSyncobjDep {
    pub(crate) handle: u32,
    pub(crate) reset: bool,
}

/// Copy and validate one EXECBUFFER syncobj dependency array using Linux's
/// extensible-stride rule: each entry is zero-initialized and then the first
/// `min(stride, sizeof(entry))` bytes are copied from userspace.
pub(crate) fn read_exec_syncobjs(
    base: u64,
    count: u32,
    stride: u32,
    output: bool,
) -> Result<Vec<ExecSyncobjDep>, FsError> {
    const MAX_SYNCOBJS: u32 = 4096;
    const SYNCOBJ_RESET: u32 = 0x01;
    let entry_size = core::mem::size_of::<crate::drm_uapi::DrmVirtGpuExecBufferSyncobjUapi>();
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAX_SYNCOBJS || base == 0 || stride == 0 {
        return Err(FsError::InvalidData);
    }
    let copy_len = (stride as usize).min(entry_size);
    let mut deps = Vec::with_capacity(count as usize);
    for index in 0..count {
        let offset = u64::from(index)
            .checked_mul(u64::from(stride))
            .ok_or(FsError::InvalidData)?;
        let address = base.checked_add(offset).ok_or(FsError::InvalidData)?;
        let address = usize::try_from(address).map_err(|_| FsError::InvalidData)?;
        // Linux zero-fills the part omitted by a short extensible stride.
        let mut wire = [0u8; 16];
        // SAFETY: the user address and bounded byte count come from the UAPI;
        // copy_in range-checks and SMAP-brackets the read.
        let bytes = unsafe { copy_in(address, copy_len)? };
        wire[..copy_len].copy_from_slice(&bytes);
        let handle = u32::from_le_bytes(wire[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(wire[4..8].try_into().unwrap());
        let point = u64::from_le_bytes(wire[8..16].try_into().unwrap());
        // Timeline points are intentionally not advertised by NARF's binary
        // syncobj implementation. Output flags must be zero; input supports
        // only RESET, exactly like virtgpu_parse_{deps,post_deps}.
        if point != 0 || (output && flags != 0) || (!output && flags & !SYNCOBJ_RESET != 0) {
            return Err(FsError::InvalidData);
        }
        deps.push(ExecSyncobjDep {
            handle,
            reset: flags & SYNCOBJ_RESET != 0,
        });
    }
    Ok(deps)
}

pub(crate) fn sync_dependency_needs_wait(
    fence_context: Option<u64>,
    submission_context: u64,
) -> bool {
    fence_context != Some(submission_context)
}

/// `DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB` — allocate a guest-page-backed blob
/// resource. Used by the DRM native context (capset 6): guest Mesa allocates
/// its buffer objects as blobs. GUEST(1) and HOST3D_GUEST(3) are guest-backed
/// and fully handled here; HOST3D(2) is either host-visible and CPU-mappable or
/// host-only, according to its blob flags.
fn handle_resource_create_blob(arg: usize, state: &VirtGpuRenderState) -> Result<u64, FsError> {
    use crate::drm_uapi::DrmVirtGpuResourceCreateBlobUapi;
    use narf_drivers_virtio::gpu_pci::{BLOB_MEM_GUEST, BLOB_MEM_HOST3D, BLOB_MEM_HOST3D_GUEST};
    let mut req: DrmVirtGpuResourceCreateBlobUapi = read_uapi(arg)?;
    const BLOB_FLAG_USE_MAPPABLE: u32 = 0x0001;
    const BLOB_FLAG_USE_SHAREABLE: u32 = 0x0002;
    const BLOB_FLAG_USE_CROSS_DEVICE: u32 = 0x0004;
    const BLOB_FLAG_USE_MASK: u32 =
        BLOB_FLAG_USE_MAPPABLE | BLOB_FLAG_USE_SHAREABLE | BLOB_FLAG_USE_CROSS_DEVICE;

    let dev = narf_drivers_virtio::gpu_pci::probed_device().ok_or(FsError::InvalidData)?;
    if !dev.resource_blob_enabled()
        || req.size == 0
        || req.blob_flags & !BLOB_FLAG_USE_MASK != 0
        // RESOURCE_ASSIGN_UUID is not implemented or advertised by NARF.
        || req.blob_flags & BLOB_FLAG_USE_CROSS_DEVICE != 0
    {
        return Err(FsError::InvalidData);
    }
    let host3d_blob = matches!(req.blob_mem, BLOB_MEM_HOST3D | BLOB_MEM_HOST3D_GUEST);
    if !matches!(
        req.blob_mem,
        BLOB_MEM_GUEST | BLOB_MEM_HOST3D | BLOB_MEM_HOST3D_GUEST
    ) || (host3d_blob && !dev.virgl_enabled())
        || (!host3d_blob && (req.blob_id != 0 || req.cmd_size != 0))
        || (host3d_blob && req.cmd_size % 4 != 0)
    {
        return Err(FsError::InvalidData);
    }
    // Linux creates a context only when VirGL is active. Pure guest blobs do
    // not need one; HOST3D variants were feature-checked above.
    if dev.virgl_enabled() {
        state.ensure_context(dev)?;
    }
    // A host3d(_guest) blob may carry a ccmd describing the host object; Linux
    // submits it via SUBMIT_3D on the context before creating the resource
    // (verify_blob requires cmd_size dword-aligned).
    if req.cmd_size != 0 {
        // SAFETY: `req.cmd` is the user pointer libdrm passed; copy_in
        // SMAP-brackets the read and bounds cmd_size.
        let cmd_bytes = unsafe { copy_in(req.cmd as usize, req.cmd_size as usize)? };
        dev.submit_virgl(state.ctx_id, None, &cmd_bytes)
            .map_err(|_| FsError::InvalidData)?;
    }
    let handle = state.allocate_handle();
    let resource_id = NEXT_VIRTGPU_RESOURCE_ID.fetch_add(1, Ordering::Relaxed);
    match req.blob_mem {
        // Guest-page backed: allocate coherent DMA and attach it as the backing.
        BLOB_MEM_GUEST | BLOB_MEM_HOST3D_GUEST => {
            let size = req.size as usize;
            let backing = alloc_guest_backing(size)?;
            let entries = backing.entries();
            dev.create_blob_resource(
                state.ctx_id,
                resource_id,
                req.blob_mem,
                req.blob_flags,
                req.blob_id,
                req.size,
                &entries,
            )
            .map_err(|_| FsError::InvalidData)?;
            state.insert_guest_blob(
                handle,
                resource_id,
                backing,
                req.blob_mem,
                req.blob_mem == BLOB_MEM_HOST3D_GUEST,
            );
        }
        // Host-allocated (host3d). Create the host resource; only USE_MAPPABLE
        // blobs get a slot in the host-visible window + a RESOURCE_MAP_BLOB.
        // Non-mappable blobs (e.g. VRAM buffers, blob_flags=0) are host-only:
        // the GPU references them by resource id and they are never CPU-mapped —
        // trying to map one fails ("failed to map virgl resource").
        BLOB_MEM_HOST3D => {
            dev.create_blob_host3d(
                state.ctx_id,
                resource_id,
                req.blob_flags,
                req.blob_id,
                req.size,
            )
            .map_err(|_| FsError::InvalidData)?;
            if req.blob_flags & BLOB_FLAG_USE_MAPPABLE != 0 {
                let base = dev.host_visible_base().ok_or(FsError::InvalidData)?;
                let offset = dev
                    .alloc_host_visible(req.size)
                    .ok_or(FsError::OutOfMemory)?;
                dev.map_blob(resource_id, offset)
                    .map_err(|_| FsError::InvalidData)?;
                state.insert_host_visible(handle, resource_id, base, offset, req.size);
            } else {
                state.insert_host_only(handle, resource_id, req.size);
            }
        }

        _ => return Err(FsError::InvalidData),
    }
    req.bo_handle = handle;
    req.res_handle = resource_id;
    // Writes back the leading 48 bytes (bo_handle/res_handle at offsets 8/12);
    // any Mesa-appended trailing bytes are left untouched.
    write_uapi(arg, req)?;
    Ok(0)
}

fn handle_transfer_3d(
    arg: usize,
    state: &VirtGpuRenderState,
    from_host: bool,
) -> Result<u64, FsError> {
    use crate::drm_uapi::DrmVirtGpuTransferToHostUapi;

    let req: DrmVirtGpuTransferToHostUapi = read_uapi(arg)?;
    let dev = narf_drivers_virtio::gpu_pci::probed_device();
    // Linux checks the VirGL feature before looking up the handle for the
    // host-to-guest ioctl. Its guest-to-host ioctl has a separate 2D fallback;
    // NARF does not advertise that private render path, so report ENOSYS when
    // no 3D transport exists.
    if from_host && !dev.map(|d| d.virgl_enabled()).unwrap_or(false) {
        return Err(FsError::NotImplemented);
    }

    let resource = state.find(req.bo_handle).ok_or(FsError::NotFound)?;
    if resource.is_guest_only_blob()
        || (!resource.host3d_blob && (req.stride != 0 || req.layer_stride != 0))
    {
        return Err(FsError::InvalidData);
    }
    let dev = dev
        .filter(|d| d.virgl_enabled())
        .ok_or(FsError::NotImplemented)?;
    state.ensure_context(dev)?;
    let transfer = narf_drivers_virtio::gpu_pci::cmd::Transfer3D {
        resource_id: resource.resource_id,
        x: req.x,
        y: req.y,
        z: req.z,
        width: req.w,
        height: req.h,
        depth: req.d,
        offset: req.offset as u64,
        level: req.level,
        stride: req.stride,
        layer_stride: req.layer_stride,
    };
    if from_host {
        dev.transfer_from_host_virgl(state.ctx_id, transfer)
    } else {
        dev.transfer_to_host_virgl(state.ctx_id, transfer)
    }
    .map_err(map_gpu_transport_error)?;
    Ok(0)
}

/// DRM syncobj ioctls on the render node, backed by this open's per-fd table.
/// The DRM native context (radeonsi-over-virtio) creates syncobjs during device
/// init and rendering. Dispatched by ioctl number (0xbf..=0xc5).
fn handle_syncobj(nr: u32, arg: usize, state: &VirtGpuRenderState) -> Result<u64, FsError> {
    match nr {
        // SYNCOBJ_CREATE { u32 handle (out), u32 flags }
        0xbf => {
            let mut req: crate::drm_uapi::DrmSyncobjCreateUapi = read_uapi(arg)?;
            let handle = state
                .syncobjs
                .lock()
                .create(req.flags)
                .map_err(|_| FsError::InvalidData)?;
            req.handle = handle;
            write_uapi(arg, req)?;
            Ok(0)
        }
        // SYNCOBJ_DESTROY { u32 handle, u32 pad }
        0xc0 => {
            // SAFETY: `arg` is the ioctl's user struct pointer; copy_in bounds
            // the 8-byte read and SMAP-brackets it.
            let bytes = unsafe { copy_in(arg, 8)? };
            let handle =
                u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| FsError::InvalidData)?);
            state
                .syncobjs
                .lock()
                .destroy(handle)
                .map_err(|_| FsError::InvalidData)?;
            Ok(0)
        }
        // SYNCOBJ_RESET (0xc4) / SIGNAL (0xc5): drm_syncobj_array
        // { u64 handles, u32 count_handles, u32 pad }
        0xc4 | 0xc5 => {
            // SAFETY: `arg` is the ioctl's user struct pointer; copy_in bounds
            // the 16-byte read and SMAP-brackets it.
            let bytes = unsafe { copy_in(arg, 16)? };
            let handles_ptr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
            if count == 0 || count > 4096 || handles_ptr == 0 {
                return Err(FsError::InvalidData);
            }
            // SAFETY: `handles_ptr` is the user handle-array pointer from the
            // ioctl struct; copy_in bounds `count * 4` and SMAP-brackets it.
            let hbytes = unsafe { copy_in(handles_ptr as usize, count * 4)? };
            let ids: Vec<u32> = hbytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            let mut tbl = state.syncobjs.lock();
            if nr == 0xc5 {
                tbl.signal_handles(&ids).map_err(|_| FsError::InvalidData)?;
            } else {
                tbl.reset_handles(&ids).map_err(|_| FsError::InvalidData)?;
            }
            Ok(0)
        }
        // SYNCOBJ_WAIT: drm_syncobj_wait { u64 handles, s64 timeout_nsec,
        //   u32 count_handles, u32 flags, u32 first_signaled, u32 pad,
        //   u64 deadline_nsec } (40 bytes in the current UAPI).
        0xc3 => {
            // SAFETY: `arg` is the ioctl's user struct pointer; copy_in bounds
            // the 40-byte read and SMAP-brackets it.
            let bytes = unsafe { copy_in(arg, 40)? };
            let handles_ptr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            let timeout_abs_ns = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
            let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
            let flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
            const WAIT_ALL: u32 = 1 << 0;
            const WAIT_FOR_SUBMIT: u32 = 1 << 1;
            if count == 0
                || count > 4096
                || handles_ptr == 0
                || flags & !(WAIT_ALL | WAIT_FOR_SUBMIT) != 0
            {
                return Err(FsError::InvalidData);
            }
            // SAFETY: `handles_ptr` is the user handle-array pointer from the
            // ioctl struct; copy_in bounds `count * 4` and SMAP-brackets it.
            let hbytes = unsafe { copy_in(handles_ptr as usize, count * 4)? };
            let ids: Vec<u32> = hbytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            let fences = state
                .syncobjs
                .lock()
                .snapshot_fences(&ids)
                .map_err(|_| FsError::InvalidData)?;
            // WAIT_FOR_SUBMIT only changes the no-fence case. Output syncobjs
            // are bound before EXECBUFFER returns, so ordinary Mesa waits
            // arrive with a fence already present; an overlapping wait on an
            // unbound object remains retryable rather than holding the table
            // lock across the producer.
            if fences.iter().any(Option::is_none) {
                return Err(FsError::WouldBlock);
            }
            let now = narf_time::wall::monotonic_ns();
            // Linux interprets this as an absolute CLOCK_MONOTONIC instant.
            // A negative value is already expired; INT64_MAX is the ordinary
            // userspace spelling of an effectively infinite wait, capped here
            // by the same 15 s GPU-hang bound as VIRTGPU_WAIT.
            let timeout_ns = u64::try_from(timeout_abs_ns)
                .unwrap_or(0)
                .saturating_sub(now)
                .min(15_000_000_000);
            match crate::drm::syncobj::SyncObjTable::wait_fences(&ids, &fences, timeout_ns, flags) {
                Ok(first_handle) => {
                    let first = ids
                        .iter()
                        .position(|handle| *handle == first_handle)
                        .unwrap_or(0) as u32;
                    // SAFETY: writes 4 bytes to the `first_signaled` field at
                    // offset 24 of the ioctl struct; copy_out SMAP-brackets it.
                    unsafe { copy_out(arg + 24, &first.to_le_bytes())? };
                    Ok(0)
                }
                Err(_) => Err(FsError::WouldBlock), // → EAGAIN
            }
        }
        // HANDLE_TO_FD (0xc1) / FD_TO_HANDLE (0xc2): fence-fd export/import needs
        // sync_file fd infrastructure NARF does not have yet.
        _ => Err(FsError::Unsupported),
    }
}

/// Dispatch the Mesa/libdrm virtgpu subset on a render-node fd.
/// Unknown commands intentionally remain ENOTTY: advertising an ioctl that
/// only partly implements fence or blob semantics causes Mesa to assume a
/// guarantee the kernel cannot keep.
pub fn dispatch_virtgpu_render(
    cmd: u32,
    arg: usize,
    state: &VirtGpuRenderState,
) -> Result<u64, FsError> {
    dispatch_virtgpu_render_inner(cmd, arg, state, None)
}

/// Primary-node variant: GEM_CLOSE must also drop the imported KMS GEM-handle
/// reference held in the card's global mode state.
pub fn dispatch_virtgpu_render_for_card(
    card_index: u32,
    cmd: u32,
    arg: usize,
    state: &VirtGpuRenderState,
) -> Result<u64, FsError> {
    let result = dispatch_virtgpu_render_inner(cmd, arg, state, Some(card_index))?;
    let nr = drm_uapi::ioc_nr(cmd);
    if cmd == drm_uapi::DRM_IOCTL_VIRTGPU_RESOURCE_CREATE
        || nr == drm_uapi::DRM_VIRTGPU_NR_RESOURCE_CREATE_BLOB
    {
        register_card_virtgpu_resource(card_index, arg, state, nr)?;
    }
    Ok(result)
}

/// A primary-node `drm_file` has one GEM handle namespace in Linux: a handle
/// returned by VIRTGPU_RESOURCE_CREATE is immediately valid for ADDFB2 on the
/// same fd. NARF's render state and generic KMS table are separate structures,
/// so mirror the new binding into the card table before returning to userspace.
fn register_card_virtgpu_resource(
    card_index: u32,
    arg: usize,
    state: &VirtGpuRenderState,
    nr: u32,
) -> Result<(), FsError> {
    let (old_handle, is_blob) = if nr == drm_uapi::DRM_VIRTGPU_NR_RESOURCE_CREATE_BLOB {
        let req: drm_uapi::DrmVirtGpuResourceCreateBlobUapi = read_uapi(arg)?;
        (req.bo_handle, true)
    } else {
        let req: drm_uapi::DrmVirtGpuResourceCreateUapi = read_uapi(arg)?;
        (req.bo_handle, false)
    };
    let resource = state.find(old_handle).ok_or(FsError::NotFound)?;
    let mode_state = crate::drm_registry::mode_state(card_index).ok_or(FsError::InvalidData)?;
    let handle = {
        let card = mode_state.lock();
        if card.gem.lookup(old_handle).is_none() {
            old_handle
        } else {
            drop(card);
            loop {
                let candidate = state.allocate_handle();
                if mode_state.lock().gem.lookup(candidate).is_none() {
                    break candidate;
                }
            }
        }
    };
    if handle != old_handle {
        state.rename_handle(old_handle, handle)?;
    }
    if let Err(_error) = mode_state
        .lock()
        .register_virtgpu_import(handle, Arc::clone(&resource))
    {
        if let Some((resource, attached)) = state.take(handle) {
            release_virtgpu_resource(state.ctx_id, resource, attached);
        }
        return Err(FsError::OutOfMemory);
    }
    if is_blob {
        let mut req: drm_uapi::DrmVirtGpuResourceCreateBlobUapi = read_uapi(arg)?;
        req.bo_handle = handle;
        write_uapi(arg, req)?;
    } else {
        let mut req: drm_uapi::DrmVirtGpuResourceCreateUapi = read_uapi(arg)?;
        req.bo_handle = handle;
        write_uapi(arg, req)?;
    }
    Ok(())
}

fn dispatch_virtgpu_render_inner(
    cmd: u32,
    arg: usize,
    state: &VirtGpuRenderState,
    card_index: Option<u32>,
) -> Result<u64, FsError> {
    use crate::drm_uapi::*;
    // RESOURCE_CREATE_BLOB is dispatched by command *number*: the DRM native
    // context's Mesa build sends a struct larger than libdrm's canonical 48
    // bytes, so the full encoded ioctl won't equal a fixed constant.
    if ioc_nr(cmd) == DRM_VIRTGPU_NR_RESOURCE_CREATE_BLOB {
        return handle_resource_create_blob(arg, state);
    }
    // DRM syncobj ioctls (nr 0xbf..=0xc5: CREATE/DESTROY/HANDLE_TO_FD/
    // FD_TO_HANDLE/WAIT/RESET/SIGNAL). The DRM native context creates and uses
    // syncobjs; route them to this open's per-fd table. Dispatched by number so
    // struct-size variations don't matter.
    if (0xbf..=0xc5).contains(&ioc_nr(cmd)) {
        return handle_syncobj(ioc_nr(cmd), arg, state);
    }
    match cmd {
        DRM_IOCTL_VIRTGPU_GETPARAM => {
            let req: DrmVirtGpuGetParamUapi = read_uapi(arg)?;
            let dev = narf_drivers_virtio::gpu_pci::probed_device();
            let available = dev.map(|d| d.virgl_enabled()).unwrap_or(false);
            let blob_ok = dev.map(|d| d.resource_blob_enabled()).unwrap_or(false);
            let ctx_ok = dev.map(|d| d.context_init_enabled()).unwrap_or(false);
            let host_vis = dev.map(|d| d.host_visible_available()).unwrap_or(false);
            let value: u64 = match req.param {
                // VIRTGPU_PARAM_3D_FEATURES.
                1 => u64::from(available),
                // VIRTGPU_PARAM_CAPSET_QUERY_FIX (2): Linux returns 1
                // unconditionally, and our GET_CAPS is the by-id form matching
                // `virtio_gpu_get_caps_ioctl`, so the fix is genuinely present.
                2 => 1,
                // VIRTGPU_PARAM_RESOURCE_BLOB (3): reflects the negotiated
                // VIRTIO_GPU_F_RESOURCE_BLOB. The DRM native context needs this.
                3 => u64::from(blob_ok),
                // VIRTGPU_PARAM_HOST_VISIBLE (4): reflects whether the device
                // exposes a host-visible blob window (shmid 0), which host3d
                // mappable blobs are mapped into.
                4 => u64::from(host_vis),
                // CROSS_DEVICE (5): no UUID assignment yet.
                5 => 0,
                // VIRTGPU_PARAM_CONTEXT_INIT (6): reflects negotiated
                // VIRTIO_GPU_F_CONTEXT_INIT — lets Mesa bind capset 6.
                6 => u64::from(ctx_ok),
                // VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs (7): a bitmask with bit N
                // set for each enumerated capset id N, from the host's actual
                // GET_CAPSET_INFO enumeration (Linux: vgdev->capset_id_mask).
                7 => dev
                    .map(|d| {
                        d.capsets()
                            .iter()
                            .fold(0u64, |m, c| m | (1u64 << c.capset_id))
                    })
                    .unwrap_or(0),
                // EXPLICIT_DEBUG_NAME (8): Linux returns has_context_init.
                8 => u64::from(ctx_ok),
                // Linux `virtio_gpu_getparam_ioctl` returns -EINVAL for any
                // param it does not recognise — not a silent 0.
                _ => return Err(FsError::InvalidData),
            };
            // Linux `virtio_gpu_getparam_ioctl` treats the struct's `value`
            // field as a USER POINTER and writes the result there as an int:
            //   copy_to_user(u64_to_user_ptr(param->value), &value, sizeof(int));
            // It does NOT write the value back into the ioctl struct. Writing
            // the field instead left Mesa's own result buffer (which `value`
            // pointed at) untouched, so its virgl winsys read 3D_FEATURES == 0
            // and dropped every GL client to llvmpipe. Match Linux exactly:
            // write a 4-byte int to the pointer.
            let value_i32 = value as i32;
            // SAFETY: `req.value` is the user pointer libdrm passed in the
            // ioctl struct; copy_out SMAP-brackets the 4-byte write and
            // rejects a null destination.
            unsafe { copy_out(req.value as usize, &value_i32.to_le_bytes())? };
            Ok(0)
        }
        DRM_IOCTL_VIRTGPU_CONTEXT_INIT => {
            let req: DrmVirtGpuContextInitUapi = read_uapi(arg)?;
            let dev = narf_drivers_virtio::gpu_pci::probed_device().ok_or(FsError::InvalidData)?;
            if !dev.context_init_enabled() || !dev.virgl_enabled() || req.num_params > 4 {
                return Err(FsError::InvalidData);
            }
            if state.context_ready.load(Ordering::Acquire) {
                return Err(FsError::AlreadyExists);
            }

            // Linux accepts at most one of each parameter, validates capset
            // and ring values before CTX_CREATE, and reports every malformed
            // case as EINVAL (bad parameter-array pointers remain EFAULT).
            let mut capset = state.context_capset.load(Ordering::Acquire);
            let mut num_rings = state.context_num_rings.load(Ordering::Acquire);
            let mut ring_mask = state.context_ring_mask.load(Ordering::Acquire);
            let mut explicit_debug_name = state.context_explicit_debug_name.load(Ordering::Acquire);
            let n = req.num_params as usize;
            if n != 0 {
                // SAFETY: `ctx_set_params` is the user pointer libdrm passed;
                // copy_in SMAP-brackets the read and bounds n*16.
                let bytes = unsafe { copy_in(req.ctx_set_params as usize, n * 16)? };
                for i in 0..n {
                    let p = u64::from_le_bytes(bytes[i * 16..i * 16 + 8].try_into().unwrap());
                    let v = u64::from_le_bytes(bytes[i * 16 + 8..i * 16 + 16].try_into().unwrap());
                    match p {
                        VIRTGPU_CONTEXT_PARAM_CAPSET_ID => {
                            if v > 63
                                || dev.capsets().iter().all(|c| c.capset_id != v as u32)
                                || capset != 0
                            {
                                return Err(FsError::InvalidData);
                            }
                            capset = v as u32;
                        }
                        VIRTGPU_CONTEXT_PARAM_NUM_RINGS => {
                            if num_rings != 0 || v > 64 {
                                return Err(FsError::InvalidData);
                            }
                            num_rings = v as u32;
                        }
                        VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK => {
                            if ring_mask != 0 {
                                return Err(FsError::InvalidData);
                            }
                            ring_mask = v;
                        }
                        VIRTGPU_CONTEXT_PARAM_DEBUG_NAME => {
                            if explicit_debug_name {
                                return Err(FsError::InvalidData);
                            }
                            if v == 0 {
                                return Err(FsError::BadAddress);
                            }
                            // The transport uses a fixed kernel debug name,
                            // but pointer presence and one-shot semantics are
                            // the Linux-visible contract.
                            explicit_debug_name = true;
                        }
                        _ => return Err(FsError::InvalidData),
                    }
                }
            }
            let valid_ring_mask = match num_rings {
                0 => 0,
                64 => u64::MAX,
                count => (1u64 << count) - 1,
            };
            if ring_mask & !valid_ring_mask != 0 {
                return Err(FsError::InvalidData);
            }
            // Record the capset for this open and create its context now.
            state.context_capset.store(capset, Ordering::Release);
            state.context_num_rings.store(num_rings, Ordering::Release);
            state.context_ring_mask.store(ring_mask, Ordering::Release);
            state
                .context_explicit_debug_name
                .store(explicit_debug_name, Ordering::Release);
            state.ensure_context(dev)?;
            Ok(0)
        }
        DRM_IOCTL_VIRTGPU_RESOURCE_CREATE => {
            let mut req: DrmVirtGpuResourceCreateUapi = read_uapi(arg)?;
            // Linux allocates one page when userspace passes size=0; it does
            // not derive allocation size from width/height.
            let bytes = if req.size == 0 {
                4096
            } else {
                req.size as usize
            };
            let backing = alloc_guest_backing(bytes)?;
            let entries = backing.entries();
            let resource_id = NEXT_VIRTGPU_RESOURCE_ID.fetch_add(1, Ordering::Relaxed);
            let dev = narf_drivers_virtio::gpu_pci::probed_device()
                .filter(|d| d.virgl_enabled())
                .ok_or(FsError::NotImplemented)?;
            state.ensure_context(dev)?;
            dev.create_virgl_resource(
                state.ctx_id,
                narf_drivers_virtio::gpu_pci::cmd::ResourceCreate3D {
                    resource_id,
                    target: req.target,
                    format: req.format,
                    bind: req.bind,
                    width: req.width,
                    height: req.height,
                    depth: req.depth,
                    array_size: req.array_size,
                    last_level: req.last_level,
                    nr_samples: req.nr_samples,
                    flags: req.flags,
                },
                &entries,
            )
            .map_err(|_| FsError::InvalidData)?;
            let handle = state.allocate_handle();
            state.insert_backing(handle, resource_id, backing);
            req.bo_handle = handle;
            req.res_handle = resource_id;
            write_uapi(arg, req)?;
            Ok(0)
        }
        DRM_IOCTL_VIRTGPU_RESOURCE_INFO => {
            let mut req: DrmVirtGpuResourceInfoUapi = read_uapi(arg)?;
            let resource = state.find(req.bo_handle).ok_or(FsError::NotFound)?;
            req.res_handle = resource.resource_id;
            req.size = resource.len() as u32;
            req.blob_mem = resource.blob_mem.unwrap_or(0);
            write_uapi(arg, req)?;
            Ok(0)
        }
        DRM_IOCTL_VIRTGPU_MAP => {
            let mut req: DrmVirtGpuMapUapi = read_uapi(arg)?;
            let _resource = state.find(req.handle).ok_or(FsError::NotFound)?;
            req.offset = (req.handle as u64) << 12;
            write_uapi(arg, req)?;
            Ok(0)
        }
        DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST => handle_transfer_3d(arg, state, true),
        DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST => handle_transfer_3d(arg, state, false),
        DRM_IOCTL_VIRTGPU_WAIT => {
            // `virtio_gpu_wait_ioctl`: NOWAIT tests the BO's reservation and
            // reports EBUSY while work is outstanding; otherwise wait up to
            // 15 s (Linux's DRM long timeout) and report EBUSY on expiry.
            const VIRTGPU_WAIT_NOWAIT: u32 = 1;
            let req: DrmVirtGpuWaitUapi = read_uapi(arg)?;
            let resource = state.find(req.handle).ok_or(FsError::NotFound)?;
            let fence = resource.last_fence.lock().clone();
            let Some(fence) = fence else {
                // Never referenced by a fenced submission — idle. The
                // synchronous TRANSFER/CREATE paths complete before their
                // ioctls return, so they leave no wait obligation.
                return Ok(0);
            };
            if req.flags & VIRTGPU_WAIT_NOWAIT != 0 {
                return if fence.is_device_signalled() {
                    Ok(0)
                } else {
                    // FsError::Busy → EBUSY at the syscall layer, matching
                    // Linux's dma_resv_test_signaled() == false path.
                    Err(FsError::Busy)
                };
            }
            if fence.wait_device(15_000) {
                Ok(0)
            } else {
                Err(FsError::Busy)
            }
        }
        DRM_IOCTL_VIRTGPU_GET_CAPS => {
            let req: DrmVirtGpuGetCapsUapi = read_uapi(arg)?;
            // Linux rejects a zero transfer size with EINVAL. A null or bad
            // destination instead fails copy_to_user with EFAULT below.
            if req.size == 0 {
                return Err(FsError::InvalidData);
            }
            let dev =
                narf_drivers_virtio::gpu_pci::probed_device().ok_or(FsError::NotImplemented)?;
            let capsets = dev.capsets();
            if capsets.is_empty() {
                return Err(FsError::NotImplemented);
            }
            // Validate the requested capset against the host's enumerated list,
            // exactly as Linux's `virtio_gpu_get_caps_ioctl` does: a capset the
            // host did not enumerate (or backs with zero size) is EINVAL. Mesa's
            // native-context probe asks for the DRM capset (id 6), which
            // QEMU/virglrenderer advertises but leaves empty without GPU
            // passthrough; rejecting it here (instead of forwarding an empty
            // capset) makes Mesa fall back to classic VirGL (capset 2) rather
            // than dropping to llvmpipe — whose dmabuf EGLImage path then throws
            // EGL_BAD_ALLOC in kwin (blank screen).
            let capset = capsets
                .iter()
                .find(|capset| {
                    capset.capset_id == req.cap_set_id
                        && capset.capset_max_version >= req.cap_set_ver
                        && capset.capset_max_size != 0
                })
                .ok_or(FsError::InvalidData)?;
            let caps = dev
                .virgl_capset(req.cap_set_id, req.cap_set_ver)
                .map_err(map_gpu_transport_error)?;
            let n = caps
                .len()
                .min(req.size as usize)
                .min(capset.capset_max_size as usize);
            // SAFETY: `n` is bounded by both the returned capset and the
            // caller's declared buffer size. copy_out rejects a null pointer
            // as EFAULT and SMAP-brackets the destination write.
            unsafe { copy_out(req.addr as usize, &caps[..n])? };
            Ok(0)
        }
        DRM_IOCTL_VIRTGPU_EXECBUFFER => {
            let req: DrmVirtGpuExecBufferUapi = read_uapi(arg)?;
            let dev = narf_drivers_virtio::gpu_pci::probed_device()
                .filter(|d| d.virgl_enabled())
                .ok_or(FsError::NotImplemented)?;
            // libdrm VIRTGPU_EXECBUF_* flags.
            const EXECBUF_FENCE_FD_IN: u32 = 0x01;
            const EXECBUF_FENCE_FD_OUT: u32 = 0x02;
            const EXECBUF_RING_IDX: u32 = 0x04;
            const EXECBUF_KNOWN: u32 =
                EXECBUF_FENCE_FD_IN | EXECBUF_FENCE_FD_OUT | EXECBUF_RING_IDX;
            // The syscall layer validates/waits FENCE_FD_IN and reserves the
            // FENCE_FD_OUT descriptor before dispatch. Binary syncobj arrays
            // are handled below; non-zero timeline points remain unsupported.
            if req.flags & !EXECBUF_KNOWN != 0 {
                return Err(FsError::InvalidData);
            }
            if req.size as usize > VIRTGPU_EXECBUFFER_MAX_BYTES || req.num_bo_handles > 256 {
                return Err(FsError::OutOfMemory);
            }
            let ring_idx = if req.flags & EXECBUF_RING_IDX != 0 {
                let num_rings = state.context_num_rings.load(Ordering::Acquire);
                if num_rings == 0 || req.ring_idx >= num_rings {
                    return Err(FsError::InvalidData);
                }
                Some(req.ring_idx as u8)
            } else {
                None
            };
            let submission_context = state.execbuf_context(u32::from(ring_idx.unwrap_or(0)));
            let in_syncobjs = read_exec_syncobjs(
                req.in_syncobjs,
                req.num_in_syncobjs,
                req.syncobj_stride,
                false,
            )?;
            let out_syncobjs = read_exec_syncobjs(
                req.out_syncobjs,
                req.num_out_syncobjs,
                req.syncobj_stride,
                true,
            )?;
            // Resolve every handle before submission. Clone the input fences
            // so the IRQ-safe table lock is never held while waiting for GPU
            // completion or for a pipeline slot.
            let input_fences: Vec<Arc<dyn crate::drm::syncobj::DmaFence>> = {
                let table = state.syncobjs.lock();
                for dep in &out_syncobjs {
                    table.get(dep.handle).map_err(|_| FsError::InvalidData)?;
                }
                in_syncobjs
                    .iter()
                    .map(|dep| {
                        table
                            .get(dep.handle)
                            .map_err(|_| FsError::InvalidData)?
                            .fence
                            .clone()
                            .ok_or(FsError::InvalidData)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            };
            // Linux skips a synchronous wait when the dependency belongs to
            // this exact ordered fence context; queue order already provides
            // it. Foreign rings/devices are waited before the new job queues.
            for fence in &input_fences {
                if sync_dependency_needs_wait(fence.context(), submission_context)
                    && !fence.wait(15_000_000_000)
                {
                    return Err(FsError::Busy);
                }
            }
            // Validate every referenced handle before touching the command
            // pointer. This makes the resource ownership check independent of
            // virgl command parsing (which belongs to the host renderer).
            let mut referenced: [Option<Arc<VirtGpuResource>>; 256] = [const { None }; 256];
            if req.num_bo_handles != 0 {
                // SAFETY: the count is capped at 256 above, multiplication by
                // four cannot overflow, and copy_in validates the entire
                // userspace handle-array range before returning owned bytes.
                let bytes =
                    unsafe { copy_in(req.bo_handles as usize, req.num_bo_handles as usize * 4)? };
                for (index, chunk) in bytes.chunks_exact(4).enumerate() {
                    let handle =
                        u32::from_le_bytes(chunk.try_into().map_err(|_| FsError::InvalidData)?);
                    referenced[index] = Some(state.find(handle).ok_or(FsError::NotFound)?);
                }
            }
            // A size-0 execbuf is a valid ring "kick" for the native context
            // (the ccmd lives in the shmem ring, referenced by ring_idx), so
            // only copy a command payload when one is present.
            let commands = if req.size != 0 {
                // SAFETY: `req.command` is the user command pointer; size is
                // bounded to the controlQ request buffer above, and copy_in
                // validates the complete source range and returns owned bytes.
                unsafe { copy_in(req.command as usize, req.size as usize)? }
            } else {
                Vec::new()
            };
            state.ensure_context(dev)?;
            // Fenced, asynchronous submission: the ioctl returns once the
            // stream is queued; the fence id signals when the host has
            // executed it (Linux `virtio_gpu_execbuffer_ioctl`). The
            // TRANSFER_*_HOST ioctls stay synchronous and UNfenced on
            // purpose: the device processes the control queue in order, so
            // by the time a transfer's own response arrives every earlier
            // fenced submit has executed — the ordering argument that keeps
            // this v1 safe without per-BO reservation objects.
            let transport_fence = match dev.submit_virgl_fenced(state.ctx_id, ring_idx, &commands) {
                Ok(fence) => fence,
                Err(error) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  drm: EXECBUFFER submit failed: {error:?}"
                    );
                    return Err(map_gpu_transport_error(error));
                }
            };
            let fence = VirtGpuFence::new(transport_fence, submission_context);
            // Publish the fence on every referenced BO (VIRTGPU_WAIT reads
            // it) and on the open (FENCE_FD_OUT's sync_file reads it).
            for resource in referenced.iter().flatten() {
                *resource.last_fence.lock() = Some(fence.clone());
            }
            if req.flags & EXECBUF_FENCE_FD_OUT != 0 {
                state
                    .pending_execbuf_fences
                    .lock()
                    .push((narf_scheduler::current_task_id().raw(), fence.clone()));
            }
            // Publish the same hardware-backed fence to every output syncobj
            // and consume RESET-marked inputs. Handles were prevalidated; if
            // a racing DESTROY removed one meanwhile, it has no remaining
            // userspace observer and can be skipped safely.
            let sync_fence: Arc<dyn crate::drm::syncobj::DmaFence> = fence;
            let mut table = state.syncobjs.lock();
            for dep in &in_syncobjs {
                if dep.reset {
                    if let Ok(obj) = table.get_mut(dep.handle) {
                        obj.fence = None;
                    }
                }
            }
            for dep in &out_syncobjs {
                if let Ok(obj) = table.get_mut(dep.handle) {
                    obj.replace_fence(sync_fence.clone());
                }
            }
            Ok(0)
        }
        DRM_IOCTL_GEM_CLOSE => {
            // `struct drm_gem_close { u32 handle; u32 pad; }`. Remove the
            // per-open handle before touching the host, so no new operation
            // can acquire the resource while teardown is in progress.
            // SAFETY: `arg` is the ioctl's userspace struct pointer; copy_in
            // validates the complete fixed-size range and SMAP-brackets it.
            let bytes = unsafe { copy_in(arg, 8)? };
            let handle =
                u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| FsError::InvalidData)?);
            // The primary node also owns dumb GEM handles, which live in the
            // generic card table rather than this VirtGPU per-open table.
            // Let the caller fall through to that path when the handle is not
            // a VirtGPU resource. The generic close returns Linux's EINVAL if
            // neither table owns it.
            let Some((resource, attached)) = state.take(handle) else {
                return Err(FsError::Unsupported);
            };
            release_virtgpu_resource(state.ctx_id, resource, attached);
            if let Some(index) = card_index {
                if let Some(mode_state) = crate::drm_registry::mode_state(index) {
                    mode_state.lock().remove_virtgpu_import(handle);
                }
            }
            Ok(0)
        }
        _ => Err(FsError::Unsupported),
    }
}

/// Quiesce one host resource before releasing its DMA pages. If host teardown
/// fails, intentionally retain this Arc: freeing the backing would let a live
/// host resource DMA into recycled kernel or userspace memory. `ctx_id` is the
/// owning open's render context (used to detach context-owned resources).
pub(crate) fn release_virtgpu_resource(
    ctx_id: u32,
    resource: Arc<VirtGpuResource>,
    attached: bool,
) {
    if attached {
        let detached = narf_drivers_virtio::gpu_pci::probed_device()
            .map(|dev| {
                dev.detach_virgl_resource(ctx_id, resource.resource_id)
                    .is_ok()
            })
            .unwrap_or(false);
        if !detached {
            core::mem::forget(resource);
            return;
        }
    }
    drop(resource);
}

/// Resolve a per-open VirtIO-GPU map offset for `sys_mmap`.
pub fn dispatch_virtgpu_mmap(
    state: &VirtGpuRenderState,
    offset: u64,
    len: usize,
) -> Result<Vec<u64>, FsError> {
    if offset & 0xfff != 0 || len == 0 || len & 0xfff != 0 {
        return Err(FsError::InvalidData);
    }
    let handle = (offset >> 12) as u32;
    let resource = state.find(handle).ok_or(FsError::InvalidData)?;
    if !resource.is_cpu_mappable() || len > resource.len() {
        return Err(FsError::InvalidData);
    }
    // Guest-backed resources map their coherent DMA pages; host-visible blobs
    // map a slice of the host-visible PCI window. `page_phys` hides the split.
    Ok((0..len / 4096)
        .map(|page| resource.page_phys(page))
        .collect())
}

/// Read `N` bytes from a user-pointer into a kernel `Vec<u8>`.
///
/// # Safety
/// `uptr` must be a valid user-mode pointer for the calling task or a
/// kernel-mode pointer (test-only). The caller must hold the syscall
/// trap context (no IRQ context, AS still active).
pub(crate) unsafe fn copy_in(uptr: usize, len: usize) -> Result<Vec<u8>, FsError> {
    if uptr == 0 {
        return Err(FsError::BadAddress);
    }
    if len > IOCTL_MAX_BUF {
        return Err(FsError::InvalidData);
    }
    let mut out = vec![0u8; len];
    // SAFETY: `uptr` is the user (or test-kernel) ioctl arg; `user_memcpy`
    // SMAP-brackets the read so a real user pointer doesn't #PF under SMAP.
    unsafe {
        user_memcpy(out.as_mut_ptr(), uptr as *const u8, len);
    }
    Ok(out)
}

/// Write a kernel slice back into a user-pointer.
pub(crate) unsafe fn copy_out(uptr: usize, bytes: &[u8]) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::BadAddress);
    }
    // SAFETY: `uptr` is the user (or test-kernel) ioctl arg; `user_memcpy`
    // SMAP-brackets the write.
    unsafe {
        user_memcpy(uptr as *mut u8, bytes.as_ptr(), bytes.len());
    }
    Ok(())
}

/// `copy_nonoverlapping` bracketed by a SMAP user-access window so the
/// kernel may touch user memory through the raw ioctl pointer. The DRM
/// ioctl path reaches here from `sys_ioctl`, which passes the user `arg`
/// straight through without clearing SMAP. Harmless on kernel pointers
/// (the test smokes): `stac` only relaxes the U/S check, it never breaks
/// a supervisor access.
///
/// # Safety
/// `dst`/`src` must be valid for `len` bytes; one side may be user memory.
#[cfg(target_arch = "x86_64")]
unsafe fn user_memcpy(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: caller guarantees the ranges; with_user_access toggles AC.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(src, dst, len);
        });
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn user_memcpy(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: caller guarantees the ranges.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, len) };
}

// ── Error translation ────────────────────────────────────────────────

fn map_err(e: DrmIoctlError) -> FsError {
    match e {
        DrmIoctlError::UnknownCmd | DrmIoctlError::BadSize => FsError::Unsupported,
        DrmIoctlError::PermissionDenied(_) => FsError::PermissionDenied,
        DrmIoctlError::UnknownConnector | DrmIoctlError::Card(_) => FsError::InvalidData,
    }
}

// ── Entry point ──────────────────────────────────────────────────────

/// Top-level `FileOps::ioctl` body for DRM card + render nodes.
///
/// `card_index` is the registry index of the card (`/dev/dri/card<N>`
/// or `renderD<N+128>`); `open_id` uniquely identifies the calling open
/// file (used for DRM master arbitration — ignored on the render path);
/// `cmd` is the encoded ioctl number; `arg` is the raw user pointer;
/// `render` selects render-node vs primary-node `DrmFileCtx`.
///
/// Returns the syscall return value (0 on success for most ioctls, or
/// an ioctl-specific positive value) or a translated `FsError`.
pub fn dispatch_card(
    card_index: u32,
    open_id: u64,
    cmd: u32,
    arg: usize,
    render: bool,
) -> Result<u64, FsError> {
    // Compatibility entry point for in-kernel one-shot callers and smokes.
    // Real file objects call `dispatch_card_for_file` so client-cap state is
    // retained across ioctls on that open.
    let client_caps = DrmClientCaps::new();
    let events = narf_lib::sync::IrqSafeSpinLock::new(crate::drm::card::DrmEventQueue::new());
    dispatch_card_for_file(
        card_index,
        open_id,
        cmd,
        arg,
        render,
        &client_caps,
        (!render).then_some(&events),
        None,
    )
}

/// Stateful card dispatcher used by a real DRM open file.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_card_for_file(
    card_index: u32,
    open_id: u64,
    cmd: u32,
    arg: usize,
    render: bool,
    client_caps: &DrmClientCaps,
    events: Option<&narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>>,
    out_fences: Option<&narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<(u64, u64)>>>,
) -> Result<u64, FsError> {
    // 1. Resolve the card. Cards registered without mode_state return
    //    ENOTSUP — bring-up drivers haven't built a Card yet.
    let mode_state = crate::drm_registry::mode_state(card_index).ok_or(FsError::Unsupported)?;

    // 2. Build the per-fd ctx. Primary opens are always authenticated, but
    //    `is_master` reflects whether THIS open currently holds the device's
    //    DRM master (compared against `Card::current_master`). Only the master
    //    passes the modeset gate — so a greeter and a user-session compositor
    //    can't both drive the scanout; the master is handed off via
    //    SET/DROP_MASTER (below) and auto-released on fd close.
    let ctx = if render {
        DrmFileCtx::render_client()
    } else {
        let is_master = mode_state.lock().is_master(open_id);
        DrmFileCtx::primary(is_master)
    };

    // 3. Look up the per-cmd handler.
    let nr = drm_uapi::ioc_nr(cmd);
    match IoctlCmd::from_raw(nr) {
        // VERSION needs special-case handling because the user struct
        // holds out-pointers (name/date/desc) that the kernel writes
        // into separately. The generic dispatcher returns the filled
        // name/date/desc bytes; we copy them through here.
        IoctlCmd::Version => handle_version(&mode_state, arg, &ctx),
        // Atomic commit decodes into AtomicState directly — handled
        // here rather than through the generic dispatcher because the
        // dispatcher only carries the wire-format word.
        IoctlCmd::ModeAtomic => {
            handle_atomic(card_index, &mode_state, arg, &ctx, events, out_fences)
        }
        // GETRESOURCES is special because the response has pointer
        // arrays the user supplied; we must write IDs into those.
        IoctlCmd::ModeGetResources => handle_getresources(&mode_state, arg, &ctx),
        // GETCONNECTOR fills user mode/encoder arrays + the two-pass
        // count protocol; the generic path would discard the result.
        IoctlCmd::ModeGetConnector => handle_getconnector(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetEncoder => handle_getencoder(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetCrtc => handle_getcrtc(&mode_state, arg, &ctx),
        IoctlCmd::ModeObjGetProperties => handle_obj_getproperties(&mode_state, arg, &ctx),
        // Universal planes (synthesised PRIMARY plane per CRTC) — weston
        // needs these to find an output's primary plane on the legacy path.
        IoctlCmd::ModeGetPlaneRes => handle_getplane_res(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetPlane => handle_getplane(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetProperty => handle_getproperty(arg),
        IoctlCmd::ModeGetPropBlob => handle_getpropblob(&mode_state, arg, &ctx),
        // SETGAMMA — accept + no-op. We scan out the framebuffer verbatim
        // (no hardware gamma LUT), so modetest's post-modeset gamma reset
        // succeeds silently instead of warning `failed to set gamma`.
        IoctlCmd::ModeSetGamma => Ok(0),
        // SET_MASTER — claim DRM master for this open. Succeeds if the device
        // master is free (or already ours); EBUSY if another open holds it.
        // Render nodes carry no display authority → EACCES. Mirrors
        // drm_auth.c::drm_setmaster_ioctl.
        IoctlCmd::SetMaster => {
            if ctx.is_render_client() {
                return Err(FsError::PermissionDenied);
            }
            match mode_state.lock().set_master(open_id) {
                Ok(()) => Ok(0),
                Err(_) => Err(FsError::Busy), // → EBUSY
            }
        }
        // DROP_MASTER — release DRM master, freeing the device for the next
        // session's SET_MASTER (the greeter→user handoff). EINVAL if the caller
        // wasn't the current master. Mirrors drm_auth.c::drm_dropmaster_ioctl.
        IoctlCmd::DropMaster => {
            if ctx.is_render_client() {
                return Err(FsError::PermissionDenied);
            }
            match mode_state.lock().drop_master(open_id) {
                Ok(()) => Ok(0),
                Err(_) => Err(FsError::InvalidData), // → EINVAL
            }
        }
        // GET_MAGIC / AUTH_MAGIC — the DRM magic-token dance a compositor
        // does to confirm it's authenticated on its GPU fd. A primary-node fd
        // IS the authenticated master here, so hand back a fixed non-zero
        // magic (drm_auth.magic = u32 @ offset 0) and accept the auth. Without
        // these the ioctls fell through to the generic path → UnknownCmd →
        // ENOTTY, and kwin aborted: "Failed to authenticate the drm magic
        // token ... Not a tty" — right after TakeDevice handed it the fd.
        IoctlCmd::GetMagic => {
            if arg != 0 {
                // SAFETY: `arg` is the user drm_auth ptr; copy_out
                // range-validates it and SMAP-brackets the 4-byte write.
                unsafe { copy_out(arg, &1u32.to_le_bytes())? };
            }
            Ok(0)
        }
        IoctlCmd::AuthMagic => Ok(0),
        // SET_CLIENT_CAP — opt into UAPI behaviours. We accept
        // UNIVERSAL_PLANES (weston REQUIRES it — it enumerates the
        // primary plane through the universal-planes UAPI) but reject
        // ATOMIC so weston falls back to legacy SETCRTC modeset, which
        // narf-drm implements (full atomic-commit is not wired yet).
        IoctlCmd::SetClientCap => handle_set_client_cap(&mode_state, arg, client_caps),
        IoctlCmd::ModeCreatePropBlob => handle_create_property_blob(&mode_state, arg, &ctx),
        IoctlCmd::ModeDestroyPropBlob => handle_destroy_property_blob(&mode_state, arg, &ctx),
        IoctlCmd::ModeListLessees => handle_list_lessees(arg, &ctx),
        // Dumb-buffer ioctls — new in Rung 3.
        IoctlCmd::ModeCreateDumb => handle_create_dumb(&mode_state, arg, &ctx),
        IoctlCmd::ModeMapDumb => handle_map_dumb(&mode_state, arg, &ctx),
        IoctlCmd::ModeDestroyDumb => handle_destroy_dumb(&mode_state, arg, &ctx),
        // SETCRTC / PAGE_FLIP — blit dumb buffer into the active scanout.
        IoctlCmd::ModeSetCrtc => handle_setcrtc(card_index, &mode_state, arg, &ctx),
        IoctlCmd::ModePageFlip => handle_page_flip(card_index, &mode_state, arg, &ctx, events),
        // CURSOR / CURSOR2 — no hardware cursor plane; funnel the pointer
        // position + visibility into narf_console so narf_fb's cursor
        // renderer composites a sprite onto the scanout. Without this the
        // compositor's pointer is invisible (the ioctl would otherwise be a
        // silent no-op through the generic path).
        IoctlCmd::ModeCursor => handle_cursor(arg, false),
        IoctlCmd::ModeCursor2 => handle_cursor(arg, true),
        // GEM_CLOSE — free dumb backing if present.
        IoctlCmd::GemClose => handle_gem_close(&mode_state, arg, &ctx),
        // Everything else: copy a generic buffer in, hand to the
        // generic dispatcher, copy results back. A few ioctls have
        // pure-output (no input bytes); those still funnel through the
        // generic path.
        _ => handle_generic(&mode_state, cmd, arg, &ctx),
    }
}

// ── Per-ioctl handlers ───────────────────────────────────────────────

/// DRM_IOCTL_VERSION: kernel writes driver identity into user-supplied
/// out-buffers (`name_ptr`, `date_ptr`, `desc_ptr`) and updates the
/// `_len` fields with the byte counts actually written.
fn handle_version(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // Read the user struct.
    // SAFETY: `arg` is the ioctl argument pointer validated by the syscall
    // trap layer (or a kernel-owned pointer on the test path); we request
    // exactly `size_of::<DrmVersionUapi>()` bytes, which `copy_in` bounds-
    // checks against `IOCTL_MAX_BUF` before copying.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmVersionUapi>())? };
    let mut req: DrmVersionUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmVersionUapi>()` bytes, so the read of one
        // `DrmVersionUapi` stays within the allocation. `read_unaligned` is
        // used because `bytes`' allocation has only `u8` alignment.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmVersionUapi) };

    // Run the generic dispatcher to get the filled in version struct.
    let v = {
        let mut card_guard = mode_state.lock();
        let result = dispatch(&mut card_guard, 0x00, &[], ctx).map_err(map_err)?;
        match result {
            DrmIoctlResult::Version(v) => v,
            _ => return Err(FsError::Unsupported),
        }
    };

    // Write the driver name / date / desc into the user buffers,
    // truncated to whatever capacity the user supplied. Then write
    // back the actual lengths so user-space knows how much landed.
    let name = c_str_bytes(&v.name);
    let date = c_str_bytes(&v.date);
    let desc = c_str_bytes(&v.desc);

    if req.name != 0 && req.name_len > 0 {
        let cap = req.name_len as usize;
        let n = name.len().min(cap);
        // SAFETY: `req.name` is the user-supplied out-pointer and is non-
        // null here; we write at most `cap` (= `req.name_len`) bytes, the
        // capacity the user advertised, so the copy stays within the
        // user-provided buffer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            copy_out(req.name as usize, &name[..n])?;
        }
    }
    if req.date != 0 && req.date_len > 0 {
        let cap = req.date_len as usize;
        let n = date.len().min(cap);
        // SAFETY: `req.date` is the user-supplied out-pointer and is non-
        // null here; we write at most `cap` (= `req.date_len`) bytes, the
        // capacity the user advertised, so the copy stays in bounds.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            copy_out(req.date as usize, &date[..n])?;
        }
    }
    if req.desc != 0 && req.desc_len > 0 {
        let cap = req.desc_len as usize;
        let n = desc.len().min(cap);
        // SAFETY: `req.desc` is the user-supplied out-pointer and is non-
        // null here; we write at most `cap` (= `req.desc_len`) bytes, the
        // capacity the user advertised, so the copy stays in bounds.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            copy_out(req.desc as usize, &desc[..n])?;
        }
    }
    req.name_len = name.len() as u64;
    req.date_len = date.len() as u64;
    req.desc_len = desc.len() as u64;
    req.version_major = v.version_major;
    req.version_minor = v.version_minor;
    req.version_patchlevel = v.version_patchlevel;

    let out_bytes: [u8; core::mem::size_of::<DrmVersionUapi>()] =
        // SAFETY: `DrmVersionUapi` is a `#[repr(C)]` POD of plain integer
        // fields with no padding-dependent invariants, so reinterpreting its
        // bytes as a `[u8; size_of::<DrmVersionUapi>()]` array is sound; the
        // source and destination have identical size by construction.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::mem::transmute(req) };
    // SAFETY: `arg` is the same user/kernel out-pointer validated for the
    // input copy above; we write exactly `size_of::<DrmVersionUapi>()`
    // bytes, the size the user struct occupies.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_GETRESOURCES — fill counts + (if user pointers
/// supplied) write per-object id arrays.
fn handle_getresources(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the ioctl argument pointer validated by the syscall
    // trap layer (or kernel-owned on the test path); we request exactly
    // `size_of::<DrmModeCardResUapi>()` bytes, bounds-checked by `copy_in`.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCardResUapi>())? };
    let mut req: DrmModeCardResUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmModeCardResUapi>()` bytes, so reading one
        // `DrmModeCardResUapi` stays within the allocation; `read_unaligned`
        // matches the `u8` alignment of the backing buffer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeCardResUapi) };

    let mut card_guard = mode_state.lock();
    // Run the existing dispatch path for the count fields.
    let result = dispatch(&mut card_guard, 0xA0, &[], ctx).map_err(map_err)?;
    let res = match result {
        DrmIoctlResult::GetResources(r) => r,
        _ => return Err(FsError::Unsupported),
    };
    // Re-borrow the locked Card for the ID write helpers below.
    let card = &*card_guard;

    // Helper to write an id array to user memory iff (a) the user
    // supplied a non-null ptr and (b) the user-supplied count is
    // greater than zero.
    fn write_ids(
        uptr: u64,
        user_count: u32,
        ids: impl Iterator<Item = u32>,
    ) -> Result<(), FsError> {
        if uptr == 0 || user_count == 0 {
            return Ok(());
        }
        let cap = user_count as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(cap * 4);
        for (i, id) in ids.enumerate() {
            if i >= cap {
                break;
            }
            buf.extend_from_slice(&id.to_le_bytes());
        }
        // SAFETY: `uptr` is the user-supplied id-array out-pointer, non-null
        // (checked above); `buf` holds at most `cap` (= `user_count`) ids of
        // 4 bytes each, so we never write past the `user_count`-element
        // array the user advertised.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { copy_out(uptr as usize, &buf) }
    }

    write_ids(req.crtc_id_ptr, req.count_crtcs, card.crtc_ids())?;
    write_ids(
        req.connector_id_ptr,
        req.count_connectors,
        card.connector_ids(),
    )?;
    write_ids(req.encoder_id_ptr, req.count_encoders, card.encoder_ids())?;
    write_ids(
        req.fb_id_ptr,
        req.count_fbs,
        card.framebuffers.iter().map(|f| f.id),
    )?;

    // Write back the canonical counts + dims.
    req.count_fbs = res.count_fbs;
    req.count_crtcs = res.count_crtcs;
    req.count_connectors = res.count_connectors;
    req.count_encoders = res.count_encoders;
    req.min_width = res.min_width;
    req.max_width = res.max_width;
    req.min_height = res.min_height;
    req.max_height = res.max_height;
    drop(card_guard);

    let out_bytes: [u8; core::mem::size_of::<DrmModeCardResUapi>()] =
        // SAFETY: `DrmModeCardResUapi` is a `#[repr(C)]` POD of plain integer /
        // pointer-sized fields, so reinterpreting its bytes as a `[u8; N]`
        // array of the same size is sound.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::mem::transmute(req) };
    // SAFETY: `arg` is the validated user/kernel out-pointer from the input
    // copy above; we write exactly `size_of::<DrmModeCardResUapi>()` bytes.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// Serialise one `drm_mode_modeinfo` (68 bytes) into `out`.
/// Layout: clock u32, {h,v}* u16×10, vrefresh u32, flags u32, type u32,
/// name[32]. `DrmModeModeInfo` isn't repr(C), so we lay it out by hand.
fn mode_to_bytes(m: &crate::drm::ioctl::DrmModeModeInfo) -> [u8; 68] {
    let mut b = [0u8; 68];
    b[0..4].copy_from_slice(&m.clock.to_le_bytes());
    let u16s = [
        m.hdisplay,
        m.hsync_start,
        m.hsync_end,
        m.htotal,
        m.hskew,
        m.vdisplay,
        m.vsync_start,
        m.vsync_end,
        m.vtotal,
        m.vscan,
    ];
    for (i, v) in u16s.iter().enumerate() {
        b[4 + i * 2..6 + i * 2].copy_from_slice(&v.to_le_bytes());
    }
    b[24..28].copy_from_slice(&m.vrefresh.to_le_bytes());
    b[28..32].copy_from_slice(&m.flags.to_le_bytes());
    b[32..36].copy_from_slice(&m.r#type.to_le_bytes());
    b[36..68].copy_from_slice(&m.name);
    b
}

/// DRM_IOCTL_MODE_GETCONNECTOR — connector info + the libdrm two-pass
/// count protocol: pass 1 (zero out-ptrs) returns counts; pass 2 (ptrs +
/// matching counts) fills the modes/encoders arrays. handle_generic can't
/// do this (it discards the result), so it's a dedicated handler.
///
/// Linux ref: `drivers/gpu/drm/drm_connector.c::drm_mode_getconnector`.
fn handle_getconnector(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // struct drm_mode_get_connector is 80 bytes. Read the user's
    // out-pointers + advertised counts before dispatch.
    // SAFETY: `arg` is the validated user/kernel ioctl pointer.
    let in_bytes = unsafe { copy_in(arg, 80)? };
    let rd = |o: usize| u64::from_le_bytes(in_bytes[o..o + 8].try_into().unwrap());
    let rd32 = |o: usize| u32::from_le_bytes(in_bytes[o..o + 4].try_into().unwrap());
    let encoders_ptr = rd(0);
    let modes_ptr = rd(8);
    let props_ptr = rd(16);
    let prop_values_ptr = rd(24);
    let user_count_modes = rd32(32);
    let user_count_props = rd32(36);
    let user_count_encoders = rd32(40);

    let result = {
        let mut card = mode_state.lock();
        dispatch(&mut card, 0xA7, &in_bytes, ctx).map_err(map_err)?
    };
    let (info, modes) = match result {
        DrmIoctlResult::GetConnector(i, m) => (i, m),
        _ => return Err(FsError::Unsupported),
    };

    // Pass 2: fill the modes array when the user gave a buffer big enough.
    if modes_ptr != 0 && (user_count_modes as usize) >= modes.len() && !modes.is_empty() {
        let mut buf: Vec<u8> = Vec::with_capacity(modes.len() * 68);
        for m in &modes {
            buf.extend_from_slice(&mode_to_bytes(m));
        }
        // SAFETY: user-supplied modes_ptr, sized for >= modes.len() entries.
        unsafe { copy_out(modes_ptr as usize, &buf)? };
    }
    // Single encoder id into the encoders array.
    if encoders_ptr != 0 && user_count_encoders >= 1 && info.encoder_id != 0 {
        // SAFETY: user-supplied encoders_ptr with >= 1 slot.
        unsafe { copy_out(encoders_ptr as usize, &info.encoder_id.to_le_bytes())? };
    }

    // Connector properties: immutable EDID plus atomic CRTC_ID. libdrm runs the same
    // two-pass count protocol as modes/encoders, so fill the id (u32) + value
    // (u64 blob id) arrays only once the caller has sized them.
    if props_ptr != 0 && prop_values_ptr != 0 && user_count_props >= 2 {
        let crtc_id = {
            let card = mode_state.lock();
            card.encoder(info.encoder_id)
                .ok()
                .and_then(|encoder| encoder.crtc_id)
                .unwrap_or(0)
        };
        let mut prop_ids = [0u8; 8];
        prop_ids[0..4].copy_from_slice(&EDID_PROP_ID.to_le_bytes());
        prop_ids[4..8].copy_from_slice(&CONNECTOR_CRTC_ID_PROP_ID.to_le_bytes());
        let mut prop_values = [0u8; 16];
        prop_values[0..8].copy_from_slice(&(edid_blob_id(info.connector_id) as u64).to_le_bytes());
        prop_values[8..16].copy_from_slice(&(crtc_id as u64).to_le_bytes());
        // SAFETY: both are user out-pointers the caller sized for >= 2 entries
        // after the counting pass; the id array is u32, the value array u64.
        unsafe {
            copy_out(props_ptr as usize, &prop_ids)?;
            copy_out(prop_values_ptr as usize, &prop_values)?;
        }
    }

    // Write the struct back, preserving the user's out-pointers (first 32
    // bytes) and updating counts + connector fields (offsets 32..76).
    let mut out = in_bytes;
    out[32..36].copy_from_slice(&info.count_modes.to_le_bytes());
    out[36..40].copy_from_slice(&2u32.to_le_bytes()); // EDID + CRTC_ID
    out[40..44].copy_from_slice(&info.count_encoders.to_le_bytes());
    out[44..48].copy_from_slice(&info.encoder_id.to_le_bytes());
    out[48..52].copy_from_slice(&info.connector_id.to_le_bytes());
    out[52..56].copy_from_slice(&info.connector_type.to_le_bytes());
    out[56..60].copy_from_slice(&info.connector_type_id.to_le_bytes());
    out[60..64].copy_from_slice(&info.connection.to_le_bytes());
    out[64..68].copy_from_slice(&info.mm_width.to_le_bytes());
    out[68..72].copy_from_slice(&info.mm_height.to_le_bytes());
    out[72..76].copy_from_slice(&info.subpixel.to_le_bytes());
    // SAFETY: `arg` is the validated user/kernel out-pointer (80 bytes).
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETENCODER — struct drm_mode_get_encoder (20 bytes):
/// encoder_id, encoder_type, crtc_id, possible_crtcs, possible_clones.
///
/// Linux ref: `drivers/gpu/drm/drm_encoder.c::drm_mode_getencoder`.
fn handle_getencoder(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated user/kernel ioctl pointer (20 bytes).
    let in_bytes = unsafe { copy_in(arg, 20)? };
    let encoder_id = u32::from_le_bytes(in_bytes[0..4].try_into().unwrap());
    let mut out = [0u8; 20];
    {
        let card = mode_state.lock();
        let enc = card.encoder(encoder_id).map_err(|_| FsError::InvalidData)?;
        out[0..4].copy_from_slice(&enc.id.to_le_bytes());
        out[4..8].copy_from_slice(&(enc.encoder_type as u32).to_le_bytes());
        out[8..12].copy_from_slice(&enc.crtc_id.unwrap_or(0).to_le_bytes());
        out[12..16].copy_from_slice(&enc.possible_crtcs.to_le_bytes());
        out[16..20].copy_from_slice(&enc.possible_clones.to_le_bytes());
    }
    // SAFETY: `arg` is the validated user/kernel out-pointer (20 bytes).
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETCRTC — struct drm_mode_crtc (104 bytes). Reports the
/// crtc's current fb/x/y/mode; `set_connectors_ptr`/`count_connectors` are
/// input-only (zero on a get) and preserved.
///
/// Linux ref: `drivers/gpu/drm/drm_crtc.c::drm_mode_getcrtc`.
fn handle_getcrtc(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated user/kernel ioctl pointer (104 bytes).
    let in_bytes = unsafe { copy_in(arg, 104)? };
    let crtc_id = u32::from_le_bytes(in_bytes[12..16].try_into().unwrap());
    let mut out = in_bytes;
    {
        let card = mode_state.lock();
        let crtc = card.crtc(crtc_id).map_err(|_| FsError::InvalidData)?;
        out[12..16].copy_from_slice(&crtc.id.to_le_bytes());
        out[16..20].copy_from_slice(&crtc.primary_fb.unwrap_or(0).to_le_bytes()); // fb_id
        out[20..24].copy_from_slice(&crtc.x.to_le_bytes());
        out[24..28].copy_from_slice(&crtc.y.to_le_bytes());
        out[28..32].copy_from_slice(&0u32.to_le_bytes()); // gamma_size
        let mode_valid: u32 = crtc.mode.is_some() as u32;
        out[32..36].copy_from_slice(&mode_valid.to_le_bytes());
        match &crtc.mode {
            Some(m) => {
                let wire = crate::drm::ioctl::mode_to_wire(m);
                out[36..104].copy_from_slice(&mode_to_bytes(&wire));
            }
            None => out[36..104].fill(0),
        }
    }
    // SAFETY: `arg` is the validated user/kernel out-pointer (104 bytes).
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_SET_CLIENT_CAP — `struct drm_set_client_cap { __u64
/// capability; __u64 value; }` (16 bytes).
///
/// We mirror Linux `drm_setclientcap` for a driver WITHOUT `DRIVER_ATOMIC`:
/// the pure client opt-in flags that need no driver support are accepted
/// (STEREO_3D, UNIVERSAL_PLANES, ASPECT_RATIO), with `value > 1` rejected
/// as EINVAL exactly as Linux does. ATOMIC and WRITEBACK_CONNECTORS require
/// atomic modeset, which narf-drm lacks, so they're rejected — weston then
/// drives modeset through the legacy SETCRTC path. UNIVERSAL_PLANES is the
/// one weston hard-requires (it enumerates the primary plane through it).
///
/// Linux ref: `drivers/gpu/drm/drm_ioctl.c::drm_setclientcap`.
fn handle_set_client_cap(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    client_caps: &DrmClientCaps,
) -> Result<u64, FsError> {
    // include/uapi/drm/drm.h DRM_CLIENT_CAP_*.
    const DRM_CLIENT_CAP_STEREO_3D: u64 = 1;
    const DRM_CLIENT_CAP_UNIVERSAL_PLANES: u64 = 2;
    const DRM_CLIENT_CAP_ATOMIC: u64 = 3;
    const DRM_CLIENT_CAP_ASPECT_RATIO: u64 = 4;
    const DRM_CLIENT_CAP_WRITEBACK_CONNECTORS: u64 = 5;
    const DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT: u64 = 6;
    const DRM_CLIENT_CAP_PLANE_COLOR_PIPELINE: u64 = 7;
    // SAFETY: `arg` is the validated 16-byte ioctl argument pointer.
    let bytes = unsafe { copy_in(arg, 16)? };
    let cap = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let value = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    match cap {
        DRM_CLIENT_CAP_STEREO_3D
        | DRM_CLIENT_CAP_UNIVERSAL_PLANES
        | DRM_CLIENT_CAP_ASPECT_RATIO => {
            // Boolean opt-in: Linux rejects any value > 1.
            if value > 1 {
                Err(FsError::InvalidData)
            } else {
                Ok(0)
            }
        }
        DRM_CLIENT_CAP_ATOMIC => {
            if mode_state.lock().driver_name != "virtio_gpu" {
                // Linux returns EOPNOTSUPP when DRIVER_ATOMIC is absent.
                return Err(FsError::Unsupported);
            }
            if value > 2 {
                Err(FsError::InvalidData)
            } else {
                client_caps.set_atomic(value != 0);
                Ok(0)
            }
        }
        DRM_CLIENT_CAP_WRITEBACK_CONNECTORS | DRM_CLIENT_CAP_PLANE_COLOR_PIPELINE => {
            if !client_caps.atomic() {
                return Err(FsError::InvalidData);
            }
            if value > 1 {
                Err(FsError::InvalidData)
            } else {
                Ok(0)
            }
        }
        DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT => {
            // Linux virtio-gpu advertises DRIVER_CURSOR_HOTSPOT. The feature
            // check precedes the per-file ATOMIC/value checks, fixing the
            // exact EOPNOTSUPP/EINVAL ordering in drm_setclientcap().
            if mode_state.lock().driver_name != "virtio_gpu" {
                return Err(FsError::Unsupported);
            }
            if !client_caps.atomic() || value > 1 {
                return Err(FsError::InvalidData);
            }
            Ok(0)
        }
        _ => Err(FsError::InvalidData),
    }
}

// ── Universal planes (legacy-modeset minimum) ─────────────────────────
//
// weston's drm-backend enumerates a CRTC's PRIMARY plane through the
// universal-planes UAPI even on the legacy modeset path — without it,
// `Failed to find primary plane for output` and the output won't enable.
// narf-drm has no real plane objects, so synthesise exactly one immutable
// PRIMARY plane per CRTC: plane `PLANE_ID_BASE + i` serves CRTC index `i`
// (possible_crtcs = 1<<i). Linux ref: drivers/gpu/drm/drm_plane.c.
const PLANE_ID_BASE: u32 = 0x40;
/// Property id of the plane "type" enum (a separate id space from objects).
const PLANE_TYPE_PROP_ID: u32 = 0x50;
const CRTC_ACTIVE_PROP_ID: u32 = 0x52;
/// `OUT_FENCE_PTR` on a CRTC: a userspace `s32*` filled with a sync_file
/// fd whose fence signals at the commit's simulated vblank.
const CRTC_OUT_FENCE_PTR_PROP_ID: u32 = 0x60;
/// `IN_FENCE_FD` on a plane: a sync_file fd (-1 = none) gating the flip.
const PLANE_IN_FENCE_FD_PROP_ID: u32 = 0x5f;
const CRTC_MODE_ID_PROP_ID: u32 = 0x53;
const CONNECTOR_CRTC_ID_PROP_ID: u32 = 0x54;
const PLANE_FB_ID_PROP_ID: u32 = 0x55;
const PLANE_CRTC_ID_PROP_ID: u32 = 0x56;
const PLANE_SRC_X_PROP_ID: u32 = 0x57;
const PLANE_SRC_Y_PROP_ID: u32 = 0x58;
const PLANE_SRC_W_PROP_ID: u32 = 0x59;
const PLANE_SRC_H_PROP_ID: u32 = 0x5a;
const PLANE_CRTC_X_PROP_ID: u32 = 0x5b;
const PLANE_CRTC_Y_PROP_ID: u32 = 0x5c;
const PLANE_CRTC_W_PROP_ID: u32 = 0x5d;
const PLANE_CRTC_H_PROP_ID: u32 = 0x5e;
const DRM_PLANE_TYPE_PRIMARY: u64 = 1;
const DRM_MODE_PROP_RANGE: u32 = 1 << 1;
const DRM_MODE_PROP_IMMUTABLE: u32 = 1 << 2;
const DRM_MODE_PROP_ENUM: u32 = 1 << 3;
const DRM_MODE_PROP_BLOB: u32 = 1 << 4;
const DRM_MODE_PROP_OBJECT: u32 = 1 << 6;
const DRM_MODE_PROP_SIGNED_RANGE: u32 = 1 << 7;
const DRM_MODE_PROP_ATOMIC: u32 = 0x8000_0000;
/// Property id of the connector "EDID" immutable blob (own id space, distinct
/// from `PLANE_TYPE_PROP_ID`). Compositors read this to fetch the display's
/// EDID via GETPROPBLOB; a synthetic connector otherwise reports none and kwin
/// logs `Could not find edid for connector`.
const EDID_PROP_ID: u32 = 0x51;
/// `DRM_MODE_OBJECT_CONNECTOR` — object-type tag OBJ_GETPROPERTIES passes for a
/// connector (`include/uapi/drm/drm_mode.h`).
const DRM_MODE_OBJECT_CONNECTOR: u32 = 0xc0c0_c0c0;
const DRM_MODE_OBJECT_CRTC: u32 = 0xcccc_cccc;
const DRM_MODE_OBJECT_PLANE: u32 = 0xeeee_eeee;

/// Stable blob id carrying a connector's EDID. One blob per connector, derived
/// from the connector id so GETPROPBLOB can regenerate it statelessly.
fn edid_blob_id(connector_id: u32) -> u32 {
    0x1000 | (connector_id & 0xFFF)
}

/// Reverse of [`edid_blob_id`]: the connector id a blob id refers to, if it is
/// one of our EDID blobs.
fn connector_id_from_edid_blob(blob_id: u32) -> Option<u32> {
    if blob_id & 0xFFFF_F000 == 0x1000 {
        Some(blob_id & 0xFFF)
    } else {
        None
    }
}

/// Generate the EDID bytes for a connector from its preferred (first) mode.
/// `None` if the connector has no id / no modes.
fn connector_edid(card: &crate::drm::card::Card, connector_id: u32) -> Option<[u8; 128]> {
    let conn = card.connector(connector_id).ok()?;
    let m = conn.modes.first()?;
    Some(crate::drm::edid_gen::synth_edid(
        m.width,
        m.height,
        m.refresh_hz as u32,
    ))
}
/// DRM_FORMAT_XRGB8888 — the one scanout format the pixman path uses.
const DRM_FORMAT_XRGB8888: u32 = 0x3432_5258;

/// `(plane_id, crtc_index)` for the synthesised primary planes.
fn synth_planes(card: &crate::drm::card::Card) -> alloc::vec::Vec<(u32, u32)> {
    (0..card.crtcs.len() as u32)
        .map(|i| (PLANE_ID_BASE + i, i))
        .collect()
}

/// DRM_IOCTL_MODE_GETPLANERESOURCES — `struct drm_mode_get_plane_res
/// { __u64 plane_id_ptr; __u32 count_planes; }` (16 bytes). Two-pass:
/// fill the id array iff the caller's count is large enough, always
/// report the real count.
fn handle_getplane_res(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated 16-byte ioctl pointer.
    let mut bytes = unsafe { copy_in(arg, 16)? };
    let plane_id_ptr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let user_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let planes = synth_planes(&mode_state.lock());
    if plane_id_ptr != 0 && user_count as usize >= planes.len() {
        let mut buf: Vec<u8> = Vec::with_capacity(planes.len() * 4);
        for (id, _) in &planes {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        // SAFETY: `plane_id_ptr` is the user out-array; we write exactly
        // `planes.len()` <= `user_count` ids of 4 bytes each.
        unsafe { copy_out(plane_id_ptr as usize, &buf)? };
    }
    bytes[8..12].copy_from_slice(&(planes.len() as u32).to_le_bytes());
    // SAFETY: `arg` is the validated 16-byte out-pointer.
    unsafe { copy_out(arg, &bytes)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETPLANE — `struct drm_mode_get_plane` (32 bytes):
/// plane_id, crtc_id, fb_id, possible_crtcs, gamma_size,
/// count_format_types, format_type_ptr.
fn handle_getplane(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated 32-byte ioctl pointer.
    let mut out = unsafe { copy_in(arg, 32)? };
    let plane_id = u32::from_le_bytes(out[0..4].try_into().unwrap());
    let user_fmt_count = u32::from_le_bytes(out[20..24].try_into().unwrap());
    let fmt_ptr = u64::from_le_bytes(out[24..32].try_into().unwrap());
    let possible_crtcs = {
        let card = mode_state.lock();
        match synth_planes(&card)
            .into_iter()
            .find(|(id, _)| *id == plane_id)
        {
            Some((_, crtc_idx)) => 1u32 << crtc_idx,
            None => return Err(FsError::InvalidData),
        }
    };
    out[4..8].copy_from_slice(&0u32.to_le_bytes()); // crtc_id (unbound)
    out[8..12].copy_from_slice(&0u32.to_le_bytes()); // fb_id
    out[12..16].copy_from_slice(&possible_crtcs.to_le_bytes());
    out[16..20].copy_from_slice(&0u32.to_le_bytes()); // gamma_size

    // One supported format (XRGB8888); fill the array two-pass.
    if fmt_ptr != 0 && user_fmt_count >= 1 {
        // SAFETY: `fmt_ptr` is the user format-array out-pointer with room
        // for >=1 u32 (checked above).
        unsafe { copy_out(fmt_ptr as usize, &DRM_FORMAT_XRGB8888.to_le_bytes())? };
    }
    out[20..24].copy_from_slice(&1u32.to_le_bytes()); // count_format_types

    // SAFETY: `arg` is the validated 32-byte out-pointer.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETPROPERTY — `struct drm_mode_get_property` (size from
/// the ioctl). We only describe the plane "type" enum property. weston
/// reads its `name` ("type") to identify the primary plane; the enum
/// entries (Overlay/Primary/Cursor) round out a well-formed reply.
fn handle_getproperty(arg: usize) -> Result<u64, FsError> {
    // struct drm_mode_get_property:
    //   u64 values_ptr;        // 0   (enum entries write here for ENUM props)
    //   u64 enum_blob_ptr;     // 8
    //   u32 prop_id;           // 16  (in)
    //   u32 flags;             // 20  (out)
    //   char name[32];         // 24  (out)
    //   u32 count_values;      // 56  (in/out)
    //   u32 count_enum_blobs;  // 60  (in/out)
    // = 64 bytes.
    // SAFETY: `arg` is the validated 64-byte ioctl pointer.
    let mut out = unsafe { copy_in(arg, 64)? };
    let prop_id = u32::from_le_bytes(out[16..20].try_into().unwrap());
    // The connector "EDID" property: an immutable blob. It carries no enum /
    // range values, so both counts stay 0; the bytes are fetched separately via
    // GETPROPBLOB using the blob id GETCONNECTOR reported as this prop's value.
    if prop_id == EDID_PROP_ID {
        out[20..24].copy_from_slice(&(DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE).to_le_bytes());
        out[24..56].fill(0);
        let name = b"EDID";
        out[24..24 + name.len()].copy_from_slice(name);
        out[56..60].copy_from_slice(&0u32.to_le_bytes()); // count_values
        out[60..64].copy_from_slice(&0u32.to_le_bytes()); // count_enum_blobs
                                                          // SAFETY: `arg` is the validated 64-byte out-pointer.
        unsafe { copy_out(arg, &out)? };
        return Ok(0);
    }

    fn write_simple_property(
        out: &mut [u8],
        name: &[u8],
        flags: u32,
        values: &[u64],
    ) -> Result<(), FsError> {
        out[20..24].copy_from_slice(&flags.to_le_bytes());
        out[24..56].fill(0);
        out[24..24 + name.len().min(31)].copy_from_slice(&name[..name.len().min(31)]);
        let values_ptr = u64::from_le_bytes(out[0..8].try_into().unwrap());
        let user_values_count = u32::from_le_bytes(out[56..60].try_into().unwrap());
        if values_ptr != 0 && user_values_count as usize >= values.len() && !values.is_empty() {
            let mut bytes = Vec::with_capacity(values.len() * 8);
            for value in values {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            // SAFETY: the caller's value array advertises at least
            // `values.len()` u64 slots.
            unsafe { copy_out(values_ptr as usize, &bytes)? };
        }
        out[56..60].copy_from_slice(&(values.len() as u32).to_le_bytes());
        out[60..64].copy_from_slice(&0u32.to_le_bytes());
        Ok(())
    }

    let simple = match prop_id {
        CRTC_ACTIVE_PROP_ID => Some((
            b"ACTIVE".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC,
            [0, 1],
        )),
        CRTC_MODE_ID_PROP_ID => Some((
            b"MODE_ID".as_slice(),
            DRM_MODE_PROP_BLOB | DRM_MODE_PROP_ATOMIC,
            [0, 0],
        )),
        CONNECTOR_CRTC_ID_PROP_ID | PLANE_CRTC_ID_PROP_ID => Some((
            b"CRTC_ID".as_slice(),
            DRM_MODE_PROP_OBJECT | DRM_MODE_PROP_ATOMIC,
            [DRM_MODE_OBJECT_CRTC as u64, 0],
        )),
        PLANE_FB_ID_PROP_ID => Some((
            b"FB_ID".as_slice(),
            DRM_MODE_PROP_OBJECT | DRM_MODE_PROP_ATOMIC,
            [0xfbfb_fbfb, 0],
        )),
        PLANE_SRC_X_PROP_ID => Some((
            b"SRC_X".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC,
            [0, u32::MAX as u64],
        )),
        PLANE_SRC_Y_PROP_ID => Some((
            b"SRC_Y".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC,
            [0, u32::MAX as u64],
        )),
        PLANE_SRC_W_PROP_ID => Some((
            b"SRC_W".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC,
            [0, u32::MAX as u64],
        )),
        PLANE_SRC_H_PROP_ID => Some((
            b"SRC_H".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC,
            [0, u32::MAX as u64],
        )),
        PLANE_CRTC_X_PROP_ID => Some((
            b"CRTC_X".as_slice(),
            DRM_MODE_PROP_SIGNED_RANGE | DRM_MODE_PROP_ATOMIC,
            [i32::MIN as i64 as u64, i32::MAX as u64],
        )),
        PLANE_CRTC_Y_PROP_ID => Some((
            b"CRTC_Y".as_slice(),
            DRM_MODE_PROP_SIGNED_RANGE | DRM_MODE_PROP_ATOMIC,
            [i32::MIN as i64 as u64, i32::MAX as u64],
        )),
        PLANE_CRTC_W_PROP_ID => Some((
            b"CRTC_W".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC,
            [0, u32::MAX as u64],
        )),
        PLANE_CRTC_H_PROP_ID => Some((
            b"CRTC_H".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC,
            [0, u32::MAX as u64],
        )),
        // Explicit-fencing pair (drm_atomic_uapi.c "Explicit Fencing
        // Properties"): IN_FENCE_FD is a signed range accepting -1 (no
        // fence) through INT_MAX; OUT_FENCE_PTR is a full-range integer
        // carrying a userspace pointer.
        PLANE_IN_FENCE_FD_PROP_ID => Some((
            b"IN_FENCE_FD".as_slice(),
            DRM_MODE_PROP_SIGNED_RANGE | DRM_MODE_PROP_ATOMIC,
            [(-1i64) as u64, i32::MAX as u64],
        )),
        CRTC_OUT_FENCE_PTR_PROP_ID => Some((
            b"OUT_FENCE_PTR".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC,
            [0, u64::MAX],
        )),
        _ => None,
    };
    if let Some((name, flags, values)) = simple {
        // Linux object properties expose one value: the accepted DRM object
        // type.  The property's current object ID lives in
        // DRM_IOCTL_MODE_OBJ_GETPROPERTIES, not in this metadata array.
        let values = if flags & DRM_MODE_PROP_BLOB != 0 {
            &values[..0]
        } else if flags & DRM_MODE_PROP_OBJECT != 0 {
            &values[..1]
        } else {
            &values[..]
        };
        write_simple_property(&mut out, name, flags, values)?;
        // SAFETY: `arg` is the validated 64-byte out-pointer.
        unsafe { copy_out(arg, &out)? };
        return Ok(0);
    }
    if prop_id != PLANE_TYPE_PROP_ID {
        return Err(FsError::InvalidData);
    }
    out[20..24].copy_from_slice(&(DRM_MODE_PROP_ENUM | DRM_MODE_PROP_IMMUTABLE).to_le_bytes());
    out[24..56].fill(0);
    let name = b"type";
    out[24..24 + name.len()].copy_from_slice(name);
    // For an ENUM property the entries go to ENUM_BLOB_PTR (offset 8) and
    // are counted by count_enum_blobs (offset 60); values_ptr/count_values
    // (offsets 0 and 56) MUST ALSO be populated with the valid enum values.
    // `modetest` iterates over both and asserts they are present.
    // Each enum entry is `drm_mode_property_enum { __u64 value; char name[32]; }` = 40 bytes.
    let enums: [(u64, &[u8]); 3] = [(0, b"Overlay"), (1, b"Primary"), (2, b"Cursor")];

    let values_ptr = u64::from_le_bytes(out[0..8].try_into().unwrap());
    let user_values_count = u32::from_le_bytes(out[56..60].try_into().unwrap());
    if values_ptr != 0 && user_values_count as usize >= enums.len() {
        let mut buf = alloc::vec![0u8; enums.len() * 8];
        for (i, (val, _)) in enums.iter().enumerate() {
            buf[i * 8..i * 8 + 8].copy_from_slice(&val.to_le_bytes());
        }
        // SAFETY: `values_ptr` is the user array out-pointer sized
        // for `user_values_count` >= 3 entries of 8 bytes each.
        unsafe { copy_out(values_ptr as usize, &buf)? };
    }

    let enum_blob_ptr = u64::from_le_bytes(out[8..16].try_into().unwrap());
    let user_enum_count = u32::from_le_bytes(out[60..64].try_into().unwrap());
    if enum_blob_ptr != 0 && user_enum_count as usize >= enums.len() {
        let mut buf = alloc::vec![0u8; enums.len() * 40];
        for (i, (val, nm)) in enums.iter().enumerate() {
            let base = i * 40;
            buf[base..base + 8].copy_from_slice(&val.to_le_bytes());
            buf[base + 8..base + 8 + nm.len()].copy_from_slice(nm);
        }
        // SAFETY: `enum_blob_ptr` is the user enum-array out-pointer sized
        // for `user_enum_count` >= 3 entries of 40 bytes each.
        unsafe { copy_out(enum_blob_ptr as usize, &buf)? };
    }
    out[56..60].copy_from_slice(&(enums.len() as u32).to_le_bytes()); // count_values
    out[60..64].copy_from_slice(&(enums.len() as u32).to_le_bytes()); // count_enum_blobs

    // SAFETY: `arg` is the validated 64-byte out-pointer.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETPROPBLOB — `struct drm_mode_get_blob` (16 bytes):
/// blob_id@0, length@4, data@8. Two-pass like the other array ioctls: the
/// first call (length 0 / data NULL) reports the blob's byte length; the second
/// (data sized to length) receives the bytes. We serve only connector EDID
/// blobs, regenerated from the connector's preferred mode.
///
/// Linux ref: `drivers/gpu/drm/drm_property.c::drm_mode_getblob_ioctl`.
fn handle_getpropblob(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated 16-byte ioctl pointer.
    let mut out = unsafe { copy_in(arg, 16)? };
    let blob_id = u32::from_le_bytes(out[0..4].try_into().unwrap());
    let user_len = u32::from_le_bytes(out[4..8].try_into().unwrap());
    let data_ptr = u64::from_le_bytes(out[8..16].try_into().unwrap());

    let connector_id = connector_id_from_edid_blob(blob_id).ok_or(FsError::InvalidData)?;
    let edid = {
        let card = mode_state.lock();
        connector_edid(&card, connector_id).ok_or(FsError::InvalidData)?
    };

    // Second pass: copy the bytes out when the caller sized its buffer.
    if data_ptr != 0 && user_len as usize >= edid.len() {
        // SAFETY: user-supplied `data_ptr` the caller sized for >= edid.len().
        unsafe { copy_out(data_ptr as usize, &edid)? };
    }
    // Always report the true length (drives the caller's allocation).
    out[4..8].copy_from_slice(&(edid.len() as u32).to_le_bytes());
    // SAFETY: `arg` is the validated 16-byte out-pointer.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_OBJ_GETPROPERTIES — `struct drm_mode_obj_get_properties`
/// (28 bytes): props_ptr, prop_values_ptr, count_props@16, obj_id@20,
/// obj_type@24. A synthesised plane carries exactly one property — the
/// immutable "type" = PRIMARY that weston reads to pick a primary plane.
/// Every other object exposes none (`count_props = 0`); returning ENOTTY
/// made libdrm hand modetest a NULL property set it dereferenced (SIGSEGV).
///
/// Linux ref: `drivers/gpu/drm/drm_mode_object.c::drm_mode_obj_get_properties_ioctl`.
fn handle_obj_getproperties(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated 28-byte ioctl pointer.
    let mut bytes = unsafe { copy_in(arg, 28)? };
    let props_ptr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let values_ptr = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let user_count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let obj_id = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let obj_type = u32::from_le_bytes(bytes[24..28].try_into().unwrap());

    let (props, values): (Vec<u32>, Vec<u64>) = {
        let card = mode_state.lock();
        if obj_type == DRM_MODE_OBJECT_PLANE {
            let Some((_, crtc_idx)) = synth_planes(&card)
                .into_iter()
                .find(|(id, _)| *id == obj_id)
            else {
                return Err(FsError::InvalidData);
            };
            let crtc = &card.crtcs[crtc_idx as usize];
            let fb = crtc.primary_fb.and_then(|id| card.framebuffer(id).ok());
            let width = fb
                .map(|f| f.width)
                .or_else(|| crtc.mode.map(|m| m.width))
                .unwrap_or(0);
            let height = fb
                .map(|f| f.height)
                .or_else(|| crtc.mode.map(|m| m.height))
                .unwrap_or(0);
            (
                vec![
                    PLANE_TYPE_PROP_ID,
                    PLANE_FB_ID_PROP_ID,
                    PLANE_CRTC_ID_PROP_ID,
                    PLANE_SRC_X_PROP_ID,
                    PLANE_SRC_Y_PROP_ID,
                    PLANE_SRC_W_PROP_ID,
                    PLANE_SRC_H_PROP_ID,
                    PLANE_CRTC_X_PROP_ID,
                    PLANE_CRTC_Y_PROP_ID,
                    PLANE_CRTC_W_PROP_ID,
                    PLANE_CRTC_H_PROP_ID,
                    PLANE_IN_FENCE_FD_PROP_ID,
                ],
                vec![
                    DRM_PLANE_TYPE_PRIMARY,
                    crtc.primary_fb.unwrap_or(0) as u64,
                    if crtc.primary_fb.is_some() {
                        crtc.id as u64
                    } else {
                        0
                    },
                    (crtc.x as u64) << 16,
                    (crtc.y as u64) << 16,
                    (width as u64) << 16,
                    (height as u64) << 16,
                    crtc.x as u64,
                    crtc.y as u64,
                    width as u64,
                    height as u64,
                    // IN_FENCE_FD reads back as -1 (never a live fd),
                    // matching drm_atomic_plane_get_property.
                    (-1i64) as u64,
                ],
            )
        } else if obj_type == DRM_MODE_OBJECT_CRTC {
            let crtc = card.crtc(obj_id).map_err(|_| FsError::InvalidData)?;
            (
                vec![
                    CRTC_ACTIVE_PROP_ID,
                    CRTC_MODE_ID_PROP_ID,
                    CRTC_OUT_FENCE_PTR_PROP_ID,
                ],
                // OUT_FENCE_PTR reads back as 0 (write-only request),
                // matching drm_atomic_crtc_get_property.
                vec![crtc.enabled as u64, 0, 0],
            )
        } else if obj_type == DRM_MODE_OBJECT_CONNECTOR {
            let connector = card.connector(obj_id).map_err(|_| FsError::InvalidData)?;
            let crtc_id = connector
                .encoder_id
                .and_then(|id| card.encoder(id).ok())
                .and_then(|encoder| encoder.crtc_id)
                .unwrap_or(0);
            (
                vec![EDID_PROP_ID, CONNECTOR_CRTC_ID_PROP_ID],
                vec![edid_blob_id(obj_id) as u64, crtc_id as u64],
            )
        } else {
            return Err(FsError::InvalidData);
        }
    };
    if props_ptr != 0 && values_ptr != 0 && user_count as usize >= props.len() {
        let mut prop_bytes = Vec::with_capacity(props.len() * 4);
        let mut value_bytes = Vec::with_capacity(values.len() * 8);
        for prop in &props {
            prop_bytes.extend_from_slice(&prop.to_le_bytes());
        }
        for value in &values {
            value_bytes.extend_from_slice(&value.to_le_bytes());
        }
        // SAFETY: both arrays were advertised with at least `props.len()`
        // entries; property ids are u32 and values are u64.
        unsafe {
            copy_out(props_ptr as usize, &prop_bytes)?;
            copy_out(values_ptr as usize, &value_bytes)?;
        }
    }
    bytes[16..20].copy_from_slice(&(props.len() as u32).to_le_bytes());
    // SAFETY: `arg` is the validated 28-byte out-pointer.
    unsafe { copy_out(arg, &bytes)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_CREATEPROPBLOB — copy an opaque userspace payload into a
/// per-card blob and return its id. Atomic modesets use a 68-byte modeinfo.
fn handle_create_property_blob(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    if ctx.is_render_client() {
        return Err(FsError::PermissionDenied);
    }
    // struct drm_mode_create_blob { u64 data; u32 length; u32 blob_id }.
    // SAFETY: `arg` is the ioctl's fixed 16-byte in/out structure; `copy_in`
    // validates the complete userspace range before returning owned bytes.
    let mut bytes = unsafe { copy_in(arg, 16)? };
    let data_ptr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if len == 0 || len > IOCTL_MAX_BUF {
        return Err(FsError::InvalidData);
    }
    // SAFETY: length is non-zero and capped; copy_in returns EFAULT for NULL.
    let data = unsafe { copy_in(data_ptr as usize, len)? };
    let blob_id = mode_state
        .lock()
        .create_property_blob(data)
        .map_err(|_| FsError::OutOfMemory)?;
    bytes[12..16].copy_from_slice(&blob_id.to_le_bytes());
    // SAFETY: fixed 16-byte in/out structure.
    unsafe { copy_out(arg, &bytes)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_DESTROYPROPBLOB — unknown ids are ENOENT, matching Linux.
fn handle_destroy_property_blob(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    if ctx.is_render_client() {
        return Err(FsError::PermissionDenied);
    }
    // SAFETY: `arg` is the fixed four-byte destroy-blob request; `copy_in`
    // validates the complete userspace range.
    let bytes = unsafe { copy_in(arg, 4)? };
    let blob_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if mode_state.lock().destroy_property_blob(blob_id) {
        Ok(0)
    } else {
        Err(FsError::NotFound)
    }
}

/// DRM_IOCTL_MODE_LIST_LESSEES — NARF has no DRM leases, so a master sees an
/// empty list. `pad != 0` is EINVAL before any output, as in drm_lease.c.
fn handle_list_lessees(arg: usize, ctx: &DrmFileCtx) -> Result<u64, FsError> {
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }
    // struct drm_mode_list_lessees { u32 count_lessees; u32 pad; u64 ptr }.
    // SAFETY: `arg` is the ioctl's fixed 16-byte in/out structure; `copy_in`
    // validates the complete userspace range before returning owned bytes.
    let mut bytes = unsafe { copy_in(arg, 16)? };
    if u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != 0 {
        return Err(FsError::InvalidData);
    }
    bytes[0..4].copy_from_slice(&0u32.to_le_bytes());
    // SAFETY: write back the same validated fixed-size request buffer.
    unsafe { copy_out(arg, &bytes)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_ATOMIC — decode objs/props/values arrays, build
/// `AtomicState`, run `core_check` + `core_commit`.
///
/// Linux ref: `drivers/gpu/drm/drm_atomic_uapi.c::drm_mode_atomic_ioctl`.
fn handle_atomic(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
    events: Option<&narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>>,
    out_fences: Option<&narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<(u64, u64)>>>,
) -> Result<u64, FsError> {
    // ATOMIC is a DRM_MASTER op (drm_ioctls[] marks DRM_MODE_ATOMIC
    // DRM_MASTER). Only the master may commit; reject render nodes and
    // non-master primary fds with EACCES. Previously ungated.
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }

    // SAFETY: `arg` is the ioctl argument pointer validated by the syscall
    // trap layer (or kernel-owned on the test path); we request exactly
    // `size_of::<DrmModeAtomicUapi>()` bytes, bounds-checked by `copy_in`.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeAtomicUapi>())? };
    let req: DrmModeAtomicUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmModeAtomicUapi>()` bytes, so reading one
        // `DrmModeAtomicUapi` stays within the allocation; `read_unaligned`
        // matches the `u8` alignment of the backing buffer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeAtomicUapi) };

    if mode_state.lock().driver_name != "virtio_gpu" {
        return Err(FsError::Unsupported);
    }
    const PAGE_FLIP_EVENT: u32 = 0x0001;
    const PAGE_FLIP_ASYNC: u32 = 0x0002;
    const TEST_ONLY: u32 = 0x0100;
    const NONBLOCK: u32 = 0x0200;
    const ALLOW_MODESET: u32 = 0x0400;
    const VALID_FLAGS: u32 =
        PAGE_FLIP_EVENT | PAGE_FLIP_ASYNC | TEST_ONLY | NONBLOCK | ALLOW_MODESET;
    if req.reserved != 0
        || req.flags & !VALID_FLAGS != 0
        || (req.flags & TEST_ONLY != 0 && req.flags & PAGE_FLIP_EVENT != 0)
        || req.count_objs > 256
    {
        return Err(FsError::InvalidData);
    }
    if req.count_objs != 0
        && (req.objs_ptr == 0
            || req.count_props_ptr == 0
            || req.props_ptr == 0
            || req.prop_values_ptr == 0)
    {
        return Err(FsError::BadAddress);
    }

    let count = req.count_objs as usize;
    let (obj_bytes, count_bytes) = if count == 0 {
        (Vec::new(), Vec::new())
    } else {
        // SAFETY: non-zero object arrays were validated above and their
        // bounded lengths cannot overflow `usize`.
        unsafe {
            (
                copy_in(req.objs_ptr as usize, count * 4)?,
                copy_in(req.count_props_ptr as usize, count * 4)?,
            )
        }
    };
    let objects: Vec<u32> = obj_bytes
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect();
    let prop_counts: Vec<u32> = count_bytes
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect();
    let total_props = prop_counts.iter().try_fold(0usize, |sum, count| {
        sum.checked_add(*count as usize)
            .filter(|total| *total <= 4096)
    });
    let total_props = total_props.ok_or(FsError::OutOfMemory)?;
    let (prop_bytes, value_bytes) = if total_props == 0 {
        (Vec::new(), Vec::new())
    } else {
        // SAFETY: non-zero property arrays were validated above and capped
        // at 4096 entries.
        unsafe {
            (
                copy_in(req.props_ptr as usize, total_props * 4)?,
                copy_in(req.prop_values_ptr as usize, total_props * 8)?,
            )
        }
    };
    let props: Vec<u32> = prop_bytes
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect();
    let values: Vec<u64> = value_bytes
        .chunks_exact(8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .collect();

    let mut state = crate::drm::atomic::AtomicState {
        allow_modeset: req.flags & ALLOW_MODESET != 0,
        ..Default::default()
    };
    let policy = crate::drm::atomic::AtomicCheckPolicy::default();
    let test_only = req.flags & TEST_ONLY != 0;
    let mut prop_index = 0usize;
    let presentation = {
        let mut card = mode_state.lock();
        // Linux's atomic state grows implicitly while properties are decoded:
        // drm_atomic_get_plane_state() adds the plane's old CRTC and
        // drm_atomic_set_crtc_for_plane() adds its new CRTC.  Keep the same
        // effective set here even when userspace submits only a plane object.
        // prepare_signaling() reserves one event for every CRTC in that
        // completed state, which is the common KWin page-flip request shape.
        let synthesized_planes = synth_planes(&card);
        // TEST_ONLY is KWin's hottest probe path and never carries an event;
        // avoid allocating its bookkeeping vector unless signaling was
        // actually requested.
        let mut event_crtc_ids =
            (req.flags & PAGE_FLIP_EVENT != 0).then(|| Vec::with_capacity(card.crtcs.len()));
        for (object_index, object_id) in objects.iter().copied().enumerate() {
            let object_prop_count = prop_counts[object_index] as usize;
            let end = prop_index
                .checked_add(object_prop_count)
                .filter(|end| *end <= props.len())
                .ok_or(FsError::InvalidData)?;
            let object_props = &props[prop_index..end];
            let object_values = &values[prop_index..end];
            prop_index = end;

            if let Some((_, crtc_index)) = synthesized_planes
                .iter()
                .copied()
                .find(|(id, _)| *id == object_id)
            {
                let crtc = &card.crtcs[crtc_index as usize];
                let old_crtc_id = crtc.primary_fb.map(|_| crtc.id);
                if let (Some(crtc_ids), Some(crtc_id)) = (event_crtc_ids.as_mut(), old_crtc_id) {
                    if !crtc_ids.contains(&crtc_id) {
                        crtc_ids.push(crtc_id);
                    }
                }
                let fb = crtc.primary_fb.and_then(|id| card.framebuffer(id).ok());
                let width = fb
                    .map(|fb| fb.width)
                    .or_else(|| crtc.mode.map(|mode| mode.width))
                    .unwrap_or(0);
                let height = fb
                    .map(|fb| fb.height)
                    .or_else(|| crtc.mode.map(|mode| mode.height))
                    .unwrap_or(0);
                let mut plane = crate::drm::atomic::PlaneState {
                    id: object_id,
                    crtc_id: crtc.primary_fb.map(|_| crtc.id),
                    fb_id: crtc.primary_fb,
                    crtc_x: crtc.x as i32,
                    crtc_y: crtc.y as i32,
                    crtc_w: width,
                    crtc_h: height,
                    src_x: crtc.x,
                    src_y: crtc.y,
                    src_w: width,
                    src_h: height,
                    in_fence_fd: None,
                };
                for (&prop, &value) in object_props.iter().zip(object_values) {
                    match prop {
                        PLANE_FB_ID_PROP_ID => plane.fb_id = (value != 0).then_some(value as u32),
                        PLANE_CRTC_ID_PROP_ID => {
                            plane.crtc_id = (value != 0).then_some(value as u32)
                        }
                        PLANE_SRC_X_PROP_ID => plane.src_x = (value >> 16) as u32,
                        PLANE_SRC_Y_PROP_ID => plane.src_y = (value >> 16) as u32,
                        PLANE_SRC_W_PROP_ID => plane.src_w = (value >> 16) as u32,
                        PLANE_SRC_H_PROP_ID => plane.src_h = (value >> 16) as u32,
                        PLANE_CRTC_X_PROP_ID => plane.crtc_x = value as i64 as i32,
                        PLANE_CRTC_Y_PROP_ID => plane.crtc_y = value as i64 as i32,
                        PLANE_CRTC_W_PROP_ID => plane.crtc_w = value as u32,
                        PLANE_CRTC_H_PROP_ID => plane.crtc_h = value as u32,
                        PLANE_IN_FENCE_FD_PROP_ID => {
                            let fd = value as i64;
                            // Linux set_property: -1 clears, other negatives
                            // are EINVAL, and the value must fit an s32.
                            if fd < -1 || fd > i32::MAX as i64 {
                                return Err(FsError::InvalidData);
                            }
                            plane.in_fence_fd = (fd >= 0).then_some(fd as i32);
                        }
                        _ => return Err(FsError::InvalidData),
                    }
                }
                if let (Some(crtc_ids), Some(crtc_id)) = (event_crtc_ids.as_mut(), plane.crtc_id) {
                    if !crtc_ids.contains(&crtc_id) {
                        crtc_ids.push(crtc_id);
                    }
                }
                state.planes.push(plane);
            } else if let Ok(crtc) = card.crtc(object_id) {
                let old_mode = crtc.mode;
                let old_active = crtc.enabled;
                let mut crtc_state = crate::drm::atomic::CrtcState {
                    id: object_id,
                    enable: old_active,
                    active: old_active,
                    mode: old_mode,
                    ..Default::default()
                };
                for (&prop, &value) in object_props.iter().zip(object_values) {
                    match prop {
                        CRTC_ACTIVE_PROP_ID => {
                            if value > 1 {
                                return Err(FsError::InvalidData);
                            }
                            crtc_state.enable = value != 0;
                            crtc_state.active = value != 0;
                        }
                        CRTC_MODE_ID_PROP_ID => {
                            crtc_state.mode = if value == 0 {
                                None
                            } else {
                                let mode = card
                                    .property_blob(value as u32)
                                    .filter(|blob| blob.len() == 68)
                                    .ok_or(FsError::InvalidData)?;
                                Some(crate::Mode {
                                    width: u16::from_le_bytes(mode[4..6].try_into().unwrap())
                                        as u32,
                                    height: u16::from_le_bytes(mode[14..16].try_into().unwrap())
                                        as u32,
                                    refresh_hz: u32::from_le_bytes(mode[24..28].try_into().unwrap())
                                        .max(1)
                                        as u16,
                                    bpp: 32,
                                })
                            };
                        }
                        CRTC_OUT_FENCE_PTR_PROP_ID => {
                            // A null pointer resets the request (Linux's
                            // set_out_fence_for_crtc treats 0 as clear).
                            crtc_state.out_fence_ptr = (value != 0).then_some(value);
                        }
                        _ => return Err(FsError::InvalidData),
                    }
                }
                // Linux's drm_atomic_helper_check_modeset compares the
                // completed old/new CRTC states; merely including MODE_ID or
                // ACTIVE in an atomic request does not require ALLOW_MODESET.
                // KWin relies on this for its TEST_ONLY no-modeset probe.
                crtc_state.mode_changed = crtc_state.mode != old_mode;
                crtc_state.active_changed = crtc_state.active != old_active;
                if let Some(crtc_ids) = event_crtc_ids.as_mut() {
                    if !crtc_ids.contains(&crtc_state.id) {
                        crtc_ids.push(crtc_state.id);
                    }
                }
                state.crtcs.push(crtc_state);
            } else if card.connector(object_id).is_ok() {
                let connector = card
                    .connector(object_id)
                    .map_err(|_| FsError::InvalidData)?;
                let mut connector_state = crate::drm::atomic::ConnectorState {
                    id: object_id,
                    crtc_id: connector
                        .encoder_id
                        .and_then(|id| card.encoder(id).ok())
                        .and_then(|encoder| encoder.crtc_id),
                };
                if let (Some(crtc_ids), Some(crtc_id)) =
                    (event_crtc_ids.as_mut(), connector_state.crtc_id)
                {
                    if !crtc_ids.contains(&crtc_id) {
                        crtc_ids.push(crtc_id);
                    }
                }
                for (&prop, &value) in object_props.iter().zip(object_values) {
                    match prop {
                        CONNECTOR_CRTC_ID_PROP_ID => {
                            connector_state.crtc_id = (value != 0).then_some(value as u32)
                        }
                        _ => return Err(FsError::InvalidData),
                    }
                }
                if let (Some(crtc_ids), Some(crtc_id)) =
                    (event_crtc_ids.as_mut(), connector_state.crtc_id)
                {
                    if !crtc_ids.contains(&crtc_id) {
                        crtc_ids.push(crtc_id);
                    }
                }
                state.connectors.push(connector_state);
            } else {
                return Err(FsError::InvalidData);
            }
        }

        if let Err(error) = state.core_check(&card, &policy) {
            let _ = writeln!(
                narf_console::Writer,
                "  drm: ATOMIC check failed: {error:?}"
            );
            return Err(FsError::InvalidData);
        }

        // Linux reserves one event for every CRTC participating in the atomic
        // state before committing. PAGE_FLIP_EVENT with no CRTC is EINVAL;
        // exhausting this drm_file's 4 KiB event budget is ENOMEM and must not
        // mutate display state.
        let mut event_queue = if req.flags & PAGE_FLIP_EVENT != 0 {
            let crtc_ids = event_crtc_ids.as_ref().ok_or(FsError::InvalidData)?;
            if crtc_ids.is_empty() {
                return Err(FsError::InvalidData);
            }
            let queue = events.ok_or(FsError::InvalidData)?.lock();
            queue
                .ensure_flip_event_space(crtc_ids.len())
                .map_err(|_| FsError::OutOfMemory)?;
            Some(queue)
        } else {
            None
        };
        if test_only {
            None
        } else {
            if let Err(error) = state.core_commit(&mut card) {
                let _ = writeln!(
                    narf_console::Writer,
                    "  drm: ATOMIC commit failed: {error:?}"
                );
                return Err(FsError::InvalidData);
            }
            let active_plane = state
                .planes
                .iter()
                .find_map(|plane| Some((plane.crtc_id?, plane.fb_id?)));
            // Advance the simulated vblank exactly once per affected CRTC;
            // the PAGE_FLIP_EVENT and any OUT_FENCE_PTR on the same CRTC
            // observe the same present instant.
            fn present_at_for(
                card: &mut crate::drm::card::Card,
                presented: &mut alloc::vec::Vec<(u32, u64)>,
                crtc_id: u32,
            ) -> u64 {
                if let Some(&(_, at)) = presented.iter().find(|(id, _)| *id == crtc_id) {
                    return at;
                }
                let at = card.advance_vblank(crtc_id);
                presented.push((crtc_id, at));
                at
            }
            let mut presented: alloc::vec::Vec<(u32, u64)> = alloc::vec::Vec::new();
            if let (Some(queue), Some(crtc_ids)) = (event_queue.as_mut(), event_crtc_ids) {
                for crtc_id in crtc_ids {
                    let at = present_at_for(&mut card, &mut presented, crtc_id);
                    card.queue_flip_event_at(queue, req.user_data, crtc_id, at)
                        .map_err(|_| FsError::OutOfMemory)?;
                }
            }
            // OUT_FENCE_PTR: hand (user pointer, vblank deadline) pairs to
            // the per-open sink; the syscall layer mints the sync_file fds
            // (fd tables are its domain) and writes them through the
            // pointers after the ioctl returns success.
            for crtc_state in &state.crtcs {
                if let Some(ptr) = crtc_state.out_fence_ptr {
                    let at = present_at_for(&mut card, &mut presented, crtc_state.id);
                    if let Some(sink) = out_fences {
                        sink.lock().push((ptr, at));
                    }
                }
            }
            active_plane.and_then(|(_, fb_id)| {
                let fb = card.framebuffer(fb_id).ok()?;
                let gem_handle = fb.gem_handle;
                Some((
                    card.virtgpu_import(gem_handle)
                        .map(|resource| resource.resource_id),
                    card.dumb_backing(gem_handle).map(|backing| backing.phys),
                    fb.pitch,
                    fb.width,
                    fb.height,
                    fb_id,
                ))
            })
        }
    };

    let (log, n) = should_log(&ATOMIC_N);
    if log {
        let _ = writeln!(
            narf_console::Writer,
            "  drm: ATOMIC #{n} objs={} props={} flags={:#x} present={}",
            req.count_objs,
            total_props,
            req.flags,
            presentation.is_some(),
        );
    }
    if let Some((resource_id, src_phys, pitch, width, height, fb_id)) = presentation {
        if let Some(resource_id) = resource_id {
            present_virgl_frame(resource_id, width, height)?;
        } else if let Some(src_phys) = src_phys {
            present_frame(card_index, src_phys, pitch, width, height);
        } else {
            note_missing_backing("ATOMIC", fb_id);
        }
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_CURSOR / CURSOR2 — set the pointer sprite + position.
///
/// `struct drm_mode_cursor` is `{ flags, crtc_id, x, y, width, height,
/// handle }` (7 × u32 = 28 bytes); CURSOR2 appends `{ hot_x, hot_y }`
/// (36 bytes). We have no hardware cursor plane, so we don't consume the
/// BO bitmap — instead we drive narf_fb's software cursor sprite from the
/// position + visibility. `DRM_MODE_CURSOR_BO` with handle 0 hides the
/// pointer; a non-zero handle shows it; `DRM_MODE_CURSOR_MOVE` repositions.
///
/// Linux ref: `drivers/gpu/drm/drm_plane.c::drm_mode_cursor_common`.
fn handle_cursor(arg: usize, with_hotspot: bool) -> Result<u64, FsError> {
    const DRM_MODE_CURSOR_BO: u32 = 0x01;
    const DRM_MODE_CURSOR_MOVE: u32 = 0x02;
    let want = if with_hotspot { 36 } else { 28 };
    // SAFETY: `arg` is the validated ioctl argument pointer; `copy_in`
    // bounds-checks `want` against IOCTL_MAX_BUF before copying.
    let bytes = unsafe { copy_in(arg, want)? };
    let rd_u32 = |off: usize| {
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    let rd_i32 = |off: usize| rd_u32(off) as i32;
    let flags = rd_u32(0);
    let x = rd_i32(8);
    let y = rd_i32(12);
    let handle = rd_u32(24);
    // CURSOR2 reports the hotspot — the active point inside the BO. Our
    // sprite's tip is at its own top-left, so shift the draw position by the
    // hotspot to keep the tip under the true pointer.
    let (hot_x, hot_y) = if with_hotspot {
        (rd_i32(28), rd_i32(32))
    } else {
        (0, 0)
    };

    if flags & DRM_MODE_CURSOR_BO != 0 {
        if handle == 0 {
            narf_console::user_cursor_hide();
        } else {
            narf_console::user_cursor_show();
        }
    }
    if flags & DRM_MODE_CURSOR_MOVE != 0 {
        let px = (x + hot_x).max(0) as u32;
        let py = (y + hot_y).max(0) as u32;
        narf_console::user_cursor_move(px, py);
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_CREATE_DUMB — allocate a dumb buffer (physically
/// contiguous pages) for a scanout-capable surface.
///
/// Linux ref: `drivers/gpu/drm/drm_dumb_buffers.c::drm_mode_create_dumb`.
fn handle_create_dumb(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // Permission: CREATE_DUMB is RENDER_ALLOW in Linux; the ioctl_flags
    // table already gates render-node access, so this just needs primary.
    let _ = ctx;

    // SAFETY: arg is the ioctl arg pointer; copy_in bounds-checks.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCreateDumbUapi>())? };
    let mut req: DrmModeCreateDumbUapi =
        // SAFETY: bytes is freshly allocated of exactly the right size.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeCreateDumbUapi) };

    if req.width == 0 || req.height == 0 || req.bpp == 0 {
        return Err(FsError::InvalidData);
    }
    // Compute pitch (round up to 64-byte stride for alignment).
    let bpp_bytes = req.bpp.div_ceil(8);
    let pitch = req.width * bpp_bytes;
    let raw_size = pitch as u64 * req.height as u64;
    // Round up to page size.
    let page_size: u64 = 4096;
    let size = (raw_size + page_size - 1) & !(page_size - 1);

    // Compute buddy order (smallest power-of-two page count >= pages_needed).
    let pages_needed = size / page_size;
    let order = {
        let mut o = 0u8;
        while (1u64 << o) < pages_needed {
            o += 1;
        }
        o
    };

    // Allocate contiguous physical pages via the buddy allocator.
    let frame = narf_memory::frame::alloc_pages_on(0, order).map_err(|_| FsError::InvalidData)?;
    let phys = frame.start_address().raw();

    // Zero the buffer so userspace doesn't see stale kernel data.
    // SAFETY: phys is identity-mapped (KERNEL_PHYS_OFFSET==0 on x86_64);
    // the allocation covers `size` bytes at `phys`.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
            0,
            size as usize,
        );
    }

    // Register in the card's dumb_backings table.
    let handle = {
        let mut card = mode_state.lock();
        card.register_dumb_backing(phys, size as usize, order)
            .map_err(|_| FsError::InvalidData)?
    };

    // Write back the result.
    req.handle = handle;
    req.pitch = pitch;
    req.size = size;

    let out_bytes: [u8; core::mem::size_of::<DrmModeCreateDumbUapi>()] =
        // SAFETY: DrmModeCreateDumbUapi is #[repr(C)] POD.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::mem::transmute(req) };
    // SAFETY: arg is the validated user/kernel pointer.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_MAP_DUMB — return a fake mmap offset encoding the
/// GEM handle so `sys_mmap` can later resolve it back to the buffer.
///
/// Linux ref: `drivers/gpu/drm/drm_dumb_buffers.c::drm_mode_mmap_dumb`.
fn handle_map_dumb(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    let _ = ctx;

    // SAFETY: as above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeMapDumbUapi>())? };
    let mut req: DrmModeMapDumbUapi =
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeMapDumbUapi) };

    let mmap_offset = {
        let card = mode_state.lock();
        card.dumb_backing(req.handle)
            .map(|b| b.mmap_offset)
            .ok_or(FsError::InvalidData)?
    };

    req.offset = mmap_offset;

    let out_bytes: [u8; core::mem::size_of::<DrmModeMapDumbUapi>()] =
        // SAFETY: #[repr(C)] POD.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::mem::transmute(req) };
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_DESTROY_DUMB — free a dumb buffer's physical pages.
///
/// Linux ref: `drivers/gpu/drm/drm_dumb_buffers.c::drm_mode_destroy_dumb`.
fn handle_destroy_dumb(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    let _ = ctx;

    // SAFETY: as above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeDestroyDumbUapi>())? };
    let req: DrmModeDestroyDumbUapi =
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeDestroyDumbUapi) };

    if free_dumb_backing(mode_state, req.handle) {
        Ok(0)
    } else {
        // drm_mode_destroy_dumb() delegates to drm_gem_handle_delete(), which
        // returns EINVAL when the per-file handle does not exist.
        Err(FsError::InvalidData)
    }
}

/// GEM_CLOSE — close a GEM handle and free its backing if it's a dumb buffer.
fn handle_gem_close(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    let _ = ctx;
    if arg == 0 {
        return Err(FsError::InvalidData);
    }
    // GEM_CLOSE struct: u32 handle + u32 pad.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, 8)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let removed_import = mode_state.lock().remove_virtgpu_import(handle);
    if removed_import || free_dumb_backing(mode_state, handle) {
        Ok(0)
    } else {
        // Linux drm_gem_handle_delete() reports EINVAL for an unknown or
        // already-closed handle.
        Err(FsError::InvalidData)
    }
}

/// Free a dumb buffer's physical backing pages (helper shared by DESTROY_DUMB + GEM_CLOSE).
fn free_dumb_backing(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    gem_handle: u32,
) -> bool {
    let (known, phys_order) = {
        let mut card = mode_state.lock();
        let known = card.dumb_backing(gem_handle).is_some();
        (known, card.remove_dumb_backing(gem_handle))
    };
    if let Some((phys, order)) = phys_order {
        let frame = narf_memory::frame::PhysFrame::new(narf_memory::addr::PhysAddr::new(phys));
        narf_memory::frame::free_pages(frame, order);
    }
    known
}

/// Release one fd/mapping reference to a dumb backing. The registry owns the
/// card lock; physical pages return to the allocator only after the final GEM,
/// framebuffer, dma-buf, and mmap reference is gone.
pub(crate) fn release_dumb_backing_ref(card_index: u32, gem_handle: u32) {
    if let Some(mode_state) = crate::drm_registry::mode_state(card_index) {
        let _ = free_dumb_backing(&mode_state, gem_handle);
    }
}

// ── Present-path telemetry ────────────────────────────────────────────
//
// A compositor that runs but shows nothing is indistinguishable, from the
// serial log alone, from a compositor that never submitted a frame. These
// counters make the scanout path observable without a debugger: which
// submission ioctl the client actually drives, whether its framebuffer
// resolved to backing pages, and whether the blit reached a live scanout.
//
// Kept quiet after the opening frames — the first four of each event, then
// every 512th — so a steady 60 fps costs a line every ~8 seconds.

static SETCRTC_N: AtomicU64 = AtomicU64::new(0);
static PAGEFLIP_N: AtomicU64 = AtomicU64::new(0);
static ATOMIC_N: AtomicU64 = AtomicU64::new(0);
static BLIT_N: AtomicU64 = AtomicU64::new(0);
static NOBACKING_N: AtomicU64 = AtomicU64::new(0);
static NOSCANOUT_N: AtomicU64 = AtomicU64::new(0);

/// True when this occurrence should be logged: the first four, then every
/// 512th. `n` is the pre-increment count.
fn should_log(counter: &AtomicU64) -> (bool, u64) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    // `%`, not `u64::is_multiple_of` — the latter is stable only since
    // 1.87 and this tree's MSRV is 1.85.
    (n <= 4 || n % 512 == 0, n)
}

/// DRM_IOCTL_MODE_SETCRTC — blit the named framebuffer's dumb buffer
/// into the active scanout via `narf_fb::fbdev_info` + memcpy.
///
/// Linux ref: `drivers/gpu/drm/drm_crtc.c::drm_mode_setcrtc`.
fn handle_setcrtc(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SETCRTC is a DRM_MASTER op: only the open holding master may modeset.
    // This rejects render nodes (never master) AND authenticated-but-non-master
    // primary fds (e.g. a second compositor before it takes over) with EACCES,
    // exactly as Linux's drm_ioctl_permit gates a DRM_MASTER ioctl.
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }

    // SAFETY: arg is the ioctl argument pointer.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCrtcUapi>())? };
    let req: DrmModeCrtcUapi =
        // SAFETY: #[repr(C)] POD of right size.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeCrtcUapi) };

    // Look up the framebuffer → GEM handle → dumb backing phys.
    let src_phys: Option<u64>;
    let virgl_resource_id: Option<u32>;
    let src_pitch: u32;
    let src_w: u32;
    let src_h: u32;
    {
        let mut card = mode_state.lock();

        // Record the mode and active fb on the crtc.
        if let Ok(crtc) = card.crtc_mut(req.crtc_id) {
            crtc.primary_fb = if req.fb_id != 0 {
                Some(req.fb_id)
            } else {
                None
            };
            crtc.enabled = req.fb_id != 0;
        }

        if req.fb_id == 0 {
            return Ok(0);
        }

        let fb = card
            .framebuffer(req.fb_id)
            .map_err(|_| FsError::InvalidData)?;
        src_pitch = fb.pitch;
        src_w = fb.width;
        src_h = fb.height;
        let gem_handle = fb.gem_handle;
        src_phys = card.dumb_backing(gem_handle).map(|b| b.phys);
        virgl_resource_id = card
            .virtgpu_import(gem_handle)
            .map(|resource| resource.resource_id);
    }

    let (log, n) = should_log(&SETCRTC_N);
    if log {
        let _ = writeln!(
            narf_console::Writer,
            "  drm: SETCRTC #{n} crtc={} fb={} {}x{} pitch={} backing={}",
            req.crtc_id,
            req.fb_id,
            src_w,
            src_h,
            src_pitch,
            if src_phys.is_some() { "yes" } else { "NONE" }
        );
    }

    // Perform the blit if we have a valid source and a live scanout.
    if let Some(resource_id) = virgl_resource_id {
        present_virgl_frame(resource_id, src_w, src_h)?;
    } else if let Some(src) = src_phys {
        present_frame(card_index, src, src_pitch, src_w, src_h);
    } else {
        note_missing_backing("SETCRTC", req.fb_id);
    }
    Ok(0)
}

/// A submission named a framebuffer whose GEM handle has no dumb backing —
/// nothing can be blitted, so the scanout keeps its previous contents. The
/// live case is a client presenting GBM/PRIME buffers rather than dumb ones.
fn note_missing_backing(op: &str, fb_id: u32) {
    let (log, n) = should_log(&NOBACKING_N);
    if log {
        let _ = writeln!(
            narf_console::Writer,
            "  drm: {op} fb={fb_id} has no dumb backing — nothing presented (#{n})"
        );
    }
}

/// DRM_IOCTL_MODE_PAGE_FLIP — same blit as SETCRTC, no vblank event.
///
/// Linux ref: `drivers/gpu/drm/drm_crtc.c::drm_mode_page_flip_ioctl`.
fn handle_page_flip(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
    events: Option<&narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>>,
) -> Result<u64, FsError> {
    // Page flip is a DRM_MASTER op — only the master may flip (see
    // handle_setcrtc). Rejects render nodes and non-master primary fds.
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }

    // SAFETY: arg is the ioctl argument pointer.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModePageFlipUapi>())? };
    let req: DrmModePageFlipUapi =
        // SAFETY: #[repr(C)] POD of right size.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModePageFlipUapi) };

    // DRM_MODE_PAGE_FLIP_EVENT — queue a flip-complete event the client
    // reads off the DRM fd after poll/select (the compositor render loop).
    const DRM_MODE_PAGE_FLIP_EVENT: u32 = 0x01;
    // Linux virtio-gpu does not advertise async flips and its CRTC exposes
    // `page_flip`, not `page_flip_target`, so ASYNC/TARGET are EINVAL.
    if req.flags & !DRM_MODE_PAGE_FLIP_EVENT != 0 || req.reserved != 0 {
        return Err(FsError::InvalidData);
    }

    let src_phys: Option<u64>;
    let virgl_resource_id: Option<u32>;
    let src_pitch: u32;
    let src_w: u32;
    let src_h: u32;
    {
        let mut card = mode_state.lock();
        // Linux resolves an unknown CRTC/fb as ENOENT and refuses a flip from
        // an unbound primary plane with EBUSY. Validate before mutating state.
        let old_fb_id = card
            .crtc(req.crtc_id)
            .map_err(|_| FsError::NotFound)?
            .primary_fb
            .ok_or(FsError::Busy)?;
        let old_format = card
            .framebuffer(old_fb_id)
            .map_err(|_| FsError::Busy)?
            .format;
        let fb = card.framebuffer(req.fb_id).map_err(|_| FsError::NotFound)?;
        if fb.format != old_format {
            return Err(FsError::InvalidData);
        }
        src_pitch = fb.pitch;
        src_w = fb.width;
        src_h = fb.height;
        let gem_handle = fb.gem_handle;
        src_phys = card.dumb_backing(gem_handle).map(|b| b.phys);
        virgl_resource_id = card
            .virtgpu_import(gem_handle)
            .map(|resource| resource.resource_id);

        // Reserve Linux's per-file event space before changing the CRTC, so an
        // ENOMEM failure leaves scanout state untouched.
        let mut event_queue = if req.flags & DRM_MODE_PAGE_FLIP_EVENT != 0 {
            let queue = events.ok_or(FsError::InvalidData)?.lock();
            queue
                .ensure_flip_event_space(1)
                .map_err(|_| FsError::OutOfMemory)?;
            Some(queue)
        } else {
            None
        };

        card.crtc_mut(req.crtc_id)
            .map_err(|_| FsError::NotFound)?
            .primary_fb = Some(req.fb_id);

        if let Some(queue) = event_queue.as_mut() {
            // The blit is synchronous; completion is then exposed at the
            // simulated-vblank deadline recorded by queue_flip_event.
            card.queue_flip_event(queue, req.user_data, req.crtc_id)
                .map_err(|_| FsError::OutOfMemory)?;
        }
    }

    let (log, n) = should_log(&PAGEFLIP_N);
    if log {
        let _ = writeln!(
            narf_console::Writer,
            "  drm: PAGE_FLIP #{n} crtc={} fb={} {}x{} event={} backing={}",
            req.crtc_id,
            req.fb_id,
            src_w,
            src_h,
            req.flags & DRM_MODE_PAGE_FLIP_EVENT != 0,
            if src_phys.is_some() { "yes" } else { "NONE" }
        );
    }

    if let Some(resource_id) = virgl_resource_id {
        present_virgl_frame(resource_id, src_w, src_h)?;
    } else if let Some(src) = src_phys {
        present_frame(card_index, src, src_pitch, src_w, src_h);
    } else {
        note_missing_backing("PAGE_FLIP", req.fb_id);
    }
    Ok(0)
}

/// Present a PRIME-imported VirGL GEM object directly, matching Linux's
/// virtio-gpu primary-plane update (`SET_SCANOUT` + `RESOURCE_FLUSH`).
fn present_virgl_frame(resource_id: u32, width: u32, height: u32) -> Result<(), FsError> {
    let dev = narf_drivers_virtio::gpu_pci::probed_device().ok_or(FsError::InvalidData)?;
    narf_console::fb_take_for_user();
    dev.present_virgl_resource(resource_id, width, height)
        .map_err(map_gpu_transport_error)
}

/// Present a dumb buffer on the card that accepted the KMS ioctl.
///
/// The QEMU profile keeps bochs as an emergency display fallback while
/// virtio-gpu is card0.  Those are independent framebuffers: copying a
/// virtio card's pixels through the global fbdev hook would silently draw on
/// bochs instead.  Select the owning card here so the primary DRM node and
/// the visible scanout always agree.
fn present_frame(card_index: u32, src_phys: u64, src_pitch: u32, src_w: u32, src_h: u32) {
    if crate::drm_registry::driver_name(card_index) == Some("virtio_gpu") {
        blit_to_virtio_scanout(src_phys, src_pitch, src_w, src_h);
    } else {
        blit_to_scanout(src_phys, src_pitch, src_w, src_h);
    }
}

/// Blit pixels from a dumb buffer into virtio-gpu's scanout resource.
///
/// KMS dumb buffers are generic system-memory GEM objects, whereas the
/// virtio device owns resource 1 as its host-visible scanout.  Copying into
/// that resource then issuing TRANSFER_TO_HOST_2D + RESOURCE_FLUSH is the
/// required bridge between the generic DRM KMS ABI and the virtio display.
/// This is deliberately separate from the VirGL render-resource path: it
/// makes ordinary KMS presentation correct before Mesa can rely on a 3D
/// resource for rendering.
fn blit_to_virtio_scanout(src_phys: u64, src_pitch: u32, src_w: u32, src_h: u32) {
    let Some(virtio) = narf_drivers_virtio::gpu_pci::probed_device() else {
        let (log, n) = should_log(&NOSCANOUT_N);
        if log {
            let _ = writeln!(
                narf_console::Writer,
                "  drm: virtio blit dropped — GPU controller unavailable (#{n})"
            );
        }
        return;
    };

    let mode = virtio.mode();
    let dst_w = mode.width.min(src_w);
    let dst_h = mode.height.min(src_h);
    let row_bytes = (dst_w as usize) * 4;
    let dst_phys = virtio.scanout_phys();
    let (log, n) = should_log(&BLIT_N);
    if log {
        let _ = writeln!(
            narf_console::Writer,
            "  drm: virtio blit #{n} src {}x{} pitch={} -> scanout {}x{}",
            src_w,
            src_h,
            src_pitch,
            mode.width,
            mode.height,
        );
    }

    // A real DRM client is now driving this scanout.  Suppress kernel
    // overlays before the frame is flushed so they cannot bleed over the
    // compositor's pixels.
    narf_console::fb_take_for_user();
    for row in 0..dst_h as usize {
        let src_row = src_phys + (row * src_pitch as usize) as u64;
        let dst_row = dst_phys + (row * mode.width as usize * 4) as u64;
        // SAFETY: both buffers are DMA allocations identity-mapped by the
        // x86_64 kernel.  Row bounds are clamped to each buffer's geometry.
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(src_row).kernel_ptr::<u8>(),
                narf_memory::PhysAddr::new(dst_row).kernel_mut_ptr::<u8>(),
                row_bytes,
            );
        }
    }

    if virtio.flush().is_err() {
        let _ = writeln!(narf_console::Writer, "  drm: virtio scanout flush failed");
    }
}

/// Blit pixels from a dumb buffer at `src_phys` into the active scanout.
///
/// Both source and destination are XRGB8888 linear; we copy row-by-row
/// up to `min(src_w, scanout_w)` × `min(src_h, scanout_h)`. After the
/// blit, `flush_scanout()` pushes the pixels to the host display on
/// virtio-gpu; it is a no-op on bochs (direct MMIO).
///
/// The scanout geometry is fetched through the DRM fbdev hook installed
/// by `narf_fb` at `Stage::Late` — avoids a circular crate dependency.
fn blit_to_scanout(src_phys: u64, src_pitch: u32, src_w: u32, src_h: u32) {
    let info = match crate::drm_fb_hook::query_scanout() {
        Some(i) => i,
        None => {
            // No live scanout: the client's pixels are being dropped on the
            // floor, which looks exactly like a compositor that never drew.
            let (log, n) = should_log(&NOSCANOUT_N);
            if log {
                let _ = writeln!(
                    narf_console::Writer,
                    "  drm: blit dropped — no live scanout (#{n})"
                );
            }
            return;
        }
    };
    let (log, n) = should_log(&BLIT_N);
    if log {
        let _ = writeln!(
            narf_console::Writer,
            "  drm: blit #{n} src {}x{} pitch={} -> scanout {}x{} stride={}",
            src_w,
            src_h,
            src_pitch,
            info.width,
            info.height,
            info.stride_bytes
        );
    }
    // A real DRM client is now driving the scanout — hand the framebuffer
    // over to it: detach the kernel console FB hook and suppress the FB
    // status-panel / cursor painters so they stop bleeding kernel chrome
    // over the compositor's pixels. Idempotent, so calling it on every
    // SETCRTC / page flip is cheap. Released when the last card node closes
    // (see `DriCardFile`'s Drop).
    narf_console::fb_take_for_user();
    let dst_w = info.width.min(src_w);
    let dst_h = info.height.min(src_h);
    let row_bytes = (dst_w as usize) * 4;
    for row in 0..dst_h as usize {
        let src_row = src_phys + (row * src_pitch as usize) as u64;
        let dst_row = info.phys + (row * info.stride_bytes as usize) as u64;
        // SAFETY: Both src and dst are identity-mapped physical addresses
        // validated by their respective allocators; `row_bytes` is within
        // the allocation bounds (row < dst_h <= src_h, dst_w <= src_w).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(src_row).kernel_ptr::<u8>(),
                narf_memory::PhysAddr::new(dst_row).kernel_mut_ptr::<u8>(),
                row_bytes,
            );
        }
    }
    // Tell the FB cursor renderer the frame was fully repainted so it drops
    // its now-stale saved-background snapshot and re-composites the pointer
    // over the fresh frame (otherwise the compositor's repaint would leave the
    // pointer erased until the next cursor *move*).
    narf_console::bump_scanout_gen();
    crate::drm_fb_hook::flush_scanout();
}

/// Return the physical frames backing a dumb buffer for `sys_mmap`.
///
/// Called from `DriCardFile::mmap_frames`. `offset` is the fake mmap
/// offset returned by MAP_DUMB (= gem_handle << 12); `len` is the
/// requested mapping length.
pub fn dispatch_mmap(card_index: u32, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
    let mode_state = crate::drm_registry::mode_state(card_index).ok_or(FsError::Unsupported)?;
    let card = mode_state.lock();
    let backing = card
        .dumb_backing_by_offset(offset)
        .ok_or(FsError::InvalidData)?;
    if len > backing.byte_len {
        return Err(FsError::InvalidData);
    }
    let pages = len / 4096;
    let mut frames = Vec::with_capacity(pages);
    for i in 0..pages {
        frames.push(backing.phys + (i as u64) * 4096);
    }
    Ok(frames)
}

/// Fallback: hand any other DRM_IOCTL_* number to the generic
/// dispatcher. For these we currently pass an empty input slice — the
/// generic dispatcher's handlers that need wire bytes (GETCONNECTOR,
/// ADDFB2, RMFB) read fields out by offset.
///
/// Where the user input doesn't fit Wave-36's minimum-viable scope
/// (no full per-cmd serdes), we still route through the dispatch so
/// permission gates fire correctly and a known-but-unimplemented cmd
/// returns ENOTSUP rather than crashing.
fn handle_generic(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    cmd: u32,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    let nr = drm_uapi::ioc_nr(cmd);
    // For ioctls with a known struct size, copy the input through.
    let size = drm_uapi::ioc_size(cmd) as usize;
    let in_bytes: Vec<u8> = if size > 0 && arg != 0 {
        // SAFETY: guarded by `arg != 0`; `size` is the encoded ioctl struct
        // size from `ioc_size(cmd)` and is bounds-checked again by `copy_in`
        // against `IOCTL_MAX_BUF`. `arg` is the validated user pointer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { copy_in(arg, size)? }
    } else {
        Vec::new()
    };
    let result = {
        let mut card = mode_state.lock();
        dispatch(&mut card, nr, &in_bytes, ctx).map_err(map_err)?
    };
    // Serialise the out-payload back to the user buffer for the ioctls
    // that carry one. GEM_CLOSE / RMFB / SyncObj have none → return 0.
    match result {
        // drm_get_cap = { __u64 capability; __u64 value; } — write `value`.
        crate::drm::ioctl::DrmIoctlResult::GetCap(cap) if arg != 0 => {
            let mut out = [0u8; 16];
            out[0..8].copy_from_slice(&cap.capability.to_le_bytes());
            out[8..16].copy_from_slice(&cap.value.to_le_bytes());
            // SAFETY: `arg` is the validated user drm_get_cap pointer (16 bytes).
            unsafe { copy_out(arg, &out)? };
        }
        // fb_id is the first __u32 of struct drm_mode_fb_cmd2.
        crate::drm::ioctl::DrmIoctlResult::AddFb2(fb_id) if arg != 0 => {
            // SAFETY: `arg` is the validated user drm_mode_fb_cmd2 pointer.
            unsafe { copy_out(arg, &fb_id.to_le_bytes())? };
        }
        _ => {}
    }
    Ok(0)
}

// ── Misc ─────────────────────────────────────────────────────────────

/// Return the byte prefix of `buf` up to (but excluding) the first
/// NUL — i.e. the C-string content of a fixed-size buffer.
fn c_str_bytes(buf: &[u8]) -> &[u8] {
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..n]
}
