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
use narf_filesystem::{dma_buf::DmaResvUsage, FsError, IoctlContext};
use narf_io::DmaBuffer;

use crate::drm::ioctl::{dispatch, DrmIoctlError, DrmIoctlResult, IoctlCmd};
use crate::drm::render_node::DrmFileCtx;
use crate::drm_uapi::{
    self, DrmModeAtomicUapi, DrmModeCardResUapi, DrmModeCreateDumbUapi, DrmModeCrtcUapi,
    DrmModeDestroyDumbUapi, DrmModeMapDumbUapi, DrmModePageFlipUapi, DrmVersionUapi,
};

// ── Native-KMS request types ─────────────────────────────────────
//
// The atomic / set-property paths collect the native display
// requests a commit implies and issue them after dropping the card
// lock. Only the amdgpu native KMS has displays to request anything
// of, so without the driver the request types are uninhabited and
// the collections are empty by construction.
#[cfg(feature = "amdgpu")]
type CrtcColorRequest = crate::amdgpu_native_kms::CrtcColorRequest;
#[cfg(not(feature = "amdgpu"))]
type CrtcColorRequest = core::convert::Infallible;
#[cfg(feature = "amdgpu")]
type ConnectorColorRequest = crate::amdgpu_native_kms::ConnectorColorRequest;
#[cfg(not(feature = "amdgpu"))]
type ConnectorColorRequest = core::convert::Infallible;
/// The GEM buffer a legacy cursor request names (amdgpu only).
#[cfg(feature = "amdgpu")]
type CursorBo = Arc<crate::amdgpu_gem::GemObject>;
#[cfg(not(feature = "amdgpu"))]
type CursorBo = Arc<core::convert::Infallible>;
/// A native hardware cursor's image (amdgpu only).
#[cfg(feature = "amdgpu")]
type CursorImage = crate::amdgpu_navi48_platform::CursorContent;
#[cfg(not(feature = "amdgpu"))]
type CursorImage = ();
/// One display's planes in an atomic commit, as the native
/// presenter consumes them (amdgpu only; the collection is empty
/// by construction without the driver).
#[cfg(feature = "amdgpu")]
type NativePresentation = (
    u32,
    Option<crate::drm::card::PlaneFrame>,
    [Option<crate::drm::card::PlaneFrame>; crate::amdgpu_dcn401_otg::MAX_OVERLAYS],
    Option<u64>,
);
#[cfg(not(feature = "amdgpu"))]
type NativePresentation = (
    u32,
    Option<crate::drm::card::PlaneFrame>,
    [Option<crate::drm::card::PlaneFrame>; 0],
    Option<u64>,
);

// ── Copy helpers ──────────────────────────────────────────────────────
//
// These mirror `narf-userspace::handlers::{copy_from_user, copy_to_user}`
// (range check + fault-guarded copy) but stay local so the GPU crate doesn't
// take a dependency on the syscall layer. `sys_ioctl` passes the raw `arg`
// through unvalidated, and every pointer *inside* an ioctl struct is the
// client's, so both are checked here. The kernel-test smokes pass
// kernel-owned pointers through the test-only `kernel_test_buffers` opt-out.

/// Maximum per-ioctl payload size (1 MiB). Hard cap so a malicious
/// `count_objs` field can't be used to force a huge allocation.
const IOCTL_MAX_BUF: usize = 1024 * 1024;

/// Maximum opaque VirGL command stream accepted from one EXECBUFFER ioctl:
/// what one SUBMIT_3D can carry (see the transport's
/// `MAX_VIRGL_COMMAND_BYTES`). It covers a full Mesa command buffer, which
/// Mesa flushes in one EXECBUFFER and drops on error.
pub(crate) const VIRTGPU_EXECBUFFER_MAX_BYTES: usize =
    narf_drivers_virtio::gpu_pci::MAX_VIRGL_COMMAND_BYTES;

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
    /// The buffer's dma-buf reservation and name, shared by every PRIME fd
    /// and imported handle naming this resource (they share this `Arc`'d
    /// resource). EXECBUFFER adds its fence as a WRITE fence, as Linux
    /// `virtio_gpu_array_add_fence` does; `DMA_BUF_IOCTL_IMPORT_SYNC_FILE`
    /// adds userspace fences.
    pub(crate) dma_buf: narf_filesystem::dma_buf::DmaBufObject,
}

/// One driver-level fence shared by BO reservations, sync files, and binary
/// syncobjs. The transport owns the completion bit; this wrapper supplies the
/// two subsystem traits without making VFS depend on the VirtIO driver.
#[derive(Debug)]
pub(crate) struct VirtGpuFence {
    transport: Arc<narf_drivers_virtio::gpu_pci::SubmittedFence>,
    context: u64,
    /// `CLOCK_MONOTONIC` ns at which this fence was first seen complete
    /// (Linux `dma_fence.timestamp`); 0 while pending. Completion is reaped
    /// by whichever query observes it, so the reap instant is the signal
    /// time NARF can report.
    signalled_at_ns: AtomicU64,
}

impl VirtGpuFence {
    fn new(
        transport: Arc<narf_drivers_virtio::gpu_pci::SubmittedFence>,
        context: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            transport,
            context,
            signalled_at_ns: AtomicU64::new(0),
        })
    }

    /// Record the first observation of completion.
    fn note_signalled(&self, signalled: bool) -> bool {
        if signalled && self.signalled_at_ns.load(Ordering::Acquire) == 0 {
            let now = narf_time::wall::monotonic_ns().max(1);
            let _ =
                self.signalled_at_ns
                    .compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
        }
        signalled
    }

    fn is_device_signalled(&self) -> bool {
        self.note_signalled(
            narf_drivers_virtio::gpu_pci::probed_device()
                .map(|dev| dev.fence_signalled(&self.transport))
                // A removed device cannot make further progress. Treat its
                // abandoned fences as done so pollers do not wedge forever.
                .unwrap_or(true),
        )
    }

    fn wait_device(&self, timeout_ms: u64) -> bool {
        self.note_signalled(
            narf_drivers_virtio::gpu_pci::probed_device()
                .map(|dev| dev.wait_fence(&self.transport, timeout_ms))
                .unwrap_or(true),
        )
    }

    async fn wait_device_async(&self, timeout_ms: u64) -> bool {
        let signalled = match narf_drivers_virtio::gpu_pci::probed_device() {
            Some(dev) => dev.wait_fence_async(&self.transport, timeout_ms).await,
            // A removed device cannot make further progress. Treat its
            // abandoned fences as done so userspace cannot wedge forever.
            None => true,
        };
        self.note_signalled(signalled)
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

/// Names follow Linux `virtgpu_fence.c`: driver `"virtio_gpu"`, timeline
/// `"controlq"`; the seqno is the virtqueue fence id
/// (`virtio_gpu_fence_emit`).
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

    fn seqno(&self) -> u64 {
        self.transport.id()
    }

    fn driver_name(&self) -> &str {
        "virtio_gpu"
    }

    fn timeline_name(&self) -> &str {
        "controlq"
    }

    fn timestamp_ns(&self) -> Option<u64> {
        match self.signalled_at_ns.load(Ordering::Acquire) {
            0 => None,
            at => Some(at),
        }
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
        // Linux `virtio_gpu_cmd_unref_resource` only queues UNREF; the backing
        // is freed from the response callback (`virtio_gpu_cmd_unref_cb` →
        // `virtio_gpu_cleanup_object`), so the final drop never waits for the
        // device. Waiting here took the GPU request gate from whatever context
        // dropped the last reference — an RCU reclaim, a file close, a cursor
        // flush that already held that gate. The round-trip runs in its own
        // stackful task instead, which can yield while the gate is busy; the
        // backing travels with it and is released only on the host's ack.
        let resource_id = self.resource_id;
        let _ = narf_scheduler::spawn_stackful(async move {
            if host_unref(resource_id) {
                drop(backing);
            } else {
                // The host may still DMA through its resource backing. Leaking
                // is bounded to the failed object and is safer than recycling
                // pages.
                core::mem::forget(backing);
            }
        });
    }
}

/// Send `RESOURCE_UNREF` for the host's final reference; `true` when the
/// device acknowledged it (only then may the guest backing be recycled).
/// Indirected so a kernel test can observe *when* it runs.
fn host_unref(resource_id: u32) -> bool {
    #[cfg(feature = "kernel-test")]
    if let Some(hook) = *TEST_HOST_UNREF.lock() {
        return hook(resource_id);
    }
    narf_drivers_virtio::gpu_pci::probed_device()
        .map(|dev| dev.unref_virgl_resource(resource_id).is_ok())
        .unwrap_or(false)
}

/// Test stand-in for the device's RESOURCE_UNREF.
#[cfg(feature = "kernel-test")]
type HostUnrefHook = fn(u32) -> bool;

#[cfg(feature = "kernel-test")]
static TEST_HOST_UNREF: narf_lib::sync::IrqSafeSpinLock<Option<HostUnrefHook>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Dropping the last reference to a host-owned VirGL resource must not talk
/// to the device in the dropper's context. Linux's
/// `virtio_gpu_cmd_unref_resource` only queues UNREF and frees the backing
/// from the response callback (`virtio_gpu_cmd_unref_cb` →
/// `virtio_gpu_cleanup_object`). NARF waited for the device inline — taking
/// the GPU request gate — from wherever the drop happened; one such drop ran
/// inside a cursor flush that already held that gate, and the CPU spun forever
/// with interrupts masked. The release must happen later, exactly once, with
/// the right id.
#[cfg(feature = "kernel-test")]
fn smoke_virtgpu_drop_defers_host_unref() -> narf_kernel_test::TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_kernel_test::TestResult;
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST: AtomicU32 = AtomicU32::new(0);
    fn record(resource_id: u32) -> bool {
        CALLS.fetch_add(1, Ordering::Relaxed);
        LAST.store(resource_id, Ordering::Relaxed);
        true
    }
    CALLS.store(0, Ordering::Relaxed);
    LAST.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();
    *TEST_HOST_UNREF.lock() = Some(record);

    drop(VirtGpuResource {
        resource_id: 0x7711,
        backing: Some(ResourceBacking::HostOnly { size: 4096 }),
        blob_mem: None,
        host3d_blob: false,
        host_owned: true,
        last_fence: narf_lib::sync::IrqSafeSpinLock::new(None),
        dma_buf: narf_filesystem::dma_buf::DmaBufObject::new(),
    });
    let inline_calls = CALLS.load(Ordering::Relaxed);
    narf_scheduler::run_until_empty();
    let later_calls = CALLS.load(Ordering::Relaxed);
    let last = LAST.load(Ordering::Relaxed);

    *TEST_HOST_UNREF.lock() = None;
    narf_scheduler::__reset_queues_for_test();
    if inline_calls != 0 {
        return TestResult::Fail("dropping a host-owned resource sent UNREF inline");
    }
    if later_calls != 1 || last != 0x7711 {
        return TestResult::Fail("the deferred UNREF did not run exactly once for this resource");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_virtgpu_drop_defers_host_unref
);

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
        dma_buf: narf_filesystem::dma_buf::DmaBufObject::new(),
    })
}

struct VirtGpuHandle {
    handle: u32,
    resource: Arc<VirtGpuResource>,
    /// The resource was CTX_ATTACHed to this open's context when the handle
    /// was created (classic resources, blobs and PRIME imports alike, as
    /// Linux's virtio_gpu_gem_object_open does), so closing the handle sends
    /// CTX_DETACH.
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
                dma_buf: narf_filesystem::dma_buf::DmaBufObject::new(),
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
                dma_buf: narf_filesystem::dma_buf::DmaBufObject::new(),
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
        attached: bool,
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
                dma_buf: narf_filesystem::dma_buf::DmaBufObject::new(),
            }),
            attached,
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
        attached: bool,
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
                dma_buf: narf_filesystem::dma_buf::DmaBufObject::new(),
            }),
            attached,
        );
    }

    /// Record a host-only blob (e.g. non-mappable VRAM) — no CPU mapping.
    pub(crate) fn insert_host_only(
        &self,
        handle: u32,
        resource_id: u32,
        size: u64,
        attached: bool,
    ) {
        self.bind(
            handle,
            Arc::new(VirtGpuResource {
                resource_id,
                backing: Some(ResourceBacking::HostOnly { size }),
                blob_mem: Some(narf_drivers_virtio::gpu_pci::BLOB_MEM_HOST3D),
                host3d_blob: true,
                host_owned: true,
                last_fence: narf_lib::sync::IrqSafeSpinLock::new(None),
                dma_buf: narf_filesystem::dma_buf::DmaBufObject::new(),
            }),
            attached,
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
        narf_drivers_virtio::pci::VirtioPciError::OutOfMemory => FsError::OutOfMemory,
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
        // Linux `virtio_gpu_cmd_submit` queues it without waiting; the
        // control queue runs it before the RESOURCE_CREATE_BLOB below.
        dev.submit_virgl_fenced(state.ctx_id, None, &cmd_bytes)
            .map_err(map_gpu_transport_error)?;
    }
    let handle = state.allocate_handle();
    let resource_id = NEXT_VIRTGPU_RESOURCE_ID.fetch_add(1, Ordering::Relaxed);
    // Linux attaches every GEM object to the opener's VirGL context when its
    // handle is created (virtio_gpu_gem_object_open), blobs included, and
    // detaches it on handle close. virglrenderer resolves a resource named in
    // a context's command stream only through that context's attached set, so
    // an unattached blob is an "Illegal resource" to the context that made it.
    let attach = dev.virgl_enabled();
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
                attach,
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
                state.insert_host_visible(handle, resource_id, base, offset, req.size, attach);
            } else {
                state.insert_host_only(handle, resource_id, req.size, attach);
            }
        }

        _ => return Err(FsError::InvalidData),
    }
    if attach {
        if let Err(error) = dev.attach_virgl_resource(state.ctx_id, resource_id) {
            // Not attached, so no detach: dropping the binding unrefs it.
            drop(state.take(handle));
            return Err(map_gpu_transport_error(error));
        }
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

/// The DRM syncobj ioctls (`drm::syncobj_ioctl`) on any driver's open,
/// against the open's own table, for a kernel caller (no descriptor table).
/// `timeline`: the driver has `DRIVER_SYNCOBJ_TIMELINE` (amdgpu does,
/// virtio-gpu does not). User opens go through [`dispatch_syncobj_user`].
pub(crate) fn dispatch_syncobj(
    cmd: u32,
    arg: usize,
    state: &VirtGpuRenderState,
    timeline: bool,
) -> Option<Result<u64, FsError>> {
    crate::drm::syncobj_ioctl::dispatch_sync(
        crate::drm_uapi::ioc_nr(cmd),
        arg,
        &state.syncobjs,
        timeline,
    )
}

/// The DRM syncobj ioctls from a user open: fd export/import through
/// `context`, and waits that park the syscall (`IoctlContext::restart_after`).
/// `None` for any other ioctl or a non-DRM ('d') command.
pub(crate) async fn dispatch_syncobj_user(
    cmd: u32,
    arg: usize,
    state: &VirtGpuRenderState,
    timeline: bool,
    context: &dyn IoctlContext,
) -> Option<Result<u64, FsError>> {
    if (cmd >> 8) & 0xff != u32::from(b'd') {
        return None;
    }
    crate::drm::syncobj_ioctl::dispatch(
        crate::drm_uapi::ioc_nr(cmd),
        arg,
        &state.syncobjs,
        timeline,
        context,
    )
    .await
}

impl VirtGpuRenderState {
    /// This open's syncobj table.
    pub(crate) fn syncobjs(
        &self,
    ) -> &narf_lib::sync::IrqSafeSpinLock<crate::drm::syncobj::SyncObjTable> {
        &self.syncobjs
    }
}

fn handle_syncobj(nr: u32, arg: usize, state: &VirtGpuRenderState) -> Result<u64, FsError> {
    crate::drm::syncobj_ioctl::dispatch_sync(nr, arg, &state.syncobjs, false)
        .unwrap_or(Err(FsError::Unsupported))
}

/// Whether `cmd` is DRM_IOCTL_WAIT_VBLANK, which a user file waits out
/// asynchronously (`wait_vblank_for_file`).
pub fn is_wait_vblank_ioctl(cmd: u32) -> bool {
    drm_uapi::ioc_nr(cmd) == 0x3A
}

/// DRM_IOCTL_WAIT_VBLANK on a primary file, sleeping rather than spinning.
pub(crate) async fn wait_vblank_for_file(
    card_index: u32,
    arg: usize,
    events: &EventQueue,
) -> Result<u64, FsError> {
    let mode_state = crate::drm_registry::mode_state(card_index).ok_or(FsError::Unsupported)?;
    // Any authenticated primary open may wait (Linux flags 0).
    wait_vblank(&mode_state, arg, &DrmFileCtx::primary(false), Some(events)).await
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

/// Whether `cmd` is the virtio-gpu resource fence-wait ioctl.
///
/// `FileOps::ioctl_user` uses this to move the only potentially long-lived
/// virtgpu ioctl onto the userspace task's async path. Other commands stay on
/// the normal synchronous dispatcher because they complete their controlq
/// round-trip before returning.
pub(crate) fn is_virtgpu_wait_ioctl(cmd: u32) -> bool {
    cmd == drm_uapi::DRM_IOCTL_VIRTGPU_WAIT
}

/// Async form of [`drm_uapi::DRM_IOCTL_VIRTGPU_WAIT`].
///
/// This runs through `FileOps::ioctl_user`, whose future parks the current
/// userspace task. It is deliberately separate from the synchronous DRM
/// dispatcher below: driving the IRQ-backed fence future with a synchronous
/// poll would recreate the compositor busy loop this path avoids.
pub(crate) async fn wait_virtgpu_render(
    arg: usize,
    state: &VirtGpuRenderState,
) -> Result<u64, FsError> {
    let (fence, nowait) = virtgpu_wait_request(arg, state)?;
    let Some(fence) = fence else {
        // Never referenced by a fenced submission — idle. The synchronous
        // TRANSFER/CREATE paths complete before their ioctls return, so they
        // leave no wait obligation.
        return Ok(0);
    };
    if nowait {
        return if fence.is_device_signalled() {
            Ok(0)
        } else {
            // FsError::Busy → EBUSY at the syscall layer, matching Linux's
            // dma_resv_test_signaled() == false path.
            Err(FsError::Busy)
        };
    }
    if fence.wait_device_async(15_000).await {
        Ok(0)
    } else {
        Err(FsError::Busy)
    }
}

/// Read and resolve a VIRTGPU_WAIT request without waiting. Keeping the
/// request decoding shared makes the synchronous DRM dispatcher and the async
/// userspace-file path agree on NOWAIT, missing-handle, and idle-resource
/// semantics.
fn virtgpu_wait_request(
    arg: usize,
    state: &VirtGpuRenderState,
) -> Result<(Option<Arc<VirtGpuFence>>, bool), FsError> {
    const VIRTGPU_WAIT_NOWAIT: u32 = 1;
    let req: drm_uapi::DrmVirtGpuWaitUapi = read_uapi(arg)?;
    let resource = state.find(req.handle).ok_or(FsError::NotFound)?;
    let fence = resource.last_fence.lock().clone();
    Ok((fence, req.flags & VIRTGPU_WAIT_NOWAIT != 0))
}

/// Synchronous compatibility implementation for direct in-kernel callers of
/// [`dispatch_virtgpu_render`]. The actual `/dev/dri/*` ioctl route uses
/// [`wait_virtgpu_render`] above and therefore parks the userspace task.
fn wait_virtgpu_render_sync(arg: usize, state: &VirtGpuRenderState) -> Result<u64, FsError> {
    let (fence, nowait) = virtgpu_wait_request(arg, state)?;
    let Some(fence) = fence else {
        return Ok(0);
    };
    if nowait {
        return if fence.is_device_signalled() {
            Ok(0)
        } else {
            Err(FsError::Busy)
        };
    }
    if fence.wait_device(15_000) {
        Ok(0)
    } else {
        Err(FsError::Busy)
    }
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
    // DRM syncobj ioctls (`drm::syncobj_ioctl`). The DRM native context
    // creates and uses syncobjs; route them to this open's per-fd table.
    // Dispatched by number so struct-size variations don't matter. virtio-gpu
    // has no DRIVER_SYNCOBJ_TIMELINE, so the timeline ones are -EOPNOTSUPP.
    if crate::drm::syncobj_ioctl::is_syncobj_ioctl(ioc_nr(cmd)) {
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
        DRM_IOCTL_VIRTGPU_WAIT => wait_virtgpu_render_sync(arg, state),
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
                            .fence()
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
                resource.dma_buf.resv.add_fence(
                    fence.clone() as Arc<dyn narf_filesystem::DrmFence>,
                    narf_filesystem::dma_buf::DmaResvUsage::Write,
                );
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
                    if let Ok(obj) = table.get(dep.handle) {
                        obj.reset();
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

/// Read `len` bytes from a user pointer into a kernel `Vec<u8>`.
///
/// Linux `copy_from_user`: [`access_ok`] confines the whole range to the
/// user half first (`arch/x86/include/asm/uaccess_64.h::__access_ok`), then
/// the transfer runs through the exception-table-guarded copy
/// (`narf_arch::x86_64::smap::copy_user_guarded`, Linux
/// `copy_user_generic` + its extable fixup), so an unmapped or
/// concurrently-unmapped buffer is `EFAULT` instead of a kernel #PF.
/// Every failure of either step is [`FsError::BadAddress`] (`EFAULT`).
///
/// # Safety
/// The caller must hold the syscall trap context (not IRQ context, the
/// calling task's address space active). `uptr` itself may be hostile.
pub(crate) unsafe fn copy_in(uptr: usize, len: usize) -> Result<Vec<u8>, FsError> {
    if len > IOCTL_MAX_BUF {
        return Err(FsError::InvalidData);
    }
    if !access_ok(uptr as u64, len) {
        return Err(FsError::BadAddress);
    }
    let mut out = vec![0u8; len];
    // SAFETY: `out` is a live kernel buffer of `len` bytes; the user side
    // is range-checked above and the guarded copy survives a fault on it.
    unsafe { guarded_copy(out.as_mut_ptr(), uptr as *const u8, len)? };
    Ok(out)
}

/// Write a kernel slice back to a user pointer: Linux `copy_to_user`, with
/// the same [`access_ok`] range check and fault-guarded transfer as
/// [`copy_in`]. Any failure is [`FsError::BadAddress`] (`EFAULT`).
///
/// # Safety
/// As [`copy_in`].
pub(crate) unsafe fn copy_out(uptr: usize, bytes: &[u8]) -> Result<(), FsError> {
    if !access_ok(uptr as u64, bytes.len()) {
        return Err(FsError::BadAddress);
    }
    // SAFETY: `bytes` is a live kernel slice; the user side is range-checked
    // above and the guarded copy survives a fault on it.
    unsafe { guarded_copy(uptr as *mut u8, bytes.as_ptr(), bytes.len()) }
}

/// First address above the user half of the 48-bit canonical VA space on
/// both supported architectures. The syscall layer's `validate_user_range`
/// splits at the same bit, so an ioctl pointer the trap layer would accept
/// through [`IoctlContext`] is accepted here and nothing else is.
const USER_VA_LIMIT: u64 = 1 << 47; // linux: n/a (NARF user/kernel split, = userspace USER_VA_LIMIT)

/// Linux `__access_ok` (`arch/x86/include/asm/uaccess_64.h`): the sum
/// `addr + size` must not wrap and must stay inside the user half. Null is
/// rejected too (every DRM pointer field this guards treats 0 as "absent"
/// before calling, so a null that reaches here is a fault, as before).
///
/// A canonical *kernel* pointer is rejected here rather than left to SMAP:
/// the guarded copy runs inside STAC/CLAC, and SMAP never faults a
/// supervisor page anyway, so without this an INFO `return_pointer`, a
/// GEM_METADATA buffer or a VERSION name pointer aimed at kernel memory
/// would be an arbitrary kernel read/write.
fn access_ok(addr: u64, len: usize) -> bool {
    if addr == 0 {
        return false;
    }
    let Some(end) = addr.checked_add(len as u64) else {
        return false;
    };
    if end <= USER_VA_LIMIT {
        return true;
    }
    #[cfg(feature = "kernel-test")]
    if kernel_test_buffers::allowed(addr, end) {
        return true;
    }
    false
}

/// Fault-guarded copy; a caught fault is `EFAULT`.
///
/// # Safety
/// The kernel side of the copy must be valid for `len` bytes; the user side
/// must have passed [`access_ok`].
unsafe fn guarded_copy(dst: *mut u8, src: *const u8, len: usize) -> Result<(), FsError> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: forwarded from the caller; the arch helper arms the per-CPU
    // recovery probe and the STAC/CLAC window itself.
    #[cfg(target_arch = "x86_64")]
    let copied = unsafe { narf_arch::x86_64::smap::copy_user_guarded(dst, src, len) };
    // SAFETY: as above.
    #[cfg(target_arch = "aarch64")]
    let copied = unsafe { narf_arch::aarch64::uaccess::copy_user_guarded(dst, src, len) };
    copied.map_err(|_| FsError::BadAddress)
}

/// Test-build-only relaxation of [`access_ok`] for the in-kernel smokes,
/// which drive the ioctl handlers with kernel stack/heap buffers standing in
/// for user memory (well over a thousand of them). Compiled only with
/// `kernel-test`; a production build has no path that accepts a kernel
/// address.
///
/// Even here the relaxation accepts only a range that lies entirely in the
/// canonical kernel half (never one straddling the hole or the user/kernel
/// boundary). A [`StrictUserCopies`] guard turns it off on the calling CPU
/// so a test can assert the production predicate end to end; the guard may
/// name one kernel buffer that keeps standing in for user memory (the ioctl
/// struct itself), so a test can aim a pointer *inside* that struct at the
/// kernel and see exactly that pointer refused.
#[cfg(feature = "kernel-test")]
pub(crate) mod kernel_test_buffers {
    use core::sync::atomic::{AtomicU64, Ordering};

    use narf_lib::percpu::{current_cpu, MAX_CPUS};

    /// Per-CPU strict window `[start, end)`: `start == 0` means no strict
    /// scope is open; otherwise only kernel ranges inside the window pass.
    /// Keyed on the CPU, as the syscall layer's `kernel_buf_scope` is,
    /// because a smoke runs its block straight through on one CPU.
    static START: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
    static END: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

    /// While alive, the DRM copy helpers apply the production predicate on
    /// the CPU that created it, except for the one stand-in buffer.
    // The guard is only opened by the x86_64-only DRM smokes.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub(crate) struct StrictUserCopies {
        cpu: usize,
        saved: (u64, u64),
    }

    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    impl StrictUserCopies {
        /// Strict for every kernel address.
        pub(crate) fn new() -> Self {
            Self::open(u64::MAX, u64::MAX)
        }

        /// Strict except for `[base, base + len)`, which keeps standing in
        /// for user memory.
        pub(crate) fn allowing(base: usize, len: usize) -> Self {
            Self::open(base as u64, base as u64 + len as u64)
        }

        fn open(start: u64, end: u64) -> Self {
            let cpu = current_cpu();
            let saved = (
                START[cpu].swap(start, Ordering::AcqRel),
                END[cpu].swap(end, Ordering::AcqRel),
            );
            Self { cpu, saved }
        }
    }

    impl Drop for StrictUserCopies {
        fn drop(&mut self) {
            START[self.cpu].store(self.saved.0, Ordering::Release);
            END[self.cpu].store(self.saved.1, Ordering::Release);
        }
    }

    /// `[addr, end)` is wholly inside the canonical kernel half and, when a
    /// strict scope is open on this CPU, inside its stand-in buffer.
    pub(super) fn allowed(addr: u64, end: u64) -> bool {
        const KERNEL_HALF: u64 = 0xffff_8000_0000_0000; // linux: n/a (48-bit canonical kernel half)
        if addr < KERNEL_HALF || end <= addr {
            return false;
        }
        let cpu = current_cpu();
        let start = START[cpu].load(Ordering::Acquire);
        start == 0 || (addr >= start && end <= END[cpu].load(Ordering::Acquire))
    }
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
        // In-kernel callers block by spinning, as the fence waits do; a
        // user file's ioctl sleeps instead (`wait_vblank`).
        IoctlCmd::WaitVblank => {
            narf_scheduler::block_on_spin(wait_vblank(&mode_state, arg, &ctx, events))
        }
        IoctlCmd::CrtcGetSequence => handle_crtc_get_sequence(&mode_state, arg, &ctx),
        IoctlCmd::CrtcQueueSequence => handle_crtc_queue_sequence(&mode_state, arg, &ctx, events),
        IoctlCmd::ModeObjGetProperties => handle_obj_getproperties(&mode_state, arg, &ctx),
        // Universal planes (synthesised PRIMARY plane per CRTC) — weston
        // needs these to find an output's primary plane on the legacy path.
        IoctlCmd::ModeGetPlaneRes => handle_getplane_res(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetPlane => handle_getplane(&mode_state, arg, &ctx),
        IoctlCmd::ModeSetPlane => handle_setplane(card_index, &mode_state, arg, &ctx),
        IoctlCmd::ModeGetProperty => handle_getproperty(arg),
        IoctlCmd::ModeConnectorSetProperty => {
            handle_set_property(card_index, &mode_state, arg, &ctx, false)
        }
        IoctlCmd::ModeObjSetProperty => {
            handle_set_property(card_index, &mode_state, arg, &ctx, true)
        }
        IoctlCmd::ModeGetPropBlob => handle_getpropblob(&mode_state, arg, &ctx),
        // SETGAMMA / GETGAMMA: the legacy gamma of a color-managed CRTC
        // (drm_mode_gamma_set_ioctl / drm_mode_gamma_get_ioctl). Other
        // cards scan out the framebuffer verbatim (no hardware gamma LUT):
        // SETGAMMA is accepted as a no-op there, so modetest's
        // post-modeset gamma reset succeeds instead of warning.
        IoctlCmd::ModeSetGamma => handle_gamma(card_index, &mode_state, arg, &ctx, true),
        IoctlCmd::ModeGetGamma => handle_gamma(card_index, &mode_state, arg, &ctx, false),
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
        // GET_MAGIC (_IOR) — this open's magic token (`drm_getmagic`).
        // Render clients are refused: neither magic ioctl carries
        // DRM_RENDER_ALLOW, so `drm_ioctl_permit` returns EACCES. `drm_ioctl`
        // still copies the (zeroed) kdata back afterwards, and a faulting
        // copy-out overrides the return code with EFAULT.
        IoctlCmd::GetMagic => {
            let (magic, ret) = if ctx.is_render_client() {
                (0u32, Err(FsError::PermissionDenied))
            } else {
                (mode_state.lock().get_magic(open_id), Ok(0))
            };
            // SAFETY: `arg` is the user drm_auth ptr; copy_out rejects NULL
            // and SMAP-brackets the 4-byte write.
            unsafe { copy_out(arg, &magic.to_le_bytes())? };
            ret
        }
        // AUTH_MAGIC (_IOW) is DRM_MASTER-only. `drm_ioctl` copies the arg in
        // first (EFAULT), then `drm_ioctl_permit` refuses a non-master or
        // render caller (EACCES), then `drm_authmagic` returns EINVAL for a
        // magic no open holds. libdrm's `drmIsMaster()` is literally
        // `drmAuthMagic(fd, 0) != -EACCES`, so accepting every call made each
        // fd look like master: kwin's createNonMasterFd() then ran DROP_MASTER
        // on a non-master fd, got EINVAL, and answered Xwayland's
        // wp_drm_lease_device_v1 bind with an invalid drm_fd — which libwayland
        // cannot marshal, so kwin dropped the client and Xwayland exited on EOF.
        IoctlCmd::AuthMagic => {
            // SAFETY: `arg` is the user drm_auth ptr; copy_in rejects NULL
            // and SMAP-brackets the 4-byte read.
            let auth = unsafe { copy_in(arg, 4)? };
            if ctx.is_render_client() || !mode_state.lock().is_master(open_id) {
                return Err(FsError::PermissionDenied);
            }
            let magic = u32::from_le_bytes([auth[0], auth[1], auth[2], auth[3]]);
            if mode_state.lock().auth_magic(magic) {
                Ok(0)
            } else {
                Err(FsError::InvalidData) // → EINVAL
            }
        }
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
        // DIRTYFB — the client wrote into a framebuffer on screen; a CRTC
        // that copies (rather than scans the dumb buffer in place) presents
        // it again. Xorg's modesetting driver relies on it for its shadow.
        IoctlCmd::ModeDirtyFb => handle_dirty_fb(card_index, &mode_state, arg, &ctx),
        // CURSOR / CURSOR2 — a card with native cursor planes (Navi48)
        // updates the CRTC's cursor plane (drm_mode_cursor_universal).
        // Otherwise there is no hardware cursor plane: funnel the pointer
        // position + visibility into narf_console so narf_fb's cursor
        // renderer composites a sprite onto the scanout. Without this the
        // compositor's pointer is invisible (the ioctl would otherwise be a
        // silent no-op through the generic path).
        IoctlCmd::ModeCursor => handle_cursor(card_index, &mode_state, arg, false, &ctx),
        IoctlCmd::ModeCursor2 => handle_cursor(card_index, &mode_state, arg, true, &ctx),
        // GEM_CLOSE — free dumb backing if present.
        IoctlCmd::GemClose => handle_gem_close(&mode_state, arg, &ctx),
        // RMFB of a framebuffer on screen turns its CRTC off; the native
        // display follows.
        IoctlCmd::ModeRmFb => {
            // SAFETY: `arg` is the user drm_mode_rmfb pointer (a u32 fb id).
            let fb_id = u32::from_le_bytes(unsafe { copy_in(arg, 4)? }[..4].try_into().unwrap());
            let shown: Vec<u32> = mode_state
                .lock()
                .crtcs
                .iter()
                .filter(|c| c.primary_fb == Some(fb_id))
                .map(|c| c.id)
                .collect();
            let overlaid: Vec<u32> = mode_state
                .lock()
                .native_planes
                .iter()
                .filter(|p| p.is_overlay() && p.fb_id == Some(fb_id))
                .filter_map(|p| p.crtc_id)
                .collect();
            let cursors: Vec<u32> = mode_state
                .lock()
                .native_planes
                .iter()
                .filter(|p| p.is_cursor() && p.fb_id == Some(fb_id))
                .filter_map(|p| p.crtc_id)
                .collect();
            let result = handle_generic(&mode_state, cmd, arg, &ctx);
            #[cfg(feature = "amdgpu")]
            if result.is_ok() && crate::drm_registry::driver_name(card_index) == Some("amdgpu") {
                for crtc_id in shown {
                    if let Some(display) = crate::amdgpu_native_kms::crtc_display(crtc_id) {
                        crate::amdgpu_native_kms::request_display_active(display, false);
                    }
                }
                // drm_framebuffer_remove disabled the overlays scanning it:
                // their displays light without them.
                let displays = crate::drm_native_planes::displays(&mode_state.lock());
                for crtc_id in overlaid {
                    if let Some(display) = crate::amdgpu_native_kms::crtc_display(crtc_id) {
                        let setup = displays
                            .iter()
                            .find(|d| d.crtc_id == crtc_id)
                            .map_or(crate::amdgpu_navi48_boot::PlaneSetup::NONE, |d| d.setup);
                        crate::amdgpu_native_kms::request_display_planes(display, setup);
                    }
                }
                // ... and the cursors scanning it go off.
                for crtc_id in cursors {
                    if let Some(display) = crate::amdgpu_native_kms::crtc_display(crtc_id) {
                        crate::amdgpu_native_kms::request_display_cursor(display, None, (0, 0));
                    }
                }
            }
            result
        }
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
    let (props, values) = {
        let card = mode_state.lock();
        let crtc_id = card
            .encoder(info.encoder_id)
            .ok()
            .and_then(|encoder| encoder.crtc_id)
            .unwrap_or(0);
        connector_properties(&card, info.connector_id, crtc_id)
    };
    if props_ptr != 0 && prop_values_ptr != 0 && user_count_props as usize >= props.len() {
        let prop_ids: Vec<u8> = props.iter().flat_map(|p| p.to_le_bytes()).collect();
        let prop_values: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        // SAFETY: both are user out-pointers the caller sized for every
        // property after the counting pass; ids are u32, values u64.
        unsafe {
            copy_out(props_ptr as usize, &prop_ids)?;
            copy_out(prop_values_ptr as usize, &prop_values)?;
        }
    }

    // Write the struct back, preserving the user's out-pointers (first 32
    // bytes) and updating counts + connector fields (offsets 32..76).
    let mut out = in_bytes;
    out[32..36].copy_from_slice(&info.count_modes.to_le_bytes());
    out[36..40].copy_from_slice(&(props.len() as u32).to_le_bytes());
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

// ── Vblank ioctls (drm_vblank.c) ─────────────────────────────────────

const VBLANK_RELATIVE: u32 = 0x1;
const VBLANK_HIGH_CRTC_MASK: u32 = 0x3e;
const VBLANK_EVENT: u32 = 0x400_0000;
const VBLANK_NEXTONMISS: u32 = 0x1000_0000;
const VBLANK_SECONDARY: u32 = 0x2000_0000;
const VBLANK_SIGNAL: u32 = 0x4000_0000;
const VBLANK_FLAGS_MASK: u32 = VBLANK_EVENT | VBLANK_SIGNAL | VBLANK_SECONDARY | VBLANK_NEXTONMISS;
/// `wait_event_interruptible_timeout(..., msecs_to_jiffies(3000))`.
const VBLANK_WAIT_NS: u64 = 3_000_000_000;

type EventQueue = narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>;
type ModeState = alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>;

/// `widen_32_to_64`: the 64-bit count nearest `current` whose low half is
/// `seq`.
fn widen_vblank(seq: u32, current: u64) -> u64 {
    current.wrapping_add_signed(i64::from(seq.wrapping_sub(current as u32) as i32))
}

/// A blocking WAIT_VBLANK still to be waited out.
pub(crate) struct VblankBlock {
    source: crate::drm::card::VblankSource,
    crtc_id: u32,
    target: u64,
    last: crate::drm::card::VblankTime,
}

/// `drm_wait_vblank_reply`: the count and its timestamp.
fn wait_vblank_reply(arg: usize, t: crate::drm::card::VblankTime) -> Result<(), FsError> {
    let mut reply = [0u8; 20];
    reply[0..4].copy_from_slice(&(t.count as u32).to_le_bytes());
    reply[4..12].copy_from_slice(&((t.ns / 1_000_000_000) as i64).to_le_bytes());
    reply[12..20].copy_from_slice(&(((t.ns % 1_000_000_000) / 1_000) as i64).to_le_bytes());
    // SAFETY: `arg` is the user drm_wait_vblank pointer; the reply's
    // sequence and timeval follow its 4-byte type field.
    unsafe { copy_out(arg + 4, &reply) }
}

/// DRM_IOCTL_WAIT_VBLANK up to the wait: validate, resolve the CRTC and
/// target (Linux `drm_wait_vblank_ioctl`), then answer a query, a reached
/// target or an event request at once. A target still ahead is returned
/// for the caller to wait out.
fn wait_vblank_begin(
    mode_state: &ModeState,
    arg: usize,
    ctx: &DrmFileCtx,
    events: Option<&EventQueue>,
) -> Result<Option<VblankBlock>, FsError> {
    if ctx.is_render_client() {
        return Err(FsError::PermissionDenied);
    }
    // SAFETY: `arg` is the user drm_wait_vblank pointer (24 bytes).
    let bytes = unsafe { copy_in(arg, 24)? };
    let kind = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let sequence = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let signal = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let card = mode_state.lock();
    // A card without hardware vblanks has none (drm_dev_has_vblank).
    let source = card.vblank_source.ok_or(FsError::Unsupported)?;
    if kind & VBLANK_SIGNAL != 0
        || kind & !(VBLANK_RELATIVE | VBLANK_FLAGS_MASK | VBLANK_HIGH_CRTC_MASK) != 0
    {
        return Err(FsError::InvalidData);
    }
    let flags = kind & VBLANK_FLAGS_MASK;
    let index = match kind & VBLANK_HIGH_CRTC_MASK {
        0 => usize::from(flags & VBLANK_SECONDARY != 0),
        high => (high >> 1) as usize,
    };
    let crtc_id = card.crtcs.get(index).ok_or(FsError::InvalidData)?.id;
    // drm_vblank_get fails on a CRTC whose vblank is off.
    let t = card
        .vblank_time(crtc_id)
        .map_err(|_| FsError::InvalidData)?;
    let mut target = if kind & VBLANK_RELATIVE != 0 {
        t.count.wrapping_add(u64::from(sequence))
    } else {
        widen_vblank(sequence, t.count)
    };
    if flags & VBLANK_NEXTONMISS != 0 && crate::drm::card::vblank_passed(t.count, target) {
        target = t.count + 1;
    }
    if flags & VBLANK_EVENT != 0 {
        let mut queue = events.ok_or(FsError::InvalidData)?.lock();
        queue
            .ensure_flip_event_space(1)
            .map_err(|_| FsError::OutOfMemory)?;
        // A target already passed is sent at once with the current count.
        let passed = crate::drm::card::vblank_passed(t.count, target);
        let target = if passed { t.count } else { target };
        card.queue_vblank_event(&mut queue, signal, crtc_id, target, false)
            .map_err(|_| FsError::OutOfMemory)?;
        drop(queue);
        drop(card);
        // SAFETY: the reply sequence at offset 4 of the user struct.
        unsafe { copy_out(arg + 4, &(target as u32).to_le_bytes())? };
        return Ok(None);
    }
    drop(card);
    if crate::drm::card::vblank_passed(t.count, target) {
        wait_vblank_reply(arg, t)?;
        return Ok(None);
    }
    Ok(Some(VblankBlock {
        source,
        crtc_id,
        target,
        last: t,
    }))
}

/// DRM_IOCTL_WAIT_VBLANK, sleeping until the target vblank begins (a
/// timer at its predicted start, then rechecks), for at most 3 s (EBUSY).
/// A CRTC turned off ends the wait with its last count.
pub(crate) async fn wait_vblank(
    mode_state: &ModeState,
    arg: usize,
    ctx: &DrmFileCtx,
    events: Option<&EventQueue>,
) -> Result<u64, FsError> {
    let Some(mut block) = wait_vblank_begin(mode_state, arg, ctx, events)? else {
        return Ok(0);
    };
    let deadline = narf_time::wall::monotonic_ns().saturating_add(VBLANK_WAIT_NS);
    while let Some(t) = (block.source)(block.crtc_id) {
        block.last = t;
        if crate::drm::card::vblank_passed(t.count, block.target) {
            break;
        }
        let now = narf_time::wall::monotonic_ns();
        if now >= deadline {
            return Err(FsError::Busy);
        }
        let ahead = block.target.wrapping_sub(t.count).min(1 << 23);
        let at = t
            .start_ns
            .saturating_add(ahead.saturating_mul(t.period_ns))
            .min(deadline)
            .max(now + 250_000);
        narf_time::SleepUntil::new(narf_time::Deadline::after_us((at - now) / 1_000).as_instant())
            .await;
    }
    wait_vblank_reply(arg, block.last)?;
    Ok(0)
}

/// DRM_IOCTL_CRTC_GET_SEQUENCE (`drm_crtc_get_sequence_ioctl`).
fn handle_crtc_get_sequence(
    mode_state: &ModeState,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    if ctx.is_render_client() {
        return Err(FsError::PermissionDenied);
    }
    // SAFETY: `arg` is the user drm_crtc_get_sequence pointer (24 bytes).
    let bytes = unsafe { copy_in(arg, 24)? };
    let crtc_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let card = mode_state.lock();
    if card.vblank_source.is_none() {
        return Err(FsError::Unsupported);
    }
    let active = card.crtc(crtc_id).map_err(|_| FsError::NotFound)?.enabled;
    let t = card
        .vblank_time(crtc_id)
        .map_err(|_| FsError::InvalidData)?;
    drop(card);
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&u32::from(active).to_le_bytes());
    out[4..12].copy_from_slice(&t.count.to_le_bytes());
    out[12..20].copy_from_slice(&(t.ns as i64).to_le_bytes());
    // SAFETY: active, sequence and sequence_ns follow the 4-byte crtc_id.
    unsafe { copy_out(arg + 4, &out)? };
    Ok(0)
}

/// DRM_IOCTL_CRTC_QUEUE_SEQUENCE (`drm_crtc_queue_sequence_ioctl`).
fn handle_crtc_queue_sequence(
    mode_state: &ModeState,
    arg: usize,
    ctx: &DrmFileCtx,
    events: Option<&EventQueue>,
) -> Result<u64, FsError> {
    const RELATIVE: u32 = 1;
    const NEXT_ON_MISS: u32 = 2;
    if ctx.is_render_client() {
        return Err(FsError::PermissionDenied);
    }
    // SAFETY: `arg` is the user drm_crtc_queue_sequence pointer (24 bytes).
    let bytes = unsafe { copy_in(arg, 24)? };
    let crtc_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let sequence = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let user_data = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let card = mode_state.lock();
    if card.vblank_source.is_none() {
        return Err(FsError::Unsupported);
    }
    card.crtc(crtc_id).map_err(|_| FsError::NotFound)?;
    if flags & !(RELATIVE | NEXT_ON_MISS) != 0 {
        return Err(FsError::InvalidData);
    }
    let t = card
        .vblank_time(crtc_id)
        .map_err(|_| FsError::InvalidData)?;
    let mut target = if flags & RELATIVE != 0 {
        sequence.wrapping_add(t.count)
    } else {
        sequence
    };
    if flags & NEXT_ON_MISS != 0 && crate::drm::card::vblank_passed(t.count, target) {
        target = t.count + 1;
    }
    let mut queue = events.ok_or(FsError::InvalidData)?.lock();
    queue
        .ensure_flip_event_space(1)
        .map_err(|_| FsError::OutOfMemory)?;
    // A target already passed is sent at once with the current count.
    if crate::drm::card::vblank_passed(t.count, target) {
        target = t.count;
    }
    card.queue_vblank_event(&mut queue, user_data, crtc_id, target, true)
        .map_err(|_| FsError::OutOfMemory)?;
    drop(queue);
    drop(card);
    // SAFETY: the sequence field at offset 8 of the user struct.
    unsafe { copy_out(arg + 8, &target.to_le_bytes())? };
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
        // drm_crtc::gamma_size: the legacy LUT's, on CRTCs that have one.
        let gamma_size = card
            .crtc_color(crtc_id)
            .map_or(0, |_| crate::drm::card::LEGACY_GAMMA_SIZE as u32);
        out[28..32].copy_from_slice(&gamma_size.to_le_bytes());
        let mode_valid: u32 = crtc.mode.is_some() as u32;
        out[32..36].copy_from_slice(&mode_valid.to_le_bytes());
        match &crtc.mode {
            Some(m) => {
                let wire = card.mode_wire(m);
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
            if !atomic_card(&mode_state.lock()) {
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
/// The connector "Broadcast RGB" enum (drm_connector_attach_broadcast_rgb_property).
const BROADCAST_RGB_PROP_ID: u32 = 0x61;
/// An enum property's (value, name) entries.
type EnumEntries = [(u64, &'static [u8]); 3];
const BROADCAST_RGB_ENUMS: EnumEntries = [(0, b"Automatic"), (1, b"Full"), (2, b"Limited 16:235")];
/// The connector "vrr_capable" immutable bool and the CRTC "VRR_ENABLED"
/// bool (drm_connector_attach_vrr_capable_property, drm_mode_config's
/// prop_vrr_enabled): ranges 0..1, the latter settable and not ATOMIC-only.
const VRR_CAPABLE_PROP_ID: u32 = 0x62;
const CRTC_VRR_ENABLED_PROP_ID: u32 = 0x63;
/// amdgpu_dm's CRTC color management on DCN 4.0.1:
/// `drm_crtc_enable_color_mgmt(crtc, 0, true, MAX_COLOR_LUT_ENTRIES)`
/// attaches "CTM", "GAMMA_LUT" and the immutable "GAMMA_LUT_SIZE" (no
/// DEGAMMA_LUT: amdgpu_dm_crtc_init leaves it off DCN_VERSION_4_01).
const CRTC_CTM_PROP_ID: u32 = 0x64;
const CRTC_GAMMA_LUT_PROP_ID: u32 = 0x65;
const CRTC_GAMMA_LUT_SIZE_PROP_ID: u32 = 0x66;
/// MAX_COLOR_LUT_ENTRIES, the GAMMA_LUT_SIZE value.
const GAMMA_LUT_SIZE: u64 = 4096;
/// `sizeof(struct drm_color_ctm)`: nine S31.32 sign-magnitude u64s.
const CTM_BLOB_SIZE: usize = 72;
/// `sizeof(struct drm_color_lut)`, a GAMMA_LUT blob's element.
const COLOR_LUT_ENTRY_SIZE: usize = 8;
/// The connector "Colorspace" enum and "HDR_OUTPUT_METADATA" blob
/// (amdgpu_dm_connector_init_helper on HDMI and DP connectors).
const COLORSPACE_PROP_ID: u32 = 0x67;
const HDR_OUTPUT_METADATA_PROP_ID: u32 = 0x68;
/// drm_mode_create_{hdmi,dp}_colorspace_property for amdgpu_dm's
/// supported_colorspaces (BT709_YCC | OPRGB | BT2020_RGB | BT2020_YCC),
/// plus Default: the same list on HDMI and DP, in DRM_MODE_COLORIMETRY_*
/// order with drm_connector.c's colorspace_names.
const COLORSPACE_ENUMS: [(u64, &[u8]); 5] = [
    (0, b"Default"),
    (2, b"BT709_YCC"),
    (7, b"opRGB"),
    (9, b"BT2020_RGB"),
    (10, b"BT2020_YCC"),
];
/// The connector "max bpc" range (drm_connector_attach_max_bpc_property,
/// which amdgpu_dm calls with 8..16 on every connector, MST end devices
/// included).
const MAX_BPC_PROP_ID: u32 = 0x80;
/// drm_connector_attach_color_format_property, native HDMI only.
const COLOR_FORMAT_PROP_ID: u32 = 0x81;
const COLOR_FORMAT_ENUMS: [(u64, &[u8]); 5] = [
    (0, b"AUTO"),
    (1, b"RGB"),
    (2, b"YUV 4:4:4"),
    (3, b"YUV 4:2:2"),
    (4, b"YUV 4:2:0"),
];
const MAX_BPC_RANGE: [u64; 2] = [8, 16];
/// `sizeof(struct hdr_output_metadata)`, the size
/// drm_atomic_connector_set_property requires of an HDR_OUTPUT_METADATA blob.
const HDR_OUTPUT_METADATA_SIZE: usize = 32;
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
const DRM_PLANE_TYPE_OVERLAY: u64 = 0;
const DRM_PLANE_TYPE_PRIMARY: u64 = 1;
const DRM_PLANE_TYPE_CURSOR: u64 = 2;
const DRM_MODE_PROP_RANGE: u32 = 1 << 1;
const DRM_MODE_PROP_IMMUTABLE: u32 = 1 << 2;
const DRM_MODE_PROP_ENUM: u32 = 1 << 3;
const DRM_MODE_PROP_BLOB: u32 = 1 << 4;
const DRM_MODE_PROP_BITMASK: u32 = 1 << 5;
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
const DRM_MODE_OBJECT_ENCODER: u32 = 0xe0e0_e0e0;
const DRM_MODE_OBJECT_FB: u32 = 0xfbfb_fbfb;
const DRM_MODE_OBJECT_BLOB: u32 = 0xbbbb_bbbb;
const DRM_MODE_OBJECT_ANY: u32 = 0;

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
    if let Some(native) = card.native_output(connector_id) {
        return native.edid;
    }
    let m = conn.modes.first()?;
    Some(crate::drm::edid_gen::synth_edid(
        m.width,
        m.height,
        m.refresh_hz as u32,
    ))
}
/// DRM_FORMAT_XRGB8888 — the one scanout format the pixman path uses.
const DRM_FORMAT_XRGB8888: u32 = 0x3432_5258;
/// DRM_FORMAT_ARGB8888, which a CPU copy shows as XRGB8888.
const DRM_FORMAT_ARGB8888: u32 = 0x3432_5241;

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
    // The primaries, then a native card's overlay and cursor planes.
    let planes: Vec<u32> = {
        let card = mode_state.lock();
        synth_planes(&card)
            .into_iter()
            .map(|(id, _)| id)
            .chain(crate::drm_native_planes::overlay_ids(&card))
            .chain(crate::drm_native_planes::cursor_ids(&card))
            .collect()
    };
    if plane_id_ptr != 0 && user_count as usize >= planes.len() {
        let mut buf: Vec<u8> = Vec::with_capacity(planes.len() * 4);
        for id in &planes {
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
    let (possible_crtcs, formats, bound) = {
        let card = mode_state.lock();
        match synth_planes(&card)
            .into_iter()
            .find(|(id, _)| *id == plane_id)
        {
            Some((_, crtc_idx)) => (
                1u32 << crtc_idx,
                card.plane_formats.unwrap_or(&[DRM_FORMAT_XRGB8888]),
                (0, 0),
            ),
            // amdgpu_dm's overlays: possible on every CRTC (0xff), with
            // their CRTC and framebuffer as committed. A cursor plane is
            // possible on its own CRTC only (drm_crtc_init_with_planes) and
            // takes ARGB8888.
            None => match card
                .native_plane(plane_id)
                .filter(|p| p.primary_of.is_none())
            {
                Some(p) if p.is_cursor() => (
                    card.crtcs
                        .iter()
                        .position(|c| Some(c.id) == p.cursor_of)
                        .map_or(0, |i| 1u32 << i),
                    &crate::drm_native_planes::CURSOR_FORMATS[..],
                    (p.crtc_id.unwrap_or(0), p.fb_id.unwrap_or(0)),
                ),
                Some(p) => (
                    0xff,
                    card.overlay_formats.unwrap_or(&[]),
                    (p.crtc_id.unwrap_or(0), p.fb_id.unwrap_or(0)),
                ),
                None => return Err(FsError::InvalidData),
            },
        }
    };
    out[4..8].copy_from_slice(&bound.0.to_le_bytes()); // crtc_id
    out[8..12].copy_from_slice(&bound.1.to_le_bytes()); // fb_id
    out[12..16].copy_from_slice(&possible_crtcs.to_le_bytes());
    out[16..20].copy_from_slice(&0u32.to_le_bytes()); // gamma_size

    // The plane's formats (XRGB8888 on the CPU-copy cards); two-pass.
    if fmt_ptr != 0 && user_fmt_count as usize >= formats.len() {
        let bytes: Vec<u8> = formats.iter().flat_map(|f| f.to_le_bytes()).collect();
        // SAFETY: `fmt_ptr` is the user format-array out-pointer with room
        // for every format (checked above).
        unsafe { copy_out(fmt_ptr as usize, &bytes)? };
    }
    out[20..24].copy_from_slice(&(formats.len() as u32).to_le_bytes()); // count_format_types

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
    if prop_id == EDID_PROP_ID
        || prop_id == crate::drm_native_planes::IN_FORMATS_PROP_ID
        || prop_id == crate::drm_native_planes::IN_FORMATS_ASYNC_PROP_ID
    {
        out[20..24].copy_from_slice(&(DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE).to_le_bytes());
        out[24..56].fill(0);
        let name: &[u8] = match prop_id {
            EDID_PROP_ID => b"EDID",
            crate::drm_native_planes::IN_FORMATS_PROP_ID => b"IN_FORMATS",
            _ => b"IN_FORMATS_ASYNC",
        };
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
        VRR_CAPABLE_PROP_ID => Some((
            b"vrr_capable".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_IMMUTABLE,
            [0, 1],
        )),
        CRTC_VRR_ENABLED_PROP_ID => Some((b"VRR_ENABLED".as_slice(), DRM_MODE_PROP_RANGE, [0, 1])),
        // drm_property_create_range(dev, 0, "max bpc", 8, 16).
        MAX_BPC_PROP_ID => Some((b"max bpc".as_slice(), DRM_MODE_PROP_RANGE, MAX_BPC_RANGE)),
        // drm_mode_create_standard_properties: plain blobs and an immutable
        // 0..UINT_MAX range.
        CRTC_CTM_PROP_ID => Some((b"CTM".as_slice(), DRM_MODE_PROP_BLOB, [0, 0])),
        CRTC_GAMMA_LUT_PROP_ID => Some((b"GAMMA_LUT".as_slice(), DRM_MODE_PROP_BLOB, [0, 0])),
        CRTC_GAMMA_LUT_SIZE_PROP_ID => Some((
            b"GAMMA_LUT_SIZE".as_slice(),
            DRM_MODE_PROP_RANGE | DRM_MODE_PROP_IMMUTABLE,
            [0, u32::MAX as u64],
        )),
        HDR_OUTPUT_METADATA_PROP_ID => Some((
            b"HDR_OUTPUT_METADATA".as_slice(),
            DRM_MODE_PROP_BLOB,
            [0, 0],
        )),
        // amdgpu_dm's plane "alpha" and "zpos" ranges (the primary's zpos
        // immutable).
        p => crate::drm_native_planes::range_property(p).map(|(name, immutable, range)| {
            let flags = if immutable {
                DRM_MODE_PROP_RANGE | DRM_MODE_PROP_IMMUTABLE
            } else {
                DRM_MODE_PROP_RANGE
            };
            (name, flags, range)
        }),
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
    const PLANE_TYPE_ENUMS: EnumEntries = [(0, b"Overlay"), (1, b"Primary"), (2, b"Cursor")];
    type Enum = (&'static [u8], u32, &'static [(u64, &'static [u8])]);
    let (name, flags, enums): Enum = match prop_id {
        PLANE_TYPE_PROP_ID => (
            b"type",
            DRM_MODE_PROP_ENUM | DRM_MODE_PROP_IMMUTABLE,
            &PLANE_TYPE_ENUMS,
        ),
        BROADCAST_RGB_PROP_ID => (b"Broadcast RGB", DRM_MODE_PROP_ENUM, &BROADCAST_RGB_ENUMS),
        COLORSPACE_PROP_ID => (b"Colorspace", DRM_MODE_PROP_ENUM, &COLORSPACE_ENUMS),
        COLOR_FORMAT_PROP_ID => (b"color format", DRM_MODE_PROP_ENUM, &COLOR_FORMAT_ENUMS),
        crate::drm_native_planes::BLEND_PROP_ID => (
            b"pixel blend mode",
            DRM_MODE_PROP_ENUM,
            &crate::drm_native_planes::BLEND_ENUMS,
        ),
        crate::drm_native_planes::CURSOR_BLEND_PROP_ID => (
            b"pixel blend mode",
            DRM_MODE_PROP_ENUM,
            &crate::drm_native_planes::CURSOR_BLEND_ENUMS,
        ),
        crate::drm_native_planes::ROTATION_PROP_ID => (
            b"rotation",
            DRM_MODE_PROP_BITMASK,
            &crate::drm_native_planes::ROTATION_ENUMS,
        ),
        crate::drm_native_planes::COLOR_ENCODING_PROP_ID => (
            b"COLOR_ENCODING",
            DRM_MODE_PROP_ENUM,
            &crate::drm_native_planes::COLOR_ENCODING_ENUMS,
        ),
        crate::drm_native_planes::COLOR_RANGE_PROP_ID => (
            b"COLOR_RANGE",
            DRM_MODE_PROP_ENUM,
            &crate::drm_native_planes::COLOR_RANGE_ENUMS,
        ),
        _ => return Err(FsError::InvalidData),
    };
    out[20..24].copy_from_slice(&flags.to_le_bytes());
    out[24..56].fill(0);
    out[24..24 + name.len()].copy_from_slice(name);
    // For an ENUM property the entries go to ENUM_BLOB_PTR (offset 8) and
    // are counted by count_enum_blobs (offset 60); values_ptr/count_values
    // (offsets 0 and 56) MUST ALSO be populated with the valid enum values.
    // `modetest` iterates over both and asserts they are present.
    // Each enum entry is `drm_mode_property_enum { __u64 value; char name[32]; }` = 40 bytes.

    let values_ptr = u64::from_le_bytes(out[0..8].try_into().unwrap());
    let user_values_count = u32::from_le_bytes(out[56..60].try_into().unwrap());
    if values_ptr != 0 && user_values_count as usize >= enums.len() {
        let mut buf = alloc::vec![0u8; enums.len() * 8];
        for (i, (val, _)) in enums.iter().enumerate() {
            buf[i * 8..i * 8 + 8].copy_from_slice(&val.to_le_bytes());
        }
        // SAFETY: `values_ptr` is the user array out-pointer sized
        // for `user_values_count` >= `enums.len()` entries of 8 bytes each.
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
        // for `user_enum_count` >= `enums.len()` entries of 40 bytes each.
        unsafe { copy_out(enum_blob_ptr as usize, &buf)? };
    }
    out[56..60].copy_from_slice(&(enums.len() as u32).to_le_bytes()); // count_values
    out[60..64].copy_from_slice(&(enums.len() as u32).to_le_bytes()); // count_enum_blobs

    // SAFETY: `arg` is the validated 64-byte out-pointer.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// A connector's properties and current values: the EDID blob, the atomic
/// CRTC_ID, and "Broadcast RGB", "max bpc", "Colorspace",
/// "HDR_OUTPUT_METADATA" and "vrr_capable" where the connector has them.
fn connector_properties(
    card: &crate::drm::card::Card,
    connector_id: u32,
    crtc_id: u32,
) -> (Vec<u32>, Vec<u64>) {
    let mut props = alloc::vec![EDID_PROP_ID, CONNECTOR_CRTC_ID_PROP_ID];
    let mut values = alloc::vec![edid_blob_id(connector_id) as u64, crtc_id as u64];
    if let Some(value) = card
        .native_output(connector_id)
        .and_then(|n| n.broadcast_rgb)
    {
        props.push(BROADCAST_RGB_PROP_ID);
        values.push(u64::from(value));
    }
    // amdgpu_dm_connector_init_helper attaches "max bpc" after
    // Broadcast RGB, then Colorspace and HDR_OUTPUT_METADATA before
    // vrr_capable.
    if let Some(bpc) = card.native_output(connector_id).and_then(|n| n.max_bpc) {
        props.push(MAX_BPC_PROP_ID);
        values.push(u64::from(bpc));
    }
    if let Some(value) = card.native_output(connector_id).and_then(|n| n.colorspace) {
        props.push(COLORSPACE_PROP_ID);
        values.push(u64::from(value));
    }
    if let Some(blob) = card
        .native_output(connector_id)
        .and_then(|n| n.hdr_output_metadata)
    {
        props.push(HDR_OUTPUT_METADATA_PROP_ID);
        values.push(u64::from(blob));
    }
    if let Some(format) = card
        .native_output(connector_id)
        .and_then(|n| n.color_format)
    {
        props.push(COLOR_FORMAT_PROP_ID);
        values.push(format as u64);
    }
    if let Some(capable) = card.native_output(connector_id).and_then(|n| n.vrr_capable) {
        props.push(VRR_CAPABLE_PROP_ID);
        values.push(u64::from(capable));
    }
    (props, values)
}

/// A CRTC color or connector HDR blob property value, validated as
/// drm_property_replace_blob_from_id does: 0 clears; otherwise the blob must
/// exist (EINVAL), be exactly `size` bytes when given and a whole number of
/// `element`-byte entries when given.
fn blob_value(
    card: &crate::drm::card::Card,
    value: u64,
    size: Option<usize>,
    element: Option<usize>,
) -> Result<u32, FsError> {
    if value == 0 {
        return Ok(0);
    }
    let id = u32::try_from(value).map_err(|_| FsError::InvalidData)?;
    let data = card.property_blob(id).ok_or(FsError::InvalidData)?;
    if size.is_some_and(|n| data.len() != n) || element.is_some_and(|n| data.len() % n != 0) {
        return Err(FsError::InvalidData);
    }
    Ok(id)
}

/// A CRTC's color properties' new values from one request: each is
/// `None` while the request leaves it alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CrtcColorChange {
    ctm: Option<u32>,
    gamma_lut: Option<u32>,
}

/// Decode one CRTC color property into `change`: EINVAL on a CRTC without
/// the property, for a blob of the wrong size, and (amdgpu_dm_verify_lut_sizes)
/// for a GAMMA_LUT of other than 4096 or 256 entries. Returns false for a
/// property that is not a color one.
fn crtc_color_property(
    card: &crate::drm::card::Card,
    crtc: u32,
    prop: u32,
    value: u64,
    change: &mut CrtcColorChange,
) -> Result<bool, FsError> {
    if !matches!(prop, CRTC_CTM_PROP_ID | CRTC_GAMMA_LUT_PROP_ID) {
        return Ok(false);
    }
    if card.crtc_color(crtc).is_none() {
        return Err(FsError::InvalidData);
    }
    if prop == CRTC_CTM_PROP_ID {
        change.ctm = Some(blob_value(card, value, Some(CTM_BLOB_SIZE), None)?);
        return Ok(true);
    }
    let id = blob_value(card, value, None, Some(COLOR_LUT_ENTRY_SIZE))?;
    if id != 0 {
        let entries = card
            .property_blob(id)
            .map_or(0, |b| b.len() / COLOR_LUT_ENTRY_SIZE);
        if entries != GAMMA_LUT_SIZE as usize && entries != crate::drm::card::LEGACY_GAMMA_SIZE {
            return Err(FsError::InvalidData);
        }
    }
    change.gamma_lut = Some(id);
    Ok(true)
}

/// Commit a CRTC's color change: the CRTC reports the new blobs (DRM's
/// color_mgmt_changed). Returns the native display and the committed CTM
/// and GAMMA_LUT bytes to program, which the caller requests after
/// releasing the card lock; None when nothing changed.
fn apply_crtc_color(
    card_index: u32,
    card: &mut crate::drm::card::Card,
    crtc: u32,
    change: CrtcColorChange,
) -> Option<(u8, CrtcColorRequest)> {
    let color = card.crtc_color.iter_mut().find(|c| c.crtc == crtc)?;
    let before = (color.ctm, color.gamma_lut);
    if let Some(id) = change.ctm {
        color.ctm = id;
    }
    if let Some(id) = change.gamma_lut {
        color.gamma_lut = id;
    }
    let (ctm, gamma_lut) = (color.ctm, color.gamma_lut);
    card.collect_blobs();
    if (ctm, gamma_lut) == before {
        return None;
    }
    // The committed state above is generic DRM state; turning it
    // into a native request is the amdgpu KMS's business alone.
    #[cfg(feature = "amdgpu")]
    {
        let bytes = |id: u32| {
            (id != 0)
                .then(|| card.property_blob(id).map(<[u8]>::to_vec))
                .flatten()
        };
        let request = crate::amdgpu_native_kms::CrtcColorRequest {
            ctm: bytes(ctm),
            gamma_lut: bytes(gamma_lut),
        };
        (crate::drm_registry::driver_name(card_index) == Some("amdgpu"))
            .then(|| crate::amdgpu_native_kms::crtc_display(crtc))
            .flatten()
            .map(|display| (display, request))
    }
    #[cfg(not(feature = "amdgpu"))]
    {
        let _ = card_index;
        None
    }
}

fn native_output_on_crtc(
    card: &crate::drm::card::Card,
    crtc: u32,
    connector: Option<u32>,
) -> Option<&crate::drm::card::NativeOutput> {
    let connector = connector.or_else(|| {
        card.connectors
            .iter()
            .find(|c| {
                c.encoder_id
                    .and_then(|id| card.encoder(id).ok())
                    .is_some_and(|e| e.crtc_id == Some(crtc))
            })
            .map(|c| c.id)
    })?;
    card.native_output(connector)
}

/// SETCRTC uses the same complete HDMI preflight as atomic modesetting.
#[cfg(feature = "amdgpu")]
fn setcrtc_output_format_supported(
    card: &crate::drm::card::Card,
    display: u8,
    connector: u32,
    mode: Option<crate::drm::ioctl::DrmModeModeInfo>,
    fourcc: u32,
    setup: crate::amdgpu_navi48_boot::PlaneSetup,
) -> bool {
    let committed = crate::drm_native_planes::displays(card);
    let mut routes = Vec::new();
    for n in &card.native {
        if n.connector == connector {
            routes.push(crate::amdgpu_native_kms::OutputRoute {
                display,
                connector,
                mode,
                planes: Some((fourcc, setup)),
            });
            continue;
        }
        let Some(crtc) = card
            .connector(n.connector)
            .ok()
            .and_then(|c| c.encoder_id)
            .and_then(|id| card.encoder(id).ok())
            .and_then(|e| e.crtc_id)
        else {
            continue;
        };
        if !card.crtc(crtc).is_ok_and(|c| c.enabled) {
            continue;
        }
        let Some(other) = crate::amdgpu_native_kms::crtc_display(crtc) else {
            continue;
        };
        if other == display {
            continue;
        }
        let planes = committed
            .iter()
            .find(|p| p.crtc_id == crtc)
            .map(|p| (p.primary_format, p.setup));
        routes.push(crate::amdgpu_native_kms::OutputRoute {
            display: other,
            connector: n.connector,
            mode: None,
            planes,
        });
    }
    let requests: Vec<_> = routes
        .iter()
        .filter_map(|r| {
            let native = card.native_output(r.connector)?;
            Some(crate::amdgpu_native_kms::OutputFormatRequest {
                display: r.display,
                connector: r.connector,
                mode: r.mode,
                planes: r.planes,
                max_bpc: native.max_bpc,
                color_format: native.color_format?,
            })
        })
        .collect();
    crate::amdgpu_native_kms::output_formats_supported(&requests, &routes)
}

/// A connector's Colorspace / HDR_OUTPUT_METADATA values from one request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ConnectorColorChange {
    color_format: Option<crate::drm::card::ColorFormat>,
    colorspace: Option<u32>,
    hdr_output_metadata: Option<u32>,
}

/// Decode one connector Colorspace or HDR_OUTPUT_METADATA value into
/// `change`: EINVAL on a connector without the property, off the enum, or
/// for a blob of other than `sizeof(struct hdr_output_metadata)` bytes.
/// Returns false for any other property.
fn connector_color_property(
    card: &crate::drm::card::Card,
    connector: u32,
    prop: u32,
    value: u64,
    change: &mut ConnectorColorChange,
) -> Result<bool, FsError> {
    let native = card.native_output(connector);
    match prop {
        COLOR_FORMAT_PROP_ID => {
            if native.and_then(|n| n.color_format).is_none() {
                return Err(FsError::InvalidData);
            }
            change.color_format =
                Some(crate::drm::card::ColorFormat::from_linux(value).ok_or(FsError::InvalidData)?);
        }
        COLORSPACE_PROP_ID => {
            if native.and_then(|n| n.colorspace).is_none()
                || !COLORSPACE_ENUMS.iter().any(|&(v, _)| v == value)
            {
                return Err(FsError::InvalidData);
            }
            change.colorspace = Some(value as u32);
        }
        HDR_OUTPUT_METADATA_PROP_ID => {
            if native.and_then(|n| n.hdr_output_metadata).is_none() {
                return Err(FsError::InvalidData);
            }
            change.hdr_output_metadata = Some(blob_value(
                card,
                value,
                Some(HDR_OUTPUT_METADATA_SIZE),
                None,
            )?);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// amdgpu_dm_connector_atomic_check for a connector driving CRTC `crtc`
/// (None: unchecked, as Linux skips a connector without one): new HDR
/// metadata must build an infoframe (amdgpu_dm_fill_hdr_info_packet,
/// EINVAL otherwise). On the native card (`native`) the stream must also
/// be able to signal the result: EINVAL for HDR metadata or a non-default
/// Colorspace that the connector's lit link cannot carry. Returns whether
/// the change needs a modeset: a new Colorspace does, and so does entering
/// or leaving HDR (metadata appearing or disappearing); changing the
/// metadata while it is set does not.
fn connector_color_check(
    card: &crate::drm::card::Card,
    native_card: bool,
    connector: u32,
    crtc: Option<u32>,
    change: ConnectorColorChange,
) -> Result<bool, FsError> {
    let Some(native) = card.native_output(connector) else {
        return Ok(false);
    };
    if crtc.is_none() {
        return Ok(false);
    }
    let mut modeset = change
        .colorspace
        .is_some_and(|v| Some(v) != native.colorspace)
        || change
            .color_format
            .is_some_and(|v| Some(v) != native.color_format);
    if let Some(new) = change.hdr_output_metadata {
        let old = native.hdr_output_metadata.unwrap_or(0);
        let bytes = |id: u32| (id != 0).then(|| card.property_blob(id)).flatten();
        // drm_connector_atomic_hdr_metadata_equal compares the bytes.
        if bytes(old) != bytes(new) {
            if let Some(data) = bytes(new) {
                #[cfg(feature = "amdgpu")]
                if !crate::amdgpu_native_kms::hdr_metadata_valid(data) {
                    return Err(FsError::InvalidData);
                }
                #[cfg(not(feature = "amdgpu"))]
                let _ = data;
            }
            modeset |= old == 0 || new == 0;
        }
    }
    let colorspace = change.colorspace.or(native.colorspace).unwrap_or(0);
    let hdr = change
        .hdr_output_metadata
        .or(native.hdr_output_metadata)
        .is_some_and(|id| id != 0);
    #[cfg(feature = "amdgpu")]
    let color_supported =
        crate::amdgpu_native_kms::connector_color_supported(connector, colorspace, hdr);
    #[cfg(not(feature = "amdgpu"))]
    let color_supported = {
        let _ = (colorspace, hdr);
        true
    };
    if native_card && !color_supported {
        return Err(FsError::InvalidData);
    }
    Ok(modeset)
}

/// Commit a connector's Colorspace / HDR_OUTPUT_METADATA: the connector
/// reports them. Returns what the native display owner must apply, which
/// the caller requests after releasing the card lock.
fn apply_connector_color(
    card_index: u32,
    card: &mut crate::drm::card::Card,
    connector: u32,
    change: ConnectorColorChange,
) -> Option<ConnectorColorRequest> {
    let native = card.native.iter_mut().find(|n| n.connector == connector)?;
    let before = (
        native.colorspace,
        native.hdr_output_metadata,
        native.color_format,
    );
    if let Some(format) = change.color_format {
        native.color_format = Some(format);
    }
    if let Some(v) = change.colorspace {
        native.colorspace = Some(v);
    }
    if let Some(id) = change.hdr_output_metadata {
        native.hdr_output_metadata = Some(id);
    }
    let after = (
        native.colorspace,
        native.hdr_output_metadata,
        native.color_format,
    );
    card.collect_blobs();
    // The committed state above is generic DRM state; turning it
    // into a native request is the amdgpu KMS's business alone.
    #[cfg(feature = "amdgpu")]
    {
        if after == before || crate::drm_registry::driver_name(card_index) != Some("amdgpu") {
            return None;
        }
        let hdr = after
            .1
            .filter(|&id| id != 0)
            .and_then(|id| card.property_blob(id))
            .map(<[u8]>::to_vec);
        Some(crate::amdgpu_native_kms::ConnectorColorRequest {
            connector,
            colorspace: after.0.unwrap_or(0),
            color_format: after.2.unwrap_or_default(),
            hdr_output_metadata: hdr,
        })
    }
    #[cfg(not(feature = "amdgpu"))]
    {
        let _ = (before, after, card_index);
        None
    }
}

/// A CRTC's "VRR_ENABLED" value, when the CRTC has the property.
fn crtc_vrr_enabled(card: &crate::drm::card::Card, crtc_id: u32) -> Option<bool> {
    card.vrr_enabled
        .iter()
        .find(|&&(id, _)| id == crtc_id)
        .map(|&(_, v)| v)
}

/// Validate a "VRR_ENABLED" value for `crtc` as drm_property_change_valid_get
/// does for a bool: EINVAL on a CRTC without it or a value above 1. Like
/// Linux, enabling is accepted whatever the sink or mode supports; the
/// display stays at fixed refresh when it cannot vary.
fn vrr_enabled_value(
    card: &crate::drm::card::Card,
    crtc: u32,
    value: u64,
) -> Result<bool, FsError> {
    if crtc_vrr_enabled(card, crtc).is_none() || value > 1 {
        return Err(FsError::InvalidData);
    }
    Ok(value != 0)
}

/// Commit a validated "VRR_ENABLED" value: the CRTC reports it. Returns the
/// native display to reprogram, which the caller requests after releasing
/// the card lock (the request takes the display owner's locks).
fn apply_vrr_enabled(
    card_index: u32,
    card: &mut crate::drm::card::Card,
    crtc: u32,
    value: bool,
) -> Option<(u8, bool)> {
    if let Some(slot) = card.vrr_enabled.iter_mut().find(|(id, _)| *id == crtc) {
        slot.1 = value;
    }
    #[cfg(feature = "amdgpu")]
    {
        (crate::drm_registry::driver_name(card_index) == Some("amdgpu"))
            .then(|| crate::amdgpu_native_kms::crtc_display(crtc))
            .flatten()
            .map(|display| (display, value))
    }
    #[cfg(not(feature = "amdgpu"))]
    {
        let _ = card_index;
        None
    }
}

/// Validate a "max bpc" value for `connector`, as
/// drm_property_change_valid_get does for a range: EINVAL for a connector
/// without the property or a value outside 8..=16.
fn max_bpc_value(card: &crate::drm::card::Card, connector: u32, value: u64) -> Result<u8, FsError> {
    let has = card
        .native_output(connector)
        .is_some_and(|n| n.max_bpc.is_some());
    if !has || !(MAX_BPC_RANGE[0]..=MAX_BPC_RANGE[1]).contains(&value) {
        return Err(FsError::InvalidData);
    }
    Ok(value as u8)
}

/// Whether a new "max bpc" on `connector` is a modeset: a changed
/// max_requested_bpc on a connector with a CRTC (its old state's, as
/// drm_atomic_helper_check_modeset sets that CRTC's connectors_changed).
fn max_bpc_modeset(card: &crate::drm::card::Card, connector: u32, bpc: u8) -> bool {
    let crtc = card
        .connector(connector)
        .ok()
        .and_then(|c| c.encoder_id)
        .and_then(|id| card.encoder(id).ok())
        .and_then(|e| e.crtc_id);
    crtc.is_some() && card.native_output(connector).and_then(|n| n.max_bpc) != Some(bpc)
}

/// Commit a validated "max bpc": the connector reports it and, on the
/// native card, the display driving it lights again with the new depth cap.
/// Returns the native request, which the caller makes after releasing the
/// card lock.
fn apply_max_bpc(
    card_index: u32,
    card: &mut crate::drm::card::Card,
    connector: u32,
    bpc: u8,
) -> Option<(u32, u8)> {
    let native = card.native.iter_mut().find(|n| n.connector == connector)?;
    if native.max_bpc == Some(bpc) {
        return None;
    }
    native.max_bpc = Some(bpc);
    (crate::drm_registry::driver_name(card_index) == Some("amdgpu")).then_some((connector, bpc))
}

/// Validate a "Broadcast RGB" value for `connector`, as
/// drm_property_change_valid_get does for an enum: EINVAL for a connector
/// without the property or a value outside its enum.
fn broadcast_rgb_value(
    card: &crate::drm::card::Card,
    connector: u32,
    value: u64,
) -> Result<u8, FsError> {
    let has = card
        .native_output(connector)
        .is_some_and(|n| n.broadcast_rgb.is_some());
    if !has || !BROADCAST_RGB_ENUMS.iter().any(|&(v, _)| v == value) {
        return Err(FsError::InvalidData);
    }
    Ok(value as u8)
}

/// Commit a validated "Broadcast RGB" value: the connector reports it and
/// the native display relights in the matching range.
fn apply_broadcast_rgb(
    card_index: u32,
    card: &mut crate::drm::card::Card,
    connector: u32,
    value: u8,
) {
    if let Some(native) = card.native.iter_mut().find(|n| n.connector == connector) {
        native.broadcast_rgb = Some(value);
    }
    #[cfg(feature = "amdgpu")]
    if crate::drm_registry::driver_name(card_index) == Some("amdgpu") {
        crate::amdgpu_native_kms::request_broadcast_rgb(value);
    }
}

/// drm_mode_obj_set_property_ioctl's lookup: `drm_mode_object_find(obj_id,
/// obj_type)` finds the object by id, of `obj_type` or of any type for
/// `DRM_MODE_OBJECT_ANY`, else ENOENT (an unknown type matches nothing);
/// one without properties (an encoder, framebuffer or blob) is EINVAL.
/// Returns the found object's type: a connector, CRTC or plane.
fn set_property_object(
    card: &crate::drm::card::Card,
    obj_id: u32,
    obj_type: u32,
) -> Result<u32, FsError> {
    let plane = || {
        #[cfg(feature = "amdgpu")]
        let native = crate::drm_native_planes::plane_state(card, obj_id).is_some();
        #[cfg(not(feature = "amdgpu"))]
        let native = false;
        native || synth_planes(card).iter().any(|(id, _)| *id == obj_id)
    };
    let found = [
        (DRM_MODE_OBJECT_CONNECTOR, card.connector(obj_id).is_ok()),
        (DRM_MODE_OBJECT_CRTC, card.crtc(obj_id).is_ok()),
        (DRM_MODE_OBJECT_PLANE, plane()),
        (DRM_MODE_OBJECT_ENCODER, card.encoder(obj_id).is_ok()),
        (DRM_MODE_OBJECT_FB, card.framebuffer(obj_id).is_ok()),
        (DRM_MODE_OBJECT_BLOB, card.property_blob(obj_id).is_some()),
    ]
    .into_iter()
    .find(|&(kind, present)| present && (obj_type == DRM_MODE_OBJECT_ANY || obj_type == kind))
    .map(|(kind, _)| kind)
    .ok_or(FsError::NotFound)?;
    match found {
        DRM_MODE_OBJECT_CONNECTOR | DRM_MODE_OBJECT_CRTC | DRM_MODE_OBJECT_PLANE => Ok(found),
        // `!arg_obj->properties`.
        _ => Err(FsError::InvalidData),
    }
}

/// DRM_IOCTL_MODE_SETPROPERTY (`struct drm_mode_connector_set_property`:
/// value@0, prop_id@8, connector_id@12) and DRM_IOCTL_MODE_OBJ_SETPROPERTY
/// (`struct drm_mode_obj_set_property`: value@0, prop_id@8, obj_id@12,
/// obj_type@16). Like drm_mode_obj_set_property_ioctl, an unknown object
/// is ENOENT and a property the object lacks is EINVAL. On an atomic card
/// every property of a connector, CRTC or plane goes through
/// set_property_atomic: a blocking one-property [`atomic_commit`] with
/// modesets allowed (drm_atomic_commit_init sets allow_modeset), so a
/// Colorspace or HDR_OUTPUT_METADATA change on a driven connector, a "max
/// bpc" change, a CRTC's ACTIVE/MODE_ID or a plane change that needs a
/// modeset all commit. Other cards keep set_property_legacy: a connector's
/// "Broadcast RGB", "max bpc", Colorspace and HDR_OUTPUT_METADATA (no
/// modeset) and a CRTC's "VRR_ENABLED" and color properties (SETPROPERTY
/// is connector-only). Master only.
fn handle_set_property(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
    object: bool,
) -> Result<u64, FsError> {
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }
    // SAFETY: `arg` is the ioctl's fixed-size argument structure.
    let bytes = unsafe { copy_in(arg, if object { 20 } else { 16 })? };
    let value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let prop_id = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let obj_id = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let obj_type = if object {
        u32::from_le_bytes(bytes[16..20].try_into().unwrap())
    } else {
        DRM_MODE_OBJECT_CONNECTOR
    };
    let obj_type = {
        let card = mode_state.lock();
        let obj_type = set_property_object(&card, obj_id, obj_type)?;
        if atomic_card(&card) {
            drop(card);
            return set_property_atomic(card_index, mode_state, obj_type, obj_id, prop_id, value);
        }
        // set_property_legacy: a plane has no legacy-settable property.
        if obj_type == DRM_MODE_OBJECT_PLANE {
            return Err(FsError::InvalidData);
        }
        obj_type
    };
    if obj_type == DRM_MODE_OBJECT_CRTC {
        let mut card = mode_state.lock();
        card.crtc(obj_id).map_err(|_| FsError::NotFound)?;
        let mut color = CrtcColorChange::default();
        if crtc_color_property(&card, obj_id, prop_id, value, &mut color)? {
            let _request = apply_crtc_color(card_index, &mut card, obj_id, color);
            drop(card);
            #[cfg(feature = "amdgpu")]
            if let Some((display, request)) = _request {
                crate::amdgpu_native_kms::request_crtc_color(display, request);
            }
            return Ok(0);
        }
        if prop_id != CRTC_VRR_ENABLED_PROP_ID {
            return Err(FsError::InvalidData);
        }
        let value = vrr_enabled_value(&card, obj_id, value)?;
        let _request = apply_vrr_enabled(card_index, &mut card, obj_id, value);
        drop(card);
        #[cfg(feature = "amdgpu")]
        if let Some((display, enabled)) = _request {
            crate::amdgpu_native_kms::request_vrr_enabled(display, enabled);
        }
        return Ok(0);
    }
    let mut card = mode_state.lock();
    let crtc = card
        .connector(obj_id)
        .map_err(|_| FsError::NotFound)?
        .encoder_id
        .and_then(|id| card.encoder(id).ok())
        .and_then(|encoder| encoder.crtc_id);
    let mut color = ConnectorColorChange::default();
    if connector_color_property(&card, obj_id, prop_id, value, &mut color)? {
        // set_property_legacy has no modeset: a Colorspace change or
        // entering/leaving HDR on a driven connector is EINVAL.
        let native = crate::drm_registry::driver_name(card_index) == Some("amdgpu");
        if connector_color_check(&card, native, obj_id, crtc, color)? {
            return Err(FsError::InvalidData);
        }
        let _request = apply_connector_color(card_index, &mut card, obj_id, color);
        drop(card);
        #[cfg(feature = "amdgpu")]
        if let Some(request) = _request {
            crate::amdgpu_native_kms::request_connector_color(request);
        }
        return Ok(0);
    }
    if prop_id == MAX_BPC_PROP_ID {
        let bpc = max_bpc_value(&card, obj_id, value)?;
        let _request = apply_max_bpc(card_index, &mut card, obj_id, bpc);
        drop(card);
        #[cfg(feature = "amdgpu")]
        if let Some((connector, bpc)) = _request {
            crate::amdgpu_native_kms::request_connector_max_bpc(connector, bpc);
        }
        return Ok(0);
    }
    if prop_id != BROADCAST_RGB_PROP_ID {
        return Err(FsError::InvalidData);
    }
    let value = broadcast_rgb_value(&card, obj_id, value)?;
    apply_broadcast_rgb(card_index, &mut card, obj_id, value);
    Ok(0)
}

/// set_property_atomic: one property of one object as a blocking atomic
/// commit through the same decode, checks and commit as
/// DRM_IOCTL_MODE_ATOMIC, with modesets allowed (drm_atomic_commit_init
/// sets allow_modeset; the ioctl clears it only without ALLOW_MODESET) and
/// no event. A CRTC's OUT_FENCE_PTR takes -1, as
/// drm_atomic_crtc_set_property writes it; no fence follows, since only
/// the atomic ioctl prepares signaling.
fn set_property_atomic(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    obj_type: u32,
    obj_id: u32,
    prop_id: u32,
    value: u64,
) -> Result<u64, FsError> {
    const ALLOW_MODESET: u32 = 0x0400;
    if obj_type == DRM_MODE_OBJECT_CRTC && prop_id == CRTC_OUT_FENCE_PTR_PROP_ID && value != 0 {
        // SAFETY: a user pointer to an s32; copy_out faults cleanly.
        unsafe { copy_out(value as usize, &(-1i32).to_le_bytes())? };
    }
    atomic_commit(
        card_index,
        mode_state,
        AtomicRequest {
            flags: ALLOW_MODESET,
            user_data: 0,
            objects: &[obj_id],
            prop_counts: &[1],
            props: &[prop_id],
            values: &[value],
        },
        None,
        None,
        None,
    )
}

/// DRM_IOCTL_MODE_SETGAMMA (`set`) and DRM_IOCTL_MODE_GETGAMMA on
/// `struct drm_mode_crtc_lut { u32 crtc_id; u32 gamma_size; u64 red, green,
/// blue; }`. Neither is a render-node ioctl and SETGAMMA is DRM_MASTER
/// (EACCES); an unknown CRTC is ENOENT and a gamma_size other than the
/// CRTC's EINVAL. SETGAMMA copies the ramps into the CRTC's gamma store,
/// then commits them as drm_crtc_legacy_gamma_set does: a 256-entry
/// GAMMA_LUT with the CTM reset (amdgpu_dm then programs the sRGB-based
/// legacy regamma). GETGAMMA returns the gamma store.
fn handle_gamma(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
    set: bool,
) -> Result<u64, FsError> {
    // A card without color management keeps its unconditional no-op.
    if set && mode_state.lock().crtc_color.is_empty() {
        return Ok(0);
    }
    if ctx.is_render_client() || set && !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }
    // SAFETY: `arg` is the fixed 32-byte ioctl structure.
    let bytes = unsafe { copy_in(arg, 32)? };
    let crtc_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let size = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let ptr = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
    let (red, green, blue) = (ptr(8), ptr(16), ptr(24));
    let card = mode_state.lock();
    card.crtc(crtc_id).map_err(|_| FsError::NotFound)?;
    let Some(color) = card.crtc_color(crtc_id) else {
        // drm_crtc_supports_legacy_gamma is false (gamma_size 0).
        return if set {
            Err(FsError::NotImplemented) // ENOSYS
        } else if size == 0 {
            Ok(0)
        } else {
            Err(FsError::InvalidData)
        };
    };
    if size != crate::drm::card::LEGACY_GAMMA_SIZE {
        return Err(FsError::InvalidData);
    }
    if !set {
        let store = color.gamma_store.clone();
        drop(card);
        for (k, at) in [red, green, blue].into_iter().enumerate() {
            let ramp: Vec<u8> = store[k * size..(k + 1) * size]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            // SAFETY: a user array of gamma_size u16s; copy_out faults cleanly.
            unsafe { copy_out(at, &ramp)? };
        }
        return Ok(0);
    }
    drop(card);
    let mut store = Vec::with_capacity(3 * size);
    for at in [red, green, blue] {
        // SAFETY: a user array of gamma_size u16s; copy_in faults cleanly.
        let ramp = unsafe { copy_in(at, 2 * size)? };
        store.extend(
            ramp.chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]])),
        );
    }
    let mut card = mode_state.lock();
    // The CRTC may have gone while the card lock was released.
    if card.crtc_color(crtc_id).is_none() {
        return Err(FsError::NotFound);
    }
    let mut lut = Vec::with_capacity(size * COLOR_LUT_ENTRY_SIZE);
    for i in 0..size {
        for v in [store[i], store[size + i], store[2 * size + i], 0] {
            lut.extend_from_slice(&v.to_le_bytes());
        }
    }
    let blob = card
        .create_property_blob(lut)
        .map_err(|_| FsError::OutOfMemory)?;
    if let Some(c) = card.crtc_color.iter_mut().find(|c| c.crtc == crtc_id) {
        c.gamma_store = store;
    }
    let change = CrtcColorChange {
        ctm: Some(0),
        gamma_lut: Some(blob),
    };
    let _request = apply_crtc_color(card_index, &mut card, crtc_id, change);
    // drm_property_blob_put: only the committed GAMMA_LUT holds it now.
    card.destroy_property_blob(blob);
    drop(card);
    #[cfg(feature = "amdgpu")]
    if let Some((display, request)) = _request {
        crate::amdgpu_native_kms::request_crtc_color(display, request);
    }
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

    // A userspace blob (MODE_ID, CTM, GAMMA_LUT, HDR_OUTPUT_METADATA), or a
    // connector's EDID.
    let edid = {
        let card = mode_state.lock();
        // A native plane's IN_FORMATS blob (amdgpu native card only).
        #[cfg(feature = "amdgpu")]
        let native_blob = crate::drm_native_planes::in_formats_blob(&card, blob_id);
        #[cfg(not(feature = "amdgpu"))]
        let native_blob: Option<Vec<u8>> = None;
        match card.property_blob(blob_id) {
            Some(data) => data.to_vec(),
            None if native_blob.is_some() => native_blob.unwrap(),
            None => {
                let connector_id =
                    connector_id_from_edid_blob(blob_id).ok_or(FsError::InvalidData)?;
                connector_edid(&card, connector_id)
                    .ok_or(FsError::InvalidData)?
                    .to_vec()
            }
        }
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
        // A native card's plane (primary or overlay): the core plane
        // properties from its state, then amdgpu_dm's.
        let native: Option<crate::drm::atomic::PlaneState> = (obj_type == DRM_MODE_OBJECT_PLANE)
            .then(|| {
                #[cfg(feature = "amdgpu")]
                {
                    crate::drm_native_planes::plane_state(&card, obj_id)
                }
                #[cfg(not(feature = "amdgpu"))]
                {
                    None
                }
            })
            .flatten();
        if let Some(p) = native {
            let plane_type = card
                .native_plane(obj_id)
                .map_or(DRM_PLANE_TYPE_PRIMARY, |n| {
                    if n.is_cursor() {
                        DRM_PLANE_TYPE_CURSOR
                    } else if n.is_overlay() {
                        DRM_PLANE_TYPE_OVERLAY
                    } else {
                        DRM_PLANE_TYPE_PRIMARY
                    }
                });
            let mut props = vec![
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
            ];
            let mut values = vec![
                plane_type,
                u64::from(p.fb_id.unwrap_or(0)),
                u64::from(p.crtc_id.unwrap_or(0)),
                u64::from(p.src_x) << 16,
                u64::from(p.src_y) << 16,
                u64::from(p.src_w) << 16,
                u64::from(p.src_h) << 16,
                p.crtc_x as i64 as u64,
                p.crtc_y as i64 as u64,
                u64::from(p.crtc_w),
                u64::from(p.crtc_h),
                (-1i64) as u64,
            ];
            #[cfg(feature = "amdgpu")]
            if let Some((ids, vals)) = crate::drm_native_planes::object_properties(&card, obj_id) {
                props.extend(ids);
                values.extend(vals);
            }
            (props, values)
        } else if obj_type == DRM_MODE_OBJECT_PLANE {
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
            let (mut props, mut values) = (
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
            );
            #[cfg(feature = "amdgpu")]
            if crate::amdgpu_native_kms::linear_gem_card(&card) {
                // GBM must choose LINEAR explicitly for the DCN30 copy
                // presenter rather than infer an AMD tiled layout.
                props.push(crate::drm_native_planes::IN_FORMATS_PROP_ID);
                values.push(u64::from(crate::drm_native_planes::in_formats_blob_id(
                    obj_id,
                )));
            }
            (props, values)
        } else if obj_type == DRM_MODE_OBJECT_CRTC {
            let crtc = card.crtc(obj_id).map_err(|_| FsError::InvalidData)?;
            let mut props = vec![
                CRTC_ACTIVE_PROP_ID,
                CRTC_MODE_ID_PROP_ID,
                CRTC_OUT_FENCE_PTR_PROP_ID,
            ];
            // OUT_FENCE_PTR reads back as 0 (write-only request),
            // matching drm_atomic_crtc_get_property.
            let mut values = vec![crtc.enabled as u64, 0, 0];
            if let Some(vrr) = crtc_vrr_enabled(&card, obj_id) {
                props.push(CRTC_VRR_ENABLED_PROP_ID);
                values.push(u64::from(vrr));
            }
            if let Some(color) = card.crtc_color(obj_id) {
                props.extend([
                    CRTC_CTM_PROP_ID,
                    CRTC_GAMMA_LUT_PROP_ID,
                    CRTC_GAMMA_LUT_SIZE_PROP_ID,
                ]);
                values.extend([
                    u64::from(color.ctm),
                    u64::from(color.gamma_lut),
                    GAMMA_LUT_SIZE,
                ]);
            }
            (props, values)
        } else if obj_type == DRM_MODE_OBJECT_CONNECTOR {
            let connector = card.connector(obj_id).map_err(|_| FsError::InvalidData)?;
            let crtc_id = connector
                .encoder_id
                .and_then(|id| card.encoder(id).ok())
                .and_then(|encoder| encoder.crtc_id)
                .unwrap_or(0);
            connector_properties(&card, obj_id, crtc_id)
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

/// Validate and wait for the explicit fences named by an atomic KMS request.
///
/// This runs at the `FileOps::ioctl_user` boundary, before the bridge takes
/// its card-state lock. A VirtIO render fence can only complete after taking
/// the transport request gate, so waiting under either the card lock or a
/// dma-buf reservation lock would create a producer/consumer lock inversion.
///
/// A parked retry has not touched KMS state, therefore it is safe for
/// `IoctlContext::restart_after` to re-execute the ioctl once a device fence
/// may have completed. Kernel-only callers have no task to park, and use the
/// bounded synchronous fallback instead.
pub(crate) fn wait_atomic_in_fences(arg: u64, context: &dyn IoctlContext) -> Result<(), FsError> {
    const TEST_ONLY: u32 = 0x0100;
    const VALID_FLAGS: u32 = 0x0001 | 0x0002 | TEST_ONLY | 0x0200 | 0x0400;
    const FENCE_REPOLL_NS: u64 = 1_000_000;
    const FENCE_TIMEOUT_MS: u64 = 15_000;

    let mut header = [0u8; core::mem::size_of::<DrmModeAtomicUapi>()];
    context.read(arg, &mut header)?;
    // SAFETY: `header` is exactly one fully initialized `repr(C)` UAPI
    // object. `read_unaligned` matches the byte-array alignment.
    let req = unsafe { core::ptr::read_unaligned(header.as_ptr() as *const DrmModeAtomicUapi) };
    if req.reserved != 0 || req.flags & !VALID_FLAGS != 0 || req.count_objs > 256 {
        return Err(FsError::InvalidData);
    }
    if req.flags & TEST_ONLY != 0 && req.flags & 0x0001 != 0 {
        return Err(FsError::InvalidData);
    }
    if req.count_objs == 0 {
        return Ok(());
    }
    if req.objs_ptr == 0
        || req.count_props_ptr == 0
        || req.props_ptr == 0
        || req.prop_values_ptr == 0
    {
        return Err(FsError::BadAddress);
    }

    let count = req.count_objs as usize;
    // Read the same arrays, in the same order, as `handle_atomic`. The object
    // ids are not needed for fence waiting, but validating their range keeps
    // EFAULT precedence identical for a malformed request.
    let mut object_bytes = vec![0u8; count * 4];
    context.read(req.objs_ptr, &mut object_bytes)?;
    let mut count_bytes = vec![0u8; count * 4];
    context.read(req.count_props_ptr, &mut count_bytes)?;
    let total_props = count_bytes
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
        .try_fold(0usize, |sum, count| {
            sum.checked_add(count).filter(|total| *total <= 4096)
        })
        .ok_or(FsError::OutOfMemory)?;
    let mut prop_bytes = vec![0u8; total_props * 4];
    context.read(req.props_ptr, &mut prop_bytes)?;
    let mut value_bytes = vec![0u8; total_props * 8];
    context.read(req.prop_values_ptr, &mut value_bytes)?;

    let test_only = req.flags & TEST_ONLY != 0;
    for (prop, value) in prop_bytes
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .zip(
            value_bytes
                .chunks_exact(8)
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap())),
        )
    {
        if prop != PLANE_IN_FENCE_FD_PROP_ID {
            continue;
        }
        let fd = value as i64;
        if fd < -1 || fd > i32::MAX as i64 {
            return Err(FsError::InvalidData);
        }
        let Some(fences) = (fd >= 0)
            .then(|| context.sync_file_fences(fd as i32))
            .flatten()
        else {
            if fd >= 0 {
                return Err(FsError::InvalidData);
            }
            continue;
        };
        // TEST_ONLY imports and validates the sync_file but has no commit
        // tail in which to consume the dependency.
        if test_only {
            continue;
        }
        for fence in fences {
            if fence.is_signalled() {
                continue;
            }
            if context.restart_after(FENCE_REPOLL_NS) {
                return Err(FsError::WouldBlock);
            }
            if !fence.wait(FENCE_TIMEOUT_MS) {
                return Err(FsError::Busy);
            }
        }
    }
    Ok(())
}

/// DRIVER_ATOMIC: VirtGPU, or a native display backend that published
/// itself as atomic (Navi48). Navi22's native card still takes legacy KMS.
fn atomic_card(card: &crate::drm::card::Card) -> bool {
    card.driver_name == "virtio_gpu" || card.native_atomic
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

    if !atomic_card(&mode_state.lock()) {
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
    atomic_commit(
        card_index,
        mode_state,
        AtomicRequest {
            flags: req.flags,
            user_data: req.user_data,
            objects: &objects,
            prop_counts: &prop_counts,
            props: &props,
            values: &values,
        },
        events,
        out_fences,
        None,
    )
}

/// One decoded DRM_IOCTL_MODE_ATOMIC request: its flags and event cookie
/// and the object/property/value arrays copied in from userspace (or built
/// by the kernel, as `set_property_atomic` does for a legacy set).
struct AtomicRequest<'a> {
    flags: u32,
    user_data: u64,
    objects: &'a [u32],
    prop_counts: &'a [u32],
    props: &'a [u32],
    values: &'a [u64],
}

/// drm_atomic_commit for a decoded request: decode each object's
/// properties into the atomic state, check it, then commit and present
/// (or stop after the check for TEST_ONLY).
fn atomic_commit(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    req: AtomicRequest<'_>,
    events: Option<&narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>>,
    out_fences: Option<&narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<(u64, u64)>>>,
    admission: Option<&scanout_kms::CommitAdmission<'_>>,
) -> Result<u64, FsError> {
    const PAGE_FLIP_EVENT: u32 = 0x0001;
    const TEST_ONLY: u32 = 0x0100;
    const ALLOW_MODESET: u32 = 0x0400;
    let AtomicRequest {
        objects,
        prop_counts,
        props,
        values,
        ..
    } = req;
    let total_props = props.len();

    // The exact timing an atomic MODE_ID set, for the native display.
    let mut native_modes: Vec<(u32, crate::drm::ioctl::DrmModeModeInfo)> = Vec::new();
    let mut state = crate::drm::atomic::AtomicState {
        allow_modeset: req.flags & ALLOW_MODESET != 0,
        ..Default::default()
    };
    let policy = crate::drm::atomic::AtomicCheckPolicy::default();
    let test_only = req.flags & TEST_ONLY != 0;
    let mut prop_index = 0usize;
    // Native VRR changes, requested once the card lock is released.
    let mut vrr_requests: Vec<(u8, bool)> = Vec::new();
    // Native CRTC color and connector Colorspace/HDR changes, likewise.
    let mut color_requests: Vec<(u8, CrtcColorRequest)> = Vec::new();
    let mut connector_requests: Vec<ConnectorColorRequest> = Vec::new();
    // Native cursor planes' hardware cursors, likewise.
    let mut cursor_requests: Vec<CursorRequest> = Vec::new();
    // Native connector "max bpc" changes, likewise.
    let mut max_bpc_requests: Vec<(u32, u8)> = Vec::new();
    let presentation = {
        let mut card = mode_state.lock();
        if let Some(a) = admission {
            a.check(&card)?;
        }
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
        // Connector "Broadcast RGB" values, applied only with the commit.
        let mut broadcast_rgb: Vec<(u32, u8)> = Vec::new();
        // Connector "max bpc" values, likewise.
        let mut max_bpcs: Vec<(u32, u8)> = Vec::new();
        // CRTC "VRR_ENABLED" values, likewise.
        let mut vrr_enabled: Vec<(u32, bool)> = Vec::new();
        // CRTC CTM/GAMMA_LUT and connector Colorspace/HDR_OUTPUT_METADATA
        // values, likewise.
        let mut crtc_colors: Vec<(u32, CrtcColorChange)> = Vec::new();
        let mut connector_colors: Vec<(u32, ConnectorColorChange)> = Vec::new();
        for (object_index, object_id) in objects.iter().copied().enumerate() {
            let object_prop_count = prop_counts[object_index] as usize;
            let end = prop_index
                .checked_add(object_prop_count)
                .filter(|end| *end <= props.len())
                .ok_or(FsError::InvalidData)?;
            let object_props = &props[prop_index..end];
            let object_values = &values[prop_index..end];
            prop_index = end;

            #[cfg(feature = "amdgpu")]
            let native_plane = crate::drm_native_planes::plane_state(&card, object_id);
            #[cfg(not(feature = "amdgpu"))]
            let native_plane: Option<crate::drm::atomic::PlaneState> = None;
            if let Some(mut plane) = native_plane {
                // A native card's plane, primary, overlay or cursor: its
                // committed state plus amdgpu_dm's properties.
                if let (Some(crtc_ids), Some(crtc_id)) = (event_crtc_ids.as_mut(), plane.crtc_id) {
                    if !crtc_ids.contains(&crtc_id) {
                        crtc_ids.push(crtc_id);
                    }
                }
                // A SRC_* fraction (amdgpu_dm ignores it on other planes).
                let mut fraction = false;
                for (&prop, &value) in object_props.iter().zip(object_values) {
                    if matches!(
                        prop,
                        PLANE_SRC_X_PROP_ID
                            | PLANE_SRC_Y_PROP_ID
                            | PLANE_SRC_W_PROP_ID
                            | PLANE_SRC_H_PROP_ID
                    ) {
                        fraction |= value & 0xffff != 0;
                    }
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
                            if fd < -1 || fd > i32::MAX as i64 {
                                return Err(FsError::InvalidData);
                            }
                            plane.in_fence_fd = (fd >= 0).then_some(fd as i32);
                        }
                        #[cfg(feature = "amdgpu")]
                        p if crate::drm_native_planes::set_property(
                            &card, &mut plane, p, value,
                        )? => {}
                        _ => return Err(FsError::InvalidData),
                    }
                }
                // dm_check_cursor_fb on SRC_* in 16.16: an enabled cursor
                // shows its whole framebuffer from 0,0, so no fraction.
                if fraction && cursor_plane_shown(&card, &plane) {
                    return Err(FsError::InvalidData);
                }
                if let (Some(crtc_ids), Some(crtc_id)) = (event_crtc_ids.as_mut(), plane.crtc_id) {
                    if !crtc_ids.contains(&crtc_id) {
                        crtc_ids.push(crtc_id);
                    }
                }
                state.planes.push(plane);
            } else if let Some((_, crtc_index)) = synthesized_planes
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
                    props: None,
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
                let mut color = CrtcColorChange::default();
                for (&prop, &value) in object_props.iter().zip(object_values) {
                    match prop {
                        p if crtc_color_property(&card, object_id, p, value, &mut color)? => {}
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
                                // A native display runs only its published
                                // timing; any other is refused at check time.
                                if !card.accepts_mode_blob(mode) {
                                    return Err(FsError::InvalidData);
                                }
                                if let Some(wire) =
                                    crate::drm::ioctl::DrmModeModeInfo::from_bytes(mode)
                                {
                                    // On the native card, a timing this
                                    // CRTC's connector offers: checked once
                                    // every connector routing is parsed.
                                    #[cfg(feature = "amdgpu")]
                                    if crate::drm_registry::driver_name(card_index)
                                        == Some("amdgpu")
                                        && crate::amdgpu_native_kms::crtc_display(object_id)
                                            .is_none()
                                    {
                                        return Err(FsError::InvalidData);
                                    }
                                    native_modes.retain(|(id, _)| *id != object_id);
                                    native_modes.push((object_id, wire));
                                }
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
                        // Not a modeset: amdgpu_dm reprograms DRR in place.
                        CRTC_VRR_ENABLED_PROP_ID => vrr_enabled
                            .push((object_id, vrr_enabled_value(&card, object_id, value)?)),
                        _ => return Err(FsError::InvalidData),
                    }
                }
                // Not a modeset: amdgpu_dm updates the stream's transfer
                // function and gamut remap in place.
                if color != CrtcColorChange::default() {
                    crtc_colors.retain(|(id, _)| *id != object_id);
                    crtc_colors.push((object_id, color));
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
                let mut color = ConnectorColorChange::default();
                for (&prop, &value) in object_props.iter().zip(object_values) {
                    match prop {
                        p if connector_color_property(&card, object_id, p, value, &mut color)? => {}
                        CONNECTOR_CRTC_ID_PROP_ID => {
                            connector_state.crtc_id = (value != 0).then_some(value as u32)
                        }
                        BROADCAST_RGB_PROP_ID => broadcast_rgb
                            .push((object_id, broadcast_rgb_value(&card, object_id, value)?)),
                        MAX_BPC_PROP_ID => {
                            let bpc = max_bpc_value(&card, object_id, value)?;
                            // A modeset of the CRTC the connector drove.
                            if max_bpc_modeset(&card, object_id, bpc) && !state.allow_modeset {
                                return Err(FsError::InvalidData);
                            }
                            max_bpcs.retain(|(id, _)| *id != object_id);
                            max_bpcs.push((object_id, bpc));
                        }
                        _ => return Err(FsError::InvalidData),
                    }
                }
                // amdgpu_dm_connector_atomic_check against the CRTC the
                // connector drives after this request: a Colorspace change or
                // entering/leaving HDR is a modeset of that CRTC.
                if color != ConnectorColorChange::default() {
                    let native = crate::drm_registry::driver_name(card_index) == Some("amdgpu");
                    if connector_color_check(
                        &card,
                        native,
                        object_id,
                        connector_state.crtc_id,
                        color,
                    )? && !state.allow_modeset
                    {
                        return Err(FsError::InvalidData);
                    }
                    connector_colors.retain(|(id, _)| *id != object_id);
                    connector_colors.push((object_id, color));
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
        check_native_atomic(&card, &state)?;
        // amdgpu_dm's plane checks on a card with its native planes, and
        // each touched display's planes after this commit.
        #[cfg(feature = "amdgpu")]
        let native_displays: Vec<crate::drm_native_planes::DisplayPlanes> =
            if card.native_planes.is_empty() {
                Vec::new()
            } else {
                let mode_of = |crtc_id: u32| {
                    state
                        .crtcs
                        .iter()
                        .find(|c| c.id == crtc_id)
                        .map(|c| c.mode)
                        .unwrap_or_else(|| card.crtc(crtc_id).ok().and_then(|c| c.mode))
                };
                crate::drm_native_planes::check(&card, &state, mode_of)?
            };
        // A native MODE_ID is a timing of the connector the CRTC drives
        // after this commit: one routed to it here, else its current one.
        #[cfg(feature = "amdgpu")]
        if crate::drm_registry::driver_name(card_index) == Some("amdgpu") {
            for (crtc_id, wire) in &native_modes {
                let connector = state
                    .connectors
                    .iter()
                    .find(|c| c.crtc_id == Some(*crtc_id))
                    .map(|c| c.id);
                if !crate::amdgpu_native_kms::crtc_display(*crtc_id)
                    .is_some_and(|d| crate::amdgpu_native_kms::display_offers(d, connector, wire))
                {
                    return Err(FsError::InvalidData);
                }
            }
            // DML admission of each touched display's planes (with its
            // primary's format) at its CRTC's mode after the commit, on the
            // connector the CRTC then drives.
            for dp in &native_displays {
                let Some(d) = crate::amdgpu_native_kms::crtc_display(dp.crtc_id) else {
                    continue;
                };
                let connector = state
                    .connectors
                    .iter()
                    .find(|c| c.crtc_id == Some(dp.crtc_id))
                    .map(|c| c.id);
                let wire = native_modes
                    .iter()
                    .find(|(id, _)| *id == dp.crtc_id)
                    .map(|(_, w)| w);
                if native_output_on_crtc(&card, dp.crtc_id, connector)
                    .is_some_and(|n| n.color_format.is_some())
                {
                    continue;
                }
                if !crate::amdgpu_native_kms::display_admits_planes(
                    d,
                    connector,
                    wire,
                    dp.primary_format,
                    &dp.setup,
                ) {
                    return Err(FsError::InvalidData);
                }
            }
            for plane in &state.planes {
                let (Some(fb_id), Some(crtc_id)) = (plane.fb_id, plane.crtc_id) else {
                    continue;
                };
                if !card.native_planes.is_empty() {
                    break;
                }
                let Some(d) = crate::amdgpu_native_kms::crtc_display(crtc_id) else {
                    continue;
                };
                let format = card
                    .framebuffer(fb_id)
                    .map_err(|_| FsError::NotFound)?
                    .format;
                let connector = state
                    .connectors
                    .iter()
                    .find(|c| c.crtc_id == Some(crtc_id))
                    .map(|c| c.id);
                let wire = native_modes
                    .iter()
                    .find(|(id, _)| *id == crtc_id)
                    .map(|(_, w)| w);
                if !crate::amdgpu_native_kms::display_admits_format(
                    d,
                    connector,
                    wire,
                    format as u32,
                ) {
                    return Err(FsError::InvalidData);
                }
            }
        }

        // Retain the existing DP/MST-only modeset admission path. The
        // additional complete format search is needed when this request
        // changes an HDMI output or any of its planes.
        // Only the amdgpu native card has native outputs whose
        // color state can touch an HDMI format search.
        #[cfg(feature = "amdgpu")]
        let hdmi_touched = card
            .native
            .iter()
            .filter(|n| n.color_format.is_some())
            .any(|n| {
                state.connectors.iter().any(|c| c.id == n.connector)
                    || connector_colors
                        .iter()
                        .any(|(id, c)| *id == n.connector && c.color_format.is_some())
                    || max_bpcs.iter().any(|(id, _)| *id == n.connector)
                    || native_modes.iter().any(|(id, _)| {
                        native_output_on_crtc(&card, *id, None)
                            .is_some_and(|current| current.connector == n.connector)
                    })
                    || native_displays.iter().any(|d| {
                        native_output_on_crtc(&card, d.crtc_id, None)
                            .is_some_and(|current| current.connector == n.connector)
                    })
            });
        #[cfg(not(feature = "amdgpu"))]
        let hdmi_touched = false;
        #[cfg(feature = "amdgpu")]
        if hdmi_touched && crate::drm_registry::driver_name(card_index) == Some("amdgpu") {
            let mut outputs = Vec::new();
            let mut routes = Vec::new();
            for native in &card.native {
                let connector = native.connector;
                let crtc = state
                    .connectors
                    .iter()
                    .find(|c| c.id == connector)
                    .map(|c| c.crtc_id)
                    .unwrap_or_else(|| {
                        card.connector(connector)
                            .ok()
                            .and_then(|c| c.encoder_id)
                            .and_then(|e| card.encoder(e).ok())
                            .and_then(|e| e.crtc_id)
                    });
                let Some(crtc) = crtc else { continue };
                let enabled = state
                    .crtcs
                    .iter()
                    .find(|c| c.id == crtc)
                    .map(|c| c.enable)
                    .unwrap_or_else(|| card.crtc(crtc).is_ok_and(|c| c.enabled));
                if !enabled {
                    continue;
                }
                let Some(display) = crate::amdgpu_native_kms::crtc_display(crtc) else {
                    continue;
                };
                let change = connector_colors
                    .iter()
                    .find(|(id, _)| *id == connector)
                    .map(|(_, c)| *c)
                    .unwrap_or_default();
                let mode = native_modes
                    .iter()
                    .find(|(id, _)| *id == crtc)
                    .map(|(_, m)| *m);
                let planes = if let Some(d) = native_displays.iter().find(|d| d.crtc_id == crtc) {
                    Some((d.primary_format, d.setup))
                } else if !card.native_planes.is_empty() {
                    // A connector-only color-format change still needs the
                    // committed primary/overlays, including pending DRM state.
                    let mut snapshot = state.clone();
                    if !snapshot.crtcs.iter().any(|c| c.id == crtc) {
                        let c = card.crtc(crtc).map_err(|_| FsError::InvalidData)?;
                        snapshot.crtcs.push(crate::drm::atomic::CrtcState {
                            id: crtc,
                            enable: c.enabled,
                            active: c.enabled,
                            mode: c.mode,
                            ..Default::default()
                        });
                    }
                    let planes = crate::drm_native_planes::check(&card, &snapshot, |id| {
                        snapshot
                            .crtcs
                            .iter()
                            .find(|c| c.id == id)
                            .map(|c| c.mode)
                            .unwrap_or_else(|| card.crtc(id).ok().and_then(|c| c.mode))
                    })?;
                    planes
                        .iter()
                        .find(|d| d.crtc_id == crtc)
                        .map(|d| (d.primary_format, d.setup))
                } else {
                    None
                };
                routes.push(crate::amdgpu_native_kms::OutputRoute {
                    display,
                    connector,
                    mode,
                    planes,
                });
                if native.color_format.is_none() {
                    continue;
                }
                outputs.push(crate::amdgpu_native_kms::OutputFormatRequest {
                    display,
                    connector,
                    color_format: change
                        .color_format
                        .or(native.color_format)
                        .unwrap_or_default(),
                    mode,
                    planes,
                    max_bpc: max_bpcs
                        .iter()
                        .find(|(id, _)| *id == connector)
                        .map(|(_, b)| *b)
                        .or(native.max_bpc),
                });
            }
            if !crate::amdgpu_native_kms::output_formats_supported(&outputs, &routes) {
                return Err(FsError::InvalidData);
            }
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
            // drm_atomic_helper_prepare_planes (amdgpu_dm's prepare_fb) for
            // every plane the commit shows, before any state changes: a pin
            // that fails fails the commit with its errno.
            #[cfg(feature = "amdgpu")]
            let prepared = PreparedFbs::prepare(
                &card,
                state
                    .planes
                    .iter()
                    .filter(|p| p.crtc_id.is_some())
                    .filter_map(|p| p.fb_id),
            )?;
            #[cfg(feature = "amdgpu")]
            let cursors = crate::drm_native_planes::cursor_changes(&card, &state);
            if let Err(error) = state.core_commit(&mut card) {
                let _ = writeln!(
                    narf_console::Writer,
                    "  drm: ATOMIC commit failed: {error:?}"
                );
                return Err(FsError::InvalidData);
            }
            #[cfg(feature = "amdgpu")]
            crate::drm_native_planes::commit(&mut card, &state);
            #[cfg(feature = "amdgpu")]
            {
                cursor_requests =
                    native_cursor_requests(card_index, &mut card, &cursors, &prepared);
            }
            for &(connector, value) in &broadcast_rgb {
                apply_broadcast_rgb(card_index, &mut card, connector, value);
            }
            for &(connector, bpc) in &max_bpcs {
                if let Some(request) = apply_max_bpc(card_index, &mut card, connector, bpc) {
                    max_bpc_requests.push(request);
                }
            }
            for &(crtc, value) in &vrr_enabled {
                if let Some(request) = apply_vrr_enabled(card_index, &mut card, crtc, value) {
                    vrr_requests.push(request);
                }
            }
            for &(crtc, change) in &crtc_colors {
                if let Some(request) = apply_crtc_color(card_index, &mut card, crtc, change) {
                    color_requests.push(request);
                }
            }
            for &(connector, change) in &connector_colors {
                if let Some(request) =
                    apply_connector_color(card_index, &mut card, connector, change)
                {
                    connector_requests.push(request);
                }
            }
            let amdgpu = crate::drm_registry::driver_name(card_index) == Some("amdgpu");
            #[cfg(feature = "amdgpu")]
            if amdgpu {
                // Routing first: a mode is checked against the connector the
                // CRTC drives. Any encoder may drive any native CRTC.
                for c in &state.connectors {
                    let current = card
                        .connector(c.id)
                        .ok()
                        .and_then(|x| x.encoder_id)
                        .and_then(|id| card.encoder(id).ok())
                        .and_then(|e| e.crtc_id);
                    if current != c.crtc_id {
                        let display = c.crtc_id.and_then(crate::amdgpu_native_kms::crtc_display);
                        crate::amdgpu_native_kms::request_connector_crtc(c.id, display);
                    }
                }
                for crtc in &state.crtcs {
                    let Some(display) = crate::amdgpu_native_kms::crtc_display(crtc.id) else {
                        continue;
                    };
                    if crtc.active_changed {
                        crate::amdgpu_native_kms::request_display_active(display, crtc.active);
                    }
                    // A new mode is a native modeset the display monitor runs.
                    if crtc.mode_changed {
                        let wire = native_modes
                            .iter()
                            .find(|(id, _)| *id == crtc.id)
                            .map(|(_, w)| w);
                        crate::amdgpu_native_kms::request_display_mode(display, wire);
                    }
                }
                // Planes and plane formats go to the display monitor too,
                // which applies them without a modeset (DC's plane update).
                for dp in &native_displays {
                    if let Some(display) = crate::amdgpu_native_kms::crtc_display(dp.crtc_id) {
                        crate::amdgpu_native_kms::request_display_planes(display, dp.setup);
                    }
                }
                // The framebuffers' formats (a cursor's is not the display's).
                for plane in &state.planes {
                    let (Some(crtc_id), Some(fb_id)) = (plane.crtc_id, plane.fb_id) else {
                        continue;
                    };
                    if card.native_plane(plane.id).is_some_and(|p| p.is_cursor()) {
                        continue;
                    }
                    if let (Some(display), Ok(fb)) = (
                        crate::amdgpu_native_kms::crtc_display(crtc_id),
                        card.framebuffer(fb_id),
                    ) {
                        crate::amdgpu_native_kms::request_display_format(display, fb.format as u32);
                    }
                }
            }
            // Every enabled plane presents on the native card (each on its
            // own display); the CPU-copy cards show one scanout. A cursor
            // plane shows on the hardware cursor instead.
            let active_planes: Vec<(u32, u32)> = state
                .planes
                .iter()
                .filter(|plane| !card.native_plane(plane.id).is_some_and(|p| p.is_cursor()))
                .filter_map(|plane| Some((plane.crtc_id?, plane.fb_id?)))
                .take(if amdgpu { usize::MAX } else { 1 })
                .collect();
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
            // CRTCs whose plane's dumb buffer goes through a hardware flip:
            // their events wait for that flip.
            let hardware_crtcs: Vec<u32> = active_planes
                .iter()
                .filter(|&&(crtc_id, _)| hardware_flips(card_index, crtc_id))
                .filter_map(|&(crtc_id, fb_id)| {
                    let fb = card.framebuffer(fb_id).ok()?;
                    let gem_handle = fb.gem_handle;
                    (card.virtgpu_import(gem_handle).is_none()
                        && (card.dumb_backing(gem_handle).is_some() || fb.bo.is_some()))
                    .then_some(crtc_id)
                })
                .collect();
            let mut flip_tickets: Vec<(u32, u64)> = Vec::new();
            if let (Some(queue), Some(crtc_ids)) = (event_queue.as_mut(), event_crtc_ids) {
                for crtc_id in crtc_ids {
                    #[cfg(feature = "amdgpu")]
                    let display = crate::amdgpu_native_kms::crtc_display(crtc_id);
                    #[cfg(not(feature = "amdgpu"))]
                    let display: Option<u8> = None;
                    if let (true, Some(display)) = (hardware_crtcs.contains(&crtc_id), display) {
                        let ticket = crate::drm::card::flips(display).lock().reserve();
                        card.queue_hw_flip_event(queue, req.user_data, crtc_id, display, ticket)
                            .map_err(|_| FsError::OutOfMemory)?;
                        flip_tickets.push((crtc_id, ticket));
                        continue;
                    }
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
            // A display with native planes presents every plane this
            // commit updates together (`drm_native_planes`).
            #[cfg(feature = "amdgpu")]
            let native_frame = |card: &crate::drm::card::Card, id: u32| {
                native_plane_frame(card, state.planes.iter().find(|p| p.id == id)?, &prepared)
            };
            #[cfg(feature = "amdgpu")]
            let native_presentations: Vec<NativePresentation> = native_displays
                .iter()
                .filter(|_| amdgpu)
                .filter(|dp| dp.setup.overlay_count() > 0 || dp.setup.primary.is_some())
                .map(|dp| {
                    let primary = card
                        .native_planes
                        .iter()
                        .find(|p| p.primary_of == Some(dp.crtc_id))
                        .and_then(|p| native_frame(&card, p.id));
                    let overlays = dp
                        .overlays
                        .map(|id| id.and_then(|id| native_frame(&card, id)));
                    let ticket = flip_tickets
                        .iter()
                        .find(|(id, _)| *id == dp.crtc_id)
                        .map(|(_, t)| *t);
                    (dp.crtc_id, primary, overlays, ticket)
                })
                .collect();
            #[cfg(not(feature = "amdgpu"))]
            let native_presentations: Vec<NativePresentation> = Vec::new();
            // ... the others each plane on its own, as before.
            let presentations: Vec<_> = active_planes
                .iter()
                .filter(|&&(crtc_id, _)| {
                    !native_presentations
                        .iter()
                        .any(|&(c, _, _, _)| c == crtc_id)
                })
                .filter_map(|&(crtc_id, fb_id)| {
                    let fb = card.framebuffer(fb_id).ok()?;
                    let gem_handle = fb.gem_handle;
                    Some((
                        crtc_id,
                        card.virtgpu_import(gem_handle).cloned(),
                        card.dumb_backing(gem_handle).map(|backing| backing.phys),
                        (fb.pitch, fb.width, fb.height, fb.format as u32),
                        fb_id,
                        fb.bo
                            .as_ref()
                            .and_then(|_| prepared_frame(&card, fb, &prepared)),
                        flip_tickets
                            .iter()
                            .find(|(id, _)| *id == crtc_id)
                            .map(|(_, t)| *t),
                    ))
                })
                .collect();
            Some((presentations, native_presentations))
        }
    };
    #[cfg(feature = "amdgpu")]
    for (display, enabled) in vrr_requests {
        crate::amdgpu_native_kms::request_vrr_enabled(display, enabled);
    }
    #[cfg(feature = "amdgpu")]
    for (display, request) in color_requests {
        crate::amdgpu_native_kms::request_crtc_color(display, request);
    }
    #[cfg(feature = "amdgpu")]
    for request in connector_requests {
        crate::amdgpu_native_kms::request_connector_color(request);
    }
    send_cursor_requests(cursor_requests);
    #[cfg(feature = "amdgpu")]
    for (connector, bpc) in max_bpc_requests {
        crate::amdgpu_native_kms::request_connector_max_bpc(connector, bpc);
    }

    let (log, n) = should_log(&ATOMIC_N);
    if log {
        let _ = writeln!(
            narf_console::Writer,
            "  drm: ATOMIC #{n} objs={} props={} flags={:#x} present={}",
            objects.len(),
            total_props,
            req.flags,
            presentation
                .as_ref()
                .is_some_and(|(p, n)| !p.is_empty() || !n.is_empty()),
        );
    }
    let (presentation, native_presentation) = match presentation {
        Some((p, n)) => (Some(p), n),
        None => (None, Vec::new()),
    };
    #[cfg(feature = "amdgpu")]
    for (crtc_id, primary, overlays, ticket) in native_presentation {
        present_native_planes(card_index, crtc_id, primary, overlays, ticket);
    }
    #[cfg(not(feature = "amdgpu"))]
    let _ = &native_presentation;
    for (
        crtc_id,
        resource,
        src_phys,
        (pitch, width, height, format),
        fb_id,
        gem_frame,
        flip_ticket,
    ) in presentation.into_iter().flatten()
    {
        if let Some(resource) = resource {
            present_virgl_frame(&resource, width, height)?;
        } else if let Some(frame) = gem_frame {
            present_frame(card_index, crtc_id, frame, flip_ticket);
        } else if let Some(src_phys) = src_phys {
            present_frame(
                card_index,
                crtc_id,
                crate::drm::card::PlaneFrame::linear(src_phys, pitch, width, height, format),
                flip_ticket,
            );
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
/// (36 bytes). On a card with native cursor planes this updates the
/// CRTC's cursor plane (`cursor_universal`). Otherwise we have no hardware
/// cursor plane, so we don't consume the BO bitmap — instead we drive
/// narf_fb's software cursor sprite from the position + visibility.
/// `DRM_MODE_CURSOR_BO` with handle 0 hides the pointer; a non-zero handle
/// shows it; `DRM_MODE_CURSOR_MOVE` repositions.
///
/// Linux ref: `drivers/gpu/drm/drm_plane.c::drm_mode_cursor_common`.
fn handle_cursor(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    with_hotspot: bool,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
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
    if !mode_state.lock().native_planes.is_empty() {
        return cursor_universal(
            card_index,
            mode_state,
            ctx,
            LegacyCursor {
                flags,
                crtc_id: rd_u32(4),
                position: (x, y),
                size: (rd_u32(16), rd_u32(20)),
                handle,
            },
            None,
            None,
        );
    }
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

/// One DRM_IOCTL_MODE_CURSOR{,2} request. CURSOR2's hotspot is not kept:
/// amdgpu is not DRIVER_CURSOR_HOTSPOT, so its cursor planes carry no
/// HOTSPOT_X/Y (drm_mode_cursor_universal drops it).
struct LegacyCursor {
    flags: u32,
    crtc_id: u32,
    position: (i32, i32),
    size: (u32, u32),
    handle: u32,
}

/// drm_mode_cursor_common then drm_mode_cursor_universal on a card with
/// native cursor planes: the CRTC's cursor plane shows a framebuffer
/// wrapped around the BO (drm_internal_framebuffer_create: ARGB8888, pitch
/// width * 4) at the new position or the CRTC's last legacy one, or goes
/// off, through the cursor plane's atomic checks (`__setplane_atomic`).
/// `bo` is the amdgpu GEM buffer `req.handle` names in the caller's own
/// table (`amdgpu_cursor_bo`), wrapped by `Card::addfb2_bo`; without it the
/// handle is one of the card's dumb buffers.
fn cursor_universal(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    ctx: &DrmFileCtx,
    req: LegacyCursor,
    bo: Option<CursorBo>,
    admission: Option<&scanout_kms::CommitAdmission<'_>>,
) -> Result<u64, FsError> {
    // Only a card with native cursor planes has any of this to do;
    // those exist only on the amdgpu native card.
    #[cfg(feature = "amdgpu")]
    {
        cursor_universal_native(card_index, mode_state, ctx, req, bo, admission)
    }
    #[cfg(not(feature = "amdgpu"))]
    {
        let _ = (card_index, mode_state, ctx, req, bo, admission);
        Err(FsError::Unsupported)
    }
}

#[cfg(feature = "amdgpu")]
fn cursor_universal_native(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    ctx: &DrmFileCtx,
    req: LegacyCursor,
    bo: Option<Arc<crate::amdgpu_gem::GemObject>>,
    admission: Option<&scanout_kms::CommitAdmission<'_>>,
) -> Result<u64, FsError> {
    const DRM_MODE_CURSOR_BO: u32 = 0x01;
    const DRM_MODE_CURSOR_MOVE: u32 = 0x02;
    // CURSOR and CURSOR2 are DRM_MASTER ioctls.
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }
    if req.flags == 0 || req.flags & !(DRM_MODE_CURSOR_BO | DRM_MODE_CURSOR_MOVE) != 0 {
        return Err(FsError::InvalidData);
    }
    let requests = {
        let mut card = mode_state.lock();
        if let Some(a) = admission {
            a.check(&card)?;
        }
        card.crtc(req.crtc_id).map_err(|_| FsError::NotFound)?;
        let cursor =
            *crate::drm_native_planes::cursor_of(&card, req.crtc_id).ok_or(FsError::InvalidData)?;
        let mut wrapped = None;
        let fb_id = if req.flags & DRM_MODE_CURSOR_BO == 0 {
            cursor.fb_id
        } else if req.handle == 0 {
            None
        } else {
            let mut cmd = crate::drm::fb_cmd::FbCmd {
                width: req.size.0,
                height: req.size.1,
                pixel_format: crate::drm_native_planes::CURSOR_FORMATS[0],
                ..Default::default()
            };
            cmd.handles[0] = req.handle;
            cmd.pitches[0] = req.size.0.wrapping_mul(4);
            // An internal framebuffer: no open's drm_fb_release removes it.
            let id = match bo {
                Some(object) => {
                    card.addfb2_bo(&cmd, object, crate::drm_devfs_bridge::NO_MASTER_OPEN_ID)
                }
                None => card.addfb2_cmd(&cmd),
            }
            .map_err(|e| match e {
                crate::drm::card::CardError::BadGemHandle => FsError::NotFound,
                _ => FsError::InvalidData,
            })?;
            wrapped = Some(id);
            Some(id)
        };
        let position = if req.flags & DRM_MODE_CURSOR_MOVE != 0 {
            req.position
        } else {
            cursor.legacy_position
        };
        let (w, h) = fb_id
            .and_then(|id| card.framebuffer(id).ok())
            .map_or((0, 0), |fb| (fb.width, fb.height));
        let plane = crate::drm::atomic::PlaneState {
            id: cursor.id,
            crtc_id: fb_id.map(|_| req.crtc_id),
            fb_id,
            crtc_x: position.0,
            crtc_y: position.1,
            crtc_w: w,
            crtc_h: h,
            src_x: 0,
            src_y: 0,
            src_w: w,
            src_h: h,
            in_fence_fd: None,
            props: Some(cursor.props),
        };
        match commit_cursor_plane(card_index, &mut card, plane, false) {
            Ok(requests) => {
                if let Some(p) = card.native_planes.iter_mut().find(|p| p.id == cursor.id) {
                    if wrapped.is_some() {
                        p.internal_fb = true;
                    }
                    if req.flags & DRM_MODE_CURSOR_MOVE != 0 {
                        p.legacy_position = req.position;
                    }
                }
                requests
            }
            Err(e) => {
                // The wrapped framebuffer goes with the failed update.
                if let Some(id) = wrapped {
                    release_framebuffer(&mut card, id);
                }
                return Err(e);
            }
        }
    };
    send_cursor_requests(requests);
    Ok(0)
}

/// One native cursor plane's commit for the CRTC's hardware cursor: what
/// it shows (a dumb buffer's image, or a pinned GEM buffer whose rows the
/// cursor task reads once its writes landed) and where.
struct CursorRequest {
    crtc_id: u32,
    image: Option<CursorImage>,
    position: (i32, i32),
}

/// Whether native plane state `plane` is a cursor plane shown on a CRTC.
fn cursor_plane_shown(
    card: &crate::drm::card::Card,
    plane: &crate::drm::atomic::PlaneState,
) -> bool {
    plane.fb_id.is_some()
        && plane.crtc_id.is_some()
        && card.native_plane(plane.id).is_some_and(|p| p.is_cursor())
}

/// A one-plane commit of a native cursor plane, as `__setplane_atomic`
/// (legacy CURSOR, SETPLANE) runs it: the core and amdgpu_dm checks, then
/// the commit. Returns the hardware cursor requests.
#[cfg(feature = "amdgpu")]
fn commit_cursor_plane(
    card_index: u32,
    card: &mut crate::drm::card::Card,
    plane: crate::drm::atomic::PlaneState,
    validate_only: bool,
) -> Result<Vec<CursorRequest>, FsError> {
    let mut state = crate::drm::atomic::AtomicState::default();
    state.planes.push(plane);
    let policy = crate::drm::atomic::AtomicCheckPolicy::default();
    if state.core_check(card, &policy).is_err() {
        return Err(FsError::InvalidData);
    }
    crate::drm_native_planes::check(card, &state, |c| card.crtc(c).ok().and_then(|c| c.mode))?;
    if validate_only {
        return Ok(Vec::new());
    }
    // prepare_fb: a cursor's GEM buffer pinned in VRAM, or the update fails.
    let prepared = PreparedFbs::prepare(
        card,
        state
            .planes
            .iter()
            .filter(|p| p.crtc_id.is_some())
            .filter_map(|p| p.fb_id),
    )?;
    let cursors = crate::drm_native_planes::cursor_changes(card, &state);
    if state.core_commit(card).is_err() {
        return Err(FsError::InvalidData);
    }
    crate::drm_native_planes::commit(card, &state);
    Ok(native_cursor_requests(
        card_index, card, &cursors, &prepared,
    ))
}

/// amdgpu_dm_commit_cursors for committed cursor plane changes: each
/// CRTC's image (read out of the framebuffer's BO) and position for the
/// native display, after the legacy-wrapped framebuffers the planes let go
/// of are removed. Only the native amdgpu card has a hardware cursor.
#[cfg(feature = "amdgpu")]
fn native_cursor_requests(
    card_index: u32,
    card: &mut crate::drm::card::Card,
    changes: &[crate::drm_native_planes::CursorChange],
    prepared: &PreparedFbs,
) -> Vec<CursorRequest> {
    for c in changes {
        if let Some(fb) = c.released_fb {
            release_framebuffer(card, fb);
        }
    }
    if crate::drm_registry::driver_name(card_index) != Some("amdgpu") {
        return Vec::new();
    }
    changes
        .iter()
        .map(|c| CursorRequest {
            crtc_id: c.crtc_id,
            image: c.fb_id.and_then(|fb| {
                crate::drm_native_planes::cursor_content(card, fb, prepared.pin(fb))
            }),
            position: c.position,
        })
        .collect()
}

fn send_cursor_requests(requests: Vec<CursorRequest>) {
    // Only the native amdgpu card has hardware cursors to send to;
    // the request list is empty without it.
    #[cfg(feature = "amdgpu")]
    for r in requests {
        if let Some(display) = crate::amdgpu_native_kms::crtc_display(r.crtc_id) {
            crate::amdgpu_native_kms::request_display_cursor(display, r.image, r.position);
        }
    }
    #[cfg(not(feature = "amdgpu"))]
    let _ = requests;
}

/// Drop a kernel-held framebuffer (a legacy-wrapped cursor one), freeing
/// its backing when that was the last reference, as RMFB does.
fn release_framebuffer(card: &mut crate::drm::card::Card, fb_id: u32) {
    if let Ok(Some((phys, order))) = card.rmfb(fb_id) {
        let frame = narf_memory::frame::PhysFrame::new(narf_memory::addr::PhysAddr::new(phys));
        narf_memory::frame::free_pages(frame, order);
    }
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
    let bpp_bytes = req.bpp.div_ceil(8);
    // The native amdgpu card pads lines as amdgpu_mode_dumb_create does
    // (amdgpu_gem_align_pitch: a 256-byte multiple for 1-4 bytes per pixel),
    // which its ADDFB2's LINEAR pitch check (amdgpu_display_verify_sizes)
    // requires; other cards keep packed lines. (With its VRAM heap up, that
    // card's opens make VRAM buffers instead: `amdgpu_dumb`.)
    let pitch = if mode_state.lock().gfx12_modifiers {
        #[cfg(feature = "amdgpu")]
        {
            match crate::amdgpu_gem::align_pitch(req.width, bpp_bytes) {
                0 => return Err(FsError::InvalidData),
                pitch => pitch,
            }
        }
        #[cfg(not(feature = "amdgpu"))]
        {
            req.width * bpp_bytes
        }
    } else {
        req.width * bpp_bytes
    };
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
static DIRTYFB_N: AtomicU64 = AtomicU64::new(0);
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
/// A plane's destination (x, y, w, h on the CRTC) and source (x, y, w, h
/// in the framebuffer) rectangles.
type PlaneRects = ((i32, i32, u32, u32), (u32, u32, u32, u32));

/// What a natively scanned-out primary plane can show: an unscaled,
/// full-screen frame from the framebuffer's origin in one of the card's
/// plane formats (`Card::plane_formats`), covering the CRTC's mode. Linux
/// refuses scaling or positioning a plane cannot do with EINVAL, and a
/// framebuffer smaller than its viewport with ENOSPC
/// (drm_atomic_helper_check_plane_state, drm_crtc_check_viewport).
/// `Ok` on cards without native planes.
fn check_native_plane(
    card: &crate::drm::card::Card,
    fb_id: u32,
    mode: Option<crate::Mode>,
    origin: (u32, u32),
    rects: Option<PlaneRects>,
) -> Result<(), FsError> {
    let Some(formats) = card.plane_formats else {
        return Ok(());
    };
    let fb = card.framebuffer(fb_id).map_err(|_| FsError::NotFound)?;
    if !formats.contains(&(fb.format as u32)) {
        return Err(FsError::InvalidData);
    }
    let Some(mode) = mode else {
        return Err(FsError::InvalidData);
    };
    let (w, h) = (mode.width, mode.height);
    if origin != (0, 0) {
        return Err(FsError::InvalidData);
    }
    if let Some((dst, src)) = rects {
        if dst != (0, 0, w, h) || src != (0, 0, w, h) {
            return Err(FsError::InvalidData);
        }
    }
    if fb.width < w || fb.height < h {
        return Err(FsError::NoSpace);
    }
    Ok(())
}

/// Every enabled plane of an atomic state on a native card, in the mode
/// its CRTC has after the commit (`check_native_plane`).
pub(crate) fn check_native_atomic(
    card: &crate::drm::card::Card,
    state: &crate::drm::atomic::AtomicState,
) -> Result<(), FsError> {
    // amdgpu_dm's native planes take placement and scaling, checked by
    // `drm_native_planes::check` instead.
    if !card.native_planes.is_empty() {
        return Ok(());
    }
    for plane in &state.planes {
        let (Some(fb_id), Some(crtc_id)) = (plane.fb_id, plane.crtc_id) else {
            continue;
        };
        let mode = state
            .crtcs
            .iter()
            .find(|c| c.id == crtc_id)
            .map(|c| c.mode)
            .unwrap_or_else(|| card.crtc(crtc_id).ok().and_then(|c| c.mode));
        let rects = (
            (plane.crtc_x, plane.crtc_y, plane.crtc_w, plane.crtc_h),
            (plane.src_x, plane.src_y, plane.src_w, plane.src_h),
        );
        check_native_plane(card, fb_id, mode, (0, 0), Some(rects))?;
    }
    Ok(())
}

fn handle_setcrtc(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }
    let (req, connector) = scanout_kms::copy_setcrtc(arg)?;
    handle_setcrtc_decoded(card_index, mode_state, req, connector, None, false)
}

fn handle_setcrtc_decoded(
    card_index: u32,
    mode_state: &Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    req: DrmModeCrtcUapi,
    setcrtc_connector: Option<u32>,
    admission: Option<&scanout_kms::CommitAdmission<'_>>,
    validate_only: bool,
) -> Result<u64, FsError> {
    // Look up the framebuffer → GEM handle → dumb backing phys.
    let src_phys: Option<u64>;
    let virgl_resource: Option<Arc<VirtGpuResource>>;
    let src_pitch: u32;
    let src_w: u32;
    let src_h: u32;
    let src_frame: crate::drm::card::PlaneFrame;
    // A GEM framebuffer, pinned for scanout in place.
    let gem_frame: Option<crate::drm::card::PlaneFrame>;
    {
        let mut card = mode_state.lock();
        if let Some(a) = admission {
            a.check(&card)?;
        }
        card.crtc(req.crtc_id).map_err(|_| FsError::NotFound)?;

        // The native display behind this CRTC, on the amdgpu card.
        #[cfg(feature = "amdgpu")]
        let native_display = (crate::drm_registry::driver_name(card_index) == Some("amdgpu"))
            .then(|| crate::amdgpu_native_kms::crtc_display(req.crtc_id))
            .flatten();
        #[cfg(not(feature = "amdgpu"))]
        let native_display: Option<u8> = None;
        // The connector SETCRTC routes the native CRTC to: one at most (no
        // cloning); none keeps the current routing.
        let native_connector = if native_display.is_some() && req.count_connectors != 0 {
            if req.count_connectors != 1 || req.set_connectors_ptr == 0 {
                return Err(FsError::InvalidData);
            }
            let id = setcrtc_connector.ok_or(FsError::InvalidData)?;
            if card.connector(id).is_err() {
                return Err(FsError::InvalidData);
            }
            Some(id)
        } else {
            None
        };
        let mut native_wire = None;
        if req.mode_valid != 0 {
            let m = req.mode;
            let wire = crate::drm::ioctl::DrmModeModeInfo {
                clock: m.clock,
                hdisplay: m.hdisplay,
                hsync_start: m.hsync_start,
                hsync_end: m.hsync_end,
                htotal: m.htotal,
                hskew: m.hskew,
                vdisplay: m.vdisplay,
                vsync_start: m.vsync_start,
                vsync_end: m.vsync_end,
                vtotal: m.vtotal,
                vscan: m.vscan,
                vrefresh: m.vrefresh,
                flags: m.flags,
                r#type: m.r#type,
                name: m.name,
            };
            if !card.accepts_mode(&wire) {
                return Err(FsError::InvalidData);
            }
            // On the native card, a timing this CRTC's own display offers.
            #[cfg(feature = "amdgpu")]
            if native_display.is_some_and(|d| {
                !crate::amdgpu_native_kms::display_offers(d, native_connector, &wire)
            }) || (crate::drm_registry::driver_name(card_index) == Some("amdgpu")
                && native_display.is_none())
            {
                return Err(FsError::InvalidData);
            }
            native_wire = Some(wire);
        }

        let requested = (req.mode_valid != 0).then(|| crate::Mode {
            width: u32::from(req.mode.hdisplay),
            height: u32::from(req.mode.vdisplay),
            refresh_hz: req.mode.vrefresh as u16,
            bpp: 32,
        });
        // A native plane is validated before any state changes.
        if req.fb_id != 0 {
            let mode = requested.or_else(|| card.crtc(req.crtc_id).ok().and_then(|c| c.mode));
            check_native_plane(&card, req.fb_id, mode, (req.x, req.y), None)?;
            // The native display must admit the plane's format at the mode.
            #[cfg(feature = "amdgpu")]
            if let Some(d) = native_display {
                let format = card
                    .framebuffer(req.fb_id)
                    .map_err(|_| FsError::NotFound)?
                    .format;
                // A tiled or 4:2:0 framebuffer is scanned as a placed
                // primary: DML admits the display's planes with it.
                let placed = mode.and_then(|m| {
                    crate::drm_native_planes::setcrtc_planes(
                        &card,
                        req.crtc_id,
                        req.fb_id,
                        (req.x, req.y),
                        (m.width, m.height),
                    )
                });
                let hdmi = native_output_on_crtc(&card, req.crtc_id, native_connector)
                    .filter(|n| n.color_format.is_some());
                if let Some(native) = hdmi {
                    let setup = placed
                        .transpose()?
                        .map_or(crate::amdgpu_navi48_boot::PlaneSetup::NONE, |p| p.setup);
                    if !setcrtc_output_format_supported(
                        &card,
                        d,
                        native.connector,
                        native_wire,
                        format as u32,
                        setup,
                    ) {
                        return Err(FsError::InvalidData);
                    }
                } else if let Some(planes) = placed {
                    let planes = planes?;
                    if !crate::amdgpu_native_kms::display_admits_planes(
                        d,
                        native_connector,
                        native_wire.as_ref(),
                        format as u32,
                        &planes.setup,
                    ) {
                        return Err(FsError::InvalidData);
                    }
                } else if !crate::amdgpu_native_kms::display_admits_format(
                    d,
                    native_connector,
                    native_wire.as_ref(),
                    format as u32,
                ) {
                    return Err(FsError::InvalidData);
                }
            }
        }

        // amdgpu_dm_plane_helper_prepare_fb before the commit changes any
        // state: a GEM framebuffer that cannot be pinned fails SETCRTC.
        if validate_only {
            return Ok(0);
        }
        let prepared = PreparedFbs::prepare(&card, (req.fb_id != 0).then_some(req.fb_id))?;
        // Record the mode and active fb on the crtc; switching it off
        // without a mode clears the mode (drm_mode_setcrtc).
        if let Ok(crtc) = card.crtc_mut(req.crtc_id) {
            crtc.primary_fb = if req.fb_id != 0 {
                Some(req.fb_id)
            } else {
                None
            };
            crtc.enabled = req.fb_id != 0;
            if requested.is_some() || req.fb_id == 0 {
                crtc.mode = requested;
            }
        }
        // drm_atomic_helper_set_config: the primary shows the framebuffer
        // whole at the mode again; the overlays stay as committed.
        #[cfg(feature = "amdgpu")]
        crate::drm_native_planes::reset_primary(&mut card, req.crtc_id);
        #[cfg(feature = "amdgpu")]
        if let Some(display) = native_display {
            let setup = crate::drm_native_planes::displays(&card)
                .into_iter()
                .find(|d| d.crtc_id == req.crtc_id)
                .map_or(crate::amdgpu_navi48_boot::PlaneSetup::NONE, |d| d.setup);
            crate::amdgpu_native_kms::request_display_planes(display, setup);
        }
        // The native display follows the CRTC's on/off state, and another
        // offered timing is a native modeset the display monitor runs (the
        // current one leaves it as it is).
        #[cfg(feature = "amdgpu")]
        if let Some(display) = native_display {
            if let Some(id) = native_connector {
                crate::amdgpu_native_kms::request_display_route(display, Some(id));
            }
            if let Some(wire) = native_wire.as_ref() {
                crate::amdgpu_native_kms::request_display_mode(display, Some(wire));
            }
            if let Ok(fb) = card.framebuffer(req.fb_id) {
                crate::amdgpu_native_kms::request_display_format(display, fb.format as u32);
            }
            crate::amdgpu_native_kms::request_display_active(display, req.fb_id != 0);
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
        src_frame = fb_frame(fb, src_phys.unwrap_or(0));
        gem_frame = fb
            .bo
            .is_some()
            .then(|| prepared_frame(&card, fb, &prepared))
            .flatten();
        virgl_resource = card.virtgpu_import(gem_handle).cloned();
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
    if let Some(resource) = virgl_resource {
        present_virgl_frame(&resource, src_w, src_h)?;
    } else if let Some(f) = gem_frame {
        present_frame(card_index, req.crtc_id, f, None);
    } else if let Some(src) = src_phys {
        present_frame(
            card_index,
            req.crtc_id,
            crate::drm::card::PlaneFrame {
                phys: src,
                ..src_frame
            },
            None,
        );
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

/// DRM_IOCTL_MODE_DIRTYFB (`drm_mode_dirtyfb_ioctl`, DRM_MASTER): the
/// contents of `fb_id` changed. Linux's dumb-buffer drivers flush them to
/// the display (`drm_atomic_helper_dirtyfb`); here every CRTC showing the
/// framebuffer presents it again through the same path as SETCRTC. Clip
/// rectangles are accepted and the whole frame is presented. A GEM
/// framebuffer is scanned out in place and needs nothing.
fn handle_dirty_fb(
    card_index: u32,
    mode_state: &Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }
    // struct drm_mode_fb_dirty_cmd { fb_id, flags, color, num_clips: u32;
    // clips_ptr: u64 } is 24 bytes.
    // SAFETY: `arg` is the user drm_mode_fb_dirty_cmd pointer.
    let raw = unsafe { copy_in(arg, 24)? };
    let cmd = crate::drm::fb_cmd::DirtyCmd::parse(&raw).ok_or(FsError::InvalidData)?;
    let clips = if cmd.num_clips == 0 {
        Vec::new()
    } else {
        let len = cmd.num_clips as usize * crate::drm::fb_cmd::CLIP_RECT_BYTES;
        // SAFETY: `clips_ptr` is the user drm_clip_rect array of
        // `num_clips` entries (at most DIRTY_MAX_CLIPS, so 2 KiB).
        unsafe { copy_in(cmd.clips_ptr as usize, len)? }
    };
    let (crtcs, frame) = {
        let card = mode_state.lock();
        let fb = card.framebuffer(cmd.fb_id).map_err(|_| FsError::NotFound)?;
        let crtcs: Vec<u32> = card
            .crtcs
            .iter()
            .filter(|c| c.primary_fb == Some(cmd.fb_id))
            .map(|c| c.id)
            .collect();
        let frame = if fb.bo.is_some() {
            None
        } else {
            card.dumb_backing(fb.gem_handle)
                .map(|b| fb_frame(fb, b.phys))
        };
        (crtcs, frame)
    };
    let rows = frame.as_ref().map_or(0..0, |f| cmd.rows(&clips, f.height));
    let (log, n) = should_log(&DIRTYFB_N);
    if log {
        let _ = writeln!(
            narf_console::Writer,
            "  drm: DIRTYFB #{n} fb={} crtcs={} backing={} rows={}..{}",
            cmd.fb_id,
            crtcs.len(),
            if frame.is_some() { "yes" } else { "NONE" },
            rows.start,
            rows.end
        );
    }
    // A request whose clips cover no row changes nothing on screen.
    if let Some(f) = frame.filter(|_| !rows.is_empty()) {
        for crtc in crtcs {
            present_dirty(card_index, crtc, f.clone(), rows.clone());
        }
    }
    Ok(0)
}

/// Present dumb framebuffer `f` on `crtc_id` after DIRTYFB damaged `rows`:
/// a native amdgpu display copies just those rows (and what its back
/// buffer missed); anything else presents the whole frame.
fn present_dirty(
    card_index: u32,
    crtc_id: u32,
    f: crate::drm::card::PlaneFrame,
    rows: core::ops::Range<u32>,
) {
    #[cfg(feature = "amdgpu")]
    if crate::drm_registry::driver_name(card_index) == Some("amdgpu")
        && f.bo.is_none()
        && f.modifier == 0
        && f.offsets == [0; 2]
        && f.chroma_pitch == 0
        && matches!(f.format, DRM_FORMAT_XRGB8888 | DRM_FORMAT_ARGB8888)
    {
        if let Some(display) = crate::amdgpu_native_kms::crtc_display(crtc_id) {
            if crate::amdgpu_native_kms::present_damaged(display, f.clone(), rows) {
                narf_console::fb_take_for_user();
                return;
            }
        }
    }
    present_frame(card_index, crtc_id, f, None);
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
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }
    let req = scanout_kms::copy_page_flip(arg)?;
    handle_page_flip_decoded(card_index, mode_state, req, events, None, false)
}

fn handle_page_flip_decoded(
    card_index: u32,
    mode_state: &Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    req: DrmModePageFlipUapi,
    events: Option<&narf_lib::sync::IrqSafeSpinLock<crate::drm::card::DrmEventQueue>>,
    admission: Option<&scanout_kms::CommitAdmission<'_>>,
    validate_only: bool,
) -> Result<u64, FsError> {
    // DRM_MODE_PAGE_FLIP_EVENT — queue a flip-complete event the client
    // reads off the DRM fd after poll/select (the compositor render loop).
    const DRM_MODE_PAGE_FLIP_EVENT: u32 = 0x01;
    // Linux virtio-gpu does not advertise async flips and its CRTC exposes
    // `page_flip`, not `page_flip_target`, so ASYNC/TARGET are EINVAL.
    if req.flags & !DRM_MODE_PAGE_FLIP_EVENT != 0 || req.reserved != 0 {
        return Err(FsError::InvalidData);
    }

    let src_phys: Option<u64>;
    let virgl_resource: Option<Arc<VirtGpuResource>>;
    let src_w: u32;
    let src_h: u32;
    let src_frame: crate::drm::card::PlaneFrame;
    // A GEM framebuffer, pinned for scanout in place.
    let gem_frame: Option<crate::drm::card::PlaneFrame>;
    let mut flip_ticket = None;
    {
        let mut card = mode_state.lock();
        if let Some(a) = admission {
            a.check(&card)?;
        }
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
        let mode = card.crtc(req.crtc_id).ok().and_then(|c| c.mode);
        let (x, y) = card
            .crtc(req.crtc_id)
            .map(|c| (c.x, c.y))
            .unwrap_or_default();
        // A placed native primary keeps its placement: the new framebuffer
        // must hold its source rectangle (drm_atomic_helper_page_flip
        // changes the framebuffer alone).
        #[cfg(feature = "amdgpu")]
        let fits = crate::drm_native_planes::flip_fits(&card, req.crtc_id, req.fb_id);
        #[cfg(not(feature = "amdgpu"))]
        let fits: Option<bool> = None;
        match fits {
            Some(true) => {}
            Some(false) => return Err(FsError::NoSpace),
            None => check_native_plane(&card, req.fb_id, mode, (x, y), None)?,
        }
        let fb = card.framebuffer(req.fb_id).map_err(|_| FsError::NotFound)?;
        src_w = fb.width;
        src_h = fb.height;
        let gem_handle = fb.gem_handle;
        src_phys = card.dumb_backing(gem_handle).map(|b| b.phys);
        src_frame = fb_frame(fb, src_phys.unwrap_or(0));
        // prepare_fb before the flip changes any state: a GEM framebuffer
        // that cannot be pinned fails PAGE_FLIP (no event is queued).
        if validate_only {
            if req.flags & DRM_MODE_PAGE_FLIP_EVENT != 0 {
                events
                    .ok_or(FsError::InvalidData)?
                    .lock()
                    .ensure_flip_event_space(1)
                    .map_err(|_| FsError::OutOfMemory)?;
            }
            return Ok(0);
        }
        let prepared = PreparedFbs::prepare(&card, [req.fb_id])?;
        let fb = card.framebuffer(req.fb_id).map_err(|_| FsError::NotFound)?;
        gem_frame = fb
            .bo
            .is_some()
            .then(|| prepared_frame(&card, fb, &prepared))
            .flatten();
        virgl_resource = card.virtgpu_import(gem_handle).cloned();

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
        // A framebuffer of another tiling changes the primary's surface
        // (DC's full update): the display relights with it, as for an
        // atomic commit.
        #[cfg(feature = "amdgpu")]
        if let Some(display) =
            crate::amdgpu_native_kms::crtc_display(req.crtc_id).filter(|_| card.gfx12_modifiers)
        {
            if let Some(d) = crate::drm_native_planes::displays(&card)
                .into_iter()
                .find(|d| d.crtc_id == req.crtc_id)
            {
                crate::amdgpu_native_kms::request_display_planes(display, d.setup);
            }
        }

        if let Some(queue) = event_queue.as_mut() {
            #[cfg(feature = "amdgpu")]
            let hardware = (virgl_resource.is_none()
                && (src_phys.is_some() || gem_frame.is_some())
                && hardware_flips(card_index, req.crtc_id))
            .then(|| crate::amdgpu_native_kms::crtc_display(req.crtc_id))
            .flatten();
            #[cfg(not(feature = "amdgpu"))]
            let hardware: Option<u8> = None;
            if let Some(display) = hardware {
                // The event waits for the hardware flip of this frame.
                let ticket = crate::drm::card::flips(display).lock().reserve();
                card.queue_hw_flip_event(queue, req.user_data, req.crtc_id, display, ticket)
                    .map_err(|_| FsError::OutOfMemory)?;
                flip_ticket = Some(ticket);
            } else {
                // The blit is synchronous; completion is then exposed at the
                // simulated-vblank deadline recorded by queue_flip_event.
                card.queue_flip_event(queue, req.user_data, req.crtc_id)
                    .map_err(|_| FsError::OutOfMemory)?;
            }
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

    if let Some(resource) = virgl_resource {
        present_virgl_frame(&resource, src_w, src_h)?;
    } else if let Some(f) = gem_frame {
        present_frame(card_index, req.crtc_id, f, flip_ticket);
    } else if let Some(src) = src_phys {
        present_frame(
            card_index,
            req.crtc_id,
            crate::drm::card::PlaneFrame {
                phys: src,
                ..src_frame
            },
            flip_ticket,
        );
    } else {
        note_missing_backing("PAGE_FLIP", req.fb_id);
    }
    Ok(0)
}

/// Wait for every GPU write that is still attached to a scanout buffer.
///
/// `EXECBUFFER` is asynchronous, so a KMS read must not reach the same
/// resource until its implicit dma-buf WRITE fences have completed.  Take the
/// reservation snapshot before waiting: device fences can reap completions by
/// taking the VirtIO request gate, and waiting while the reservation lock is
/// held would deadlock the producer.  The bound is the same GPU-hang bound as
/// `VIRTGPU_WAIT` and EXECBUFFER input-fence handling.
pub(crate) fn wait_virgl_scanout_writes(resource: &VirtGpuResource) -> Result<(), FsError> {
    const GPU_FENCE_TIMEOUT_MS: u64 = 15_000;

    for fence in resource.dma_buf.resv.fences(DmaResvUsage::Write) {
        if !fence.is_signalled() && !fence.wait(GPU_FENCE_TIMEOUT_MS) {
            return Err(FsError::Busy);
        }
    }
    Ok(())
}

/// Present a PRIME-imported VirGL GEM object directly, matching Linux's
/// virtio-gpu primary-plane update (`SET_SCANOUT` + `RESOURCE_FLUSH`).
fn present_virgl_frame(resource: &VirtGpuResource, width: u32, height: u32) -> Result<(), FsError> {
    // This must precede SET_SCANOUT/RESOURCE_FLUSH.  The caller holds no DRM
    // or reservation lock here, so an asynchronous render submission can
    // finish and reap its fence without lock inversion.
    wait_virgl_scanout_writes(resource)?;
    let dev = narf_drivers_virtio::gpu_pci::probed_device().ok_or(FsError::InvalidData)?;
    narf_console::fb_take_for_user();
    dev.present_virgl_resource(resource.resource_id, width, height)
        .map_err(map_gpu_transport_error)
}

/// Present a dumb buffer on the card that accepted the KMS ioctl.
///
/// The QEMU profile keeps bochs as an emergency display fallback while
/// virtio-gpu is card0.  Those are independent framebuffers: copying a
/// virtio card's pixels through the global fbdev hook would silently draw on
/// bochs instead.  Select the owning card here so the primary DRM node and
/// the visible scanout always agree.
/// Whether `card_index` presents dumb-buffer frames through a hardware flip,
/// so their flip-complete events wait for that flip (see `drm::card::FlipLog`).
fn hardware_flips(card_index: u32, crtc_id: u32) -> bool {
    // Only the amdgpu native card flips in hardware.
    #[cfg(feature = "amdgpu")]
    {
        crate::drm_registry::driver_name(card_index) == Some("amdgpu")
            && crate::amdgpu_native_kms::crtc_display(crtc_id)
                .is_some_and(crate::amdgpu_native_kms::native_present_ready)
    }
    #[cfg(not(feature = "amdgpu"))]
    {
        let _ = (card_index, crtc_id);
        false
    }
}

/// DRM_IOCTL_MODE_SETPLANE — `struct drm_mode_set_plane` (48 bytes):
/// plane_id, crtc_id, fb_id, flags, crtc_x, crtc_y (s32), crtc_w, crtc_h,
/// src_x, src_y, src_h, src_w (16.16). On a card with amdgpu_dm's native
/// planes it is drm_mode_setplane's atomic path (__setplane_atomic): the
/// plane alone updated (fb 0 disables it) through the same checks and
/// admission as an atomic commit, without events or ALLOW_MODESET.
///
/// Linux ref: `drivers/gpu/drm/drm_plane.c::drm_mode_setplane`,
/// `drm_atomic_helper_update_plane`.
fn handle_setplane(
    card_index: u32,
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    if !ctx.is_master {
        return Err(FsError::PermissionDenied);
    }
    // SAFETY: fixed-size UAPI, copied with guarded user access.
    let bytes = unsafe { copy_in(arg, 48)? };
    handle_setplane_decoded(card_index, mode_state, &bytes, None, false)
}

fn handle_setplane_decoded(
    card_index: u32,
    mode_state: &Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    bytes: &[u8],
    admission: Option<&scanout_kms::CommitAdmission<'_>>,
    validate_only: bool,
) -> Result<u64, FsError> {
    // SETPLANE's atomic path serves native planes only; those exist
    // only on the amdgpu native card.
    #[cfg(feature = "amdgpu")]
    {
        handle_setplane_decoded_native(card_index, mode_state, bytes, admission, validate_only)
    }
    #[cfg(not(feature = "amdgpu"))]
    {
        let _ = (card_index, mode_state, bytes, admission, validate_only);
        Err(FsError::Unsupported)
    }
}

#[cfg(feature = "amdgpu")]
fn handle_setplane_decoded_native(
    card_index: u32,
    mode_state: &Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    bytes: &[u8],
    admission: Option<&scanout_kms::CommitAdmission<'_>>,
    validate_only: bool,
) -> Result<u64, FsError> {
    let word = |i: usize| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    let (plane_id, crtc_id, fb_id) = (word(0), word(1), word(2));
    let (crtc_x, crtc_y, crtc_w, crtc_h) = (word(4) as i32, word(5) as i32, word(6), word(7));
    let (src_x, src_y, src_h, src_w) = (word(8), word(9), word(10), word(11));
    let amdgpu = crate::drm_registry::driver_name(card_index) == Some("amdgpu");
    let mut cursor_requests = Vec::new();
    let presentation = {
        let mut card = mode_state.lock();
        if let Some(a) = admission {
            a.check(&card)?;
        }
        if card.native_planes.is_empty() {
            return Err(FsError::Unsupported);
        }
        let mut plane =
            crate::drm_native_planes::plane_state(&card, plane_id).ok_or(FsError::NotFound)?;
        let cursor = card.native_plane(plane_id).is_some_and(|p| p.is_cursor());
        if fb_id == 0 {
            plane.crtc_id = None;
            plane.fb_id = None;
        } else {
            let fb = card.framebuffer(fb_id).map_err(|_| FsError::NotFound)?;
            card.crtc(crtc_id).map_err(|_| FsError::NotFound)?;
            // __setplane_check: Linux's -ERANGE overflow help (EINVAL
            // here) and drm_framebuffer_check_src_coords' -ENOSPC.
            if crtc_w > i32::MAX as u32
                || crtc_x > i32::MAX - crtc_w as i32
                || crtc_h > i32::MAX as u32
                || crtc_y > i32::MAX - crtc_h as i32
            {
                return Err(FsError::InvalidData);
            }
            let (fw, fh) = (u64::from(fb.width) << 16, u64::from(fb.height) << 16);
            let (sx, sy, sw, sh) = (
                u64::from(src_x),
                u64::from(src_y),
                u64::from(src_w),
                u64::from(src_h),
            );
            if sw > fw || sx > fw - sw || sh > fh || sy > fh - sh {
                return Err(FsError::NoSpace);
            }
            plane.crtc_id = Some(crtc_id);
            plane.fb_id = Some(fb_id);
            plane.crtc_x = crtc_x;
            plane.crtc_y = crtc_y;
            plane.crtc_w = crtc_w;
            plane.crtc_h = crtc_h;
            plane.src_x = src_x >> 16;
            plane.src_y = src_y >> 16;
            plane.src_w = src_w >> 16;
            plane.src_h = src_h >> 16;
            // dm_check_cursor_fb on the 16.16 source.
            if cursor && (src_x | src_y | src_w | src_h) & 0xffff != 0 {
                return Err(FsError::InvalidData);
            }
        }
        if cursor {
            // drm_atomic_helper_update_plane: a legacy cursor update.
            cursor_requests = commit_cursor_plane(card_index, &mut card, plane, validate_only)?;
            Vec::new()
        } else {
            let mut state = crate::drm::atomic::AtomicState::default();
            state.planes.push(plane);
            let policy = crate::drm::atomic::AtomicCheckPolicy::default();
            if state.core_check(&card, &policy).is_err() {
                return Err(FsError::InvalidData);
            }
            let displays = crate::drm_native_planes::check(&card, &state, |c| {
                card.crtc(c).ok().and_then(|c| c.mode)
            })?;
            for dp in &displays {
                if let Some(d) =
                    crate::amdgpu_native_kms::crtc_display(dp.crtc_id).filter(|_| amdgpu)
                {
                    if !crate::amdgpu_native_kms::display_admits_planes(
                        d,
                        None,
                        None,
                        dp.primary_format,
                        &dp.setup,
                    ) {
                        return Err(FsError::InvalidData);
                    }
                }
            }
            // prepare_fb before the update changes any state.
            if validate_only {
                return Ok(0);
            }
            let prepared = PreparedFbs::prepare(&card, state.planes[0].fb_id)?;
            if state.core_commit(&mut card).is_err() {
                return Err(FsError::InvalidData);
            }
            crate::drm_native_planes::commit(&mut card, &state);
            let mut frames = Vec::new();
            for dp in &displays {
                let Some(display) =
                    crate::amdgpu_native_kms::crtc_display(dp.crtc_id).filter(|_| amdgpu)
                else {
                    continue;
                };
                crate::amdgpu_native_kms::request_display_planes(display, dp.setup);
                let primary = (card.native_plane(plane_id).and_then(|p| p.primary_of)
                    == Some(dp.crtc_id))
                .then(|| native_plane_frame(&card, &state.planes[0], &prepared))
                .flatten();
                if let Some(f) = &primary {
                    crate::amdgpu_native_kms::request_display_format(display, f.format);
                }
                let overlays = dp.overlays.map(|id| {
                    id.filter(|&id| id == plane_id)
                        .and_then(|_| native_plane_frame(&card, &state.planes[0], &prepared))
                });
                frames.push((dp.crtc_id, primary, overlays));
            }
            frames
        }
    };
    send_cursor_requests(cursor_requests);
    for (crtc_id, primary, overlays) in presentation {
        present_native_planes(card_index, crtc_id, primary, overlays, None);
    }
    Ok(0)
}

/// amdgpu_dm_plane_helper_prepare_fb for the framebuffers a commit shows,
/// run under the KMS lock before the commit changes any state: each GEM
/// framebuffer's buffer pinned in VRAM (`GemObject::pin_scanout`; the
/// async `amdgpu_kms_async` moved it back first). A pin that fails
/// fails the ioctl with its errno before anything changed, as a failed
/// prepare_fb fails drm_atomic_helper_prepare_planes; dropping the set
/// unpins them (cleanup_fb of the failed commit). A dumb framebuffer
/// needs no pin.
#[derive(Default)]
pub(crate) struct PreparedFbs(Vec<(u32, crate::drm::card::ScanoutPin)>);
impl PreparedFbs {
    pub(crate) fn prepare(
        card: &crate::drm::card::Card,
        fb_ids: impl IntoIterator<Item = u32>,
    ) -> Result<Self, FsError> {
        let mut pins: Vec<(u32, crate::drm::card::ScanoutPin)> = Vec::new();
        for id in fb_ids {
            if pins.iter().any(|(f, _)| *f == id) {
                continue;
            }
            // Only an amdgpu GEM framebuffer pins; a dumb one needs none.
            #[cfg(feature = "amdgpu")]
            {
                let Some(bo) = card.framebuffer(id).ok().and_then(|fb| fb.bo.as_ref()) else {
                    continue;
                };
                match bo.object.pin_scanout() {
                    Ok(pin) => pins.push((id, Arc::new(pin))),
                    Err(e) => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  drm: fb {id} not pinned for scanout: {e:?}"
                        );
                        return Err(e);
                    }
                }
            }
            #[cfg(not(feature = "amdgpu"))]
            let _ = (card, id);
        }
        Ok(Self(pins))
    }
    /// The pin prepare took on framebuffer `fb_id`'s GEM buffer.
    pub(crate) fn pin(&self, fb_id: u32) -> Option<crate::drm::card::ScanoutPin> {
        self.0
            .iter()
            .find(|(f, _)| *f == fb_id)
            .map(|(_, p)| p.clone())
    }
}

/// A native plane's framebuffer as the presenter shows it: its dumb
/// backing (which the presenter copies), or its amdgpu GEM buffer pinned
/// for scanout in place (`prepared_frame`); pitch, size and fourcc.
fn native_plane_frame(
    card: &crate::drm::card::Card,
    plane: &crate::drm::atomic::PlaneState,
    prepared: &PreparedFbs,
) -> Option<crate::drm::card::PlaneFrame> {
    prepared_frame(card, card.framebuffer(plane.fb_id?).ok()?, prepared)
}

/// Framebuffer `fb` as the presenter shows it: a dumb buffer's backing, or
/// its GEM buffer with the pin `prepared` took on it, which a plane scans
/// out in place until a later flip latches past it. None without either.
fn prepared_frame(
    card: &crate::drm::card::Card,
    fb: &crate::drm::card::Framebuffer,
    prepared: &PreparedFbs,
) -> Option<crate::drm::card::PlaneFrame> {
    if fb.bo.is_some() {
        return Some(crate::drm::card::PlaneFrame {
            bo: Some(prepared.pin(fb.id)?),
            ..fb_frame(fb, 0)
        });
    }
    let phys = card.dumb_backing(fb.gem_handle)?.phys;
    Some(fb_frame(fb, phys))
}

/// `prepared_frame` of framebuffer `fb` after preparing it alone (None
/// when its GEM buffer cannot be pinned).
#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
pub(crate) fn scanout_frame(
    card: &crate::drm::card::Card,
    fb: &crate::drm::card::Framebuffer,
) -> Option<crate::drm::card::PlaneFrame> {
    let prepared = PreparedFbs::prepare(card, [fb.id]).ok()?;
    prepared_frame(card, fb, &prepared)
}

/// Framebuffer `fb` (backed at `phys`) as the presenter copies it.
fn fb_frame(fb: &crate::drm::card::Framebuffer, phys: u64) -> crate::drm::card::PlaneFrame {
    crate::drm::card::PlaneFrame {
        phys,
        pitch: fb.pitch,
        width: fb.width,
        height: fb.height,
        format: fb.format as u32,
        offsets: fb.offsets,
        chroma_pitch: fb.chroma_pitch,
        modifier: fb.modifier,
        bo: None,
    }
}

/// A display with native planes presents an atomic commit's planes
/// together through its back buffers; when it cannot, the primary takes
/// `present_frame`'s fallback.
#[cfg(feature = "amdgpu")]
fn present_native_planes(
    card_index: u32,
    crtc_id: u32,
    primary: Option<crate::drm::card::PlaneFrame>,
    overlays: [Option<crate::drm::card::PlaneFrame>; crate::amdgpu_dcn401_otg::MAX_OVERLAYS],
    ticket: Option<u64>,
) {
    let Some(display) = crate::amdgpu_native_kms::crtc_display(crtc_id) else {
        return;
    };
    if primary.is_none() && overlays.iter().all(Option::is_none) {
        // Nothing to copy: the event completes in place.
        if ticket.is_some() {
            crate::amdgpu_native_kms::present_planes(display, None, overlays, ticket);
        }
        return;
    }
    // A client framebuffer scanned out in place has no CPU fallback.
    let fallback = primary.clone().filter(|f| f.bo.is_none());
    if crate::amdgpu_native_kms::present_planes(display, primary, overlays, ticket) {
        narf_console::fb_take_for_user();
        return;
    }
    if let Some(f) = fallback {
        present_frame(card_index, crtc_id, f, None);
    }
}

/// `flip_ticket` is the ticket of a flip-complete event waiting for this
/// frame's hardware flip; it is completed whichever way the frame goes.
/// `f` is the framebuffer: its dumb backing, pitch, size, fourcc and, on
/// the native amdgpu card, its planes and modifier.
fn present_frame(
    card_index: u32,
    crtc_id: u32,
    f: crate::drm::card::PlaneFrame,
    flip_ticket: Option<u64>,
) {
    let (src_phys, src_pitch, src_w, src_h, src_format) =
        (f.phys, f.pitch, f.width, f.height, f.format);
    let driver = crate::drm_registry::driver_name(card_index);
    // A native amdgpu display presents tear-free through its back buffer
    // and a VUPDATE-latched flip instead of copying onto the visible front.
    #[cfg(feature = "amdgpu")]
    if driver == Some("amdgpu") {
        if let Some(display) = crate::amdgpu_native_kms::crtc_display(crtc_id) {
            // A refused frame completes its ticket at once. A tiled or 4:2:0
            // framebuffer (only the Navi 48 card takes them) goes as its
            // primary plane's frame.
            let linear =
                f.bo.is_none() && f.modifier == 0 && f.offsets == [0; 2] && f.chroma_pitch == 0;
            let gem = f.bo.is_some();
            let native = if linear {
                crate::amdgpu_native_kms::present_frame(
                    display,
                    src_phys,
                    src_pitch,
                    src_w,
                    src_h,
                    flip_ticket,
                    src_format,
                )
            } else {
                crate::amdgpu_native_kms::present_planes(
                    display,
                    Some(f),
                    core::array::from_fn(|_| None),
                    flip_ticket,
                )
            };
            if native {
                narf_console::fb_take_for_user();
                return;
            }
            // A GEM framebuffer is scanned out in place or not at all.
            if gem {
                return;
            }
            // Only the console's display has a CPU front to copy onto, and
            // that copy takes 32-bit 8888 pixels.
            if display != crate::amdgpu_native_kms::console_pipe()
                || !matches!(src_format, DRM_FORMAT_XRGB8888 | DRM_FORMAT_ARGB8888)
            {
                return;
            }
        }
    }
    if driver == Some("virtio_gpu") {
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
    // SAFETY: fb replaces its generic mapping through scanout_access; all
    // destination accesses below finish before this view is dropped.
    let view = unsafe { crate::scanout_access::snapshot(crate::drm_fb_hook::query_scanout) };
    let info = match *view {
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
        let offset = (row * info.stride_bytes as usize) as u64;
        // A device-memory scanout is reached through its kernel mapping; a
        // RAM-backed one through the physical map.
        let dst = if info.virt != 0 {
            (info.virt + offset) as *mut u8
        } else {
            narf_memory::PhysAddr::new(info.phys + offset).kernel_mut_ptr::<u8>()
        };
        // SAFETY: src is an identity-mapped dumb buffer validated by its
        // allocator; dst is the scanout's mapping or physical-map address.
        // `row_bytes` is within both (row < dst_h <= src_h, dst_w <= src_w).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(src_row).kernel_ptr::<u8>(),
                dst,
                row_bytes,
            );
        }
    }
    drop(view);
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
        // fb_id is the first __u32 of both drm_mode_fb_cmd and fb_cmd2.
        crate::drm::ioctl::DrmIoctlResult::AddFb2(fb_id) if arg != 0 => {
            // SAFETY: `arg` is the validated user framebuffer request pointer.
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

/// `DRM_IOWR(0x05, struct drm_client)`: idx i32, auth i32, then pid, uid,
/// magic and iocs as `unsigned long` — 40 bytes on LP64.
pub const DRM_IOCTL_GET_CLIENT: u32 = 0xc028_6405;

/// Linux `drm_getclient`, the "hollowed-out" form kept for old tools and for
/// libdrm's `amdgpu_get_auth`: client 0 is the caller (its authentication,
/// its pid, `overflowuid`, no magic, no ioctl count); any other index is
/// EINVAL.
pub fn get_client(
    arg: u64,
    context: &dyn narf_filesystem::IoctlContext,
    authenticated: bool,
) -> Result<u64, FsError> {
    let mut client = [0u8; 40];
    context
        .read(arg, &mut client)
        .map_err(|_| FsError::BadAddress)?;
    if i32::from_le_bytes(client[0..4].try_into().unwrap()) != 0 {
        return Err(FsError::InvalidData);
    }
    /// `overflowuid` default.
    const OVERFLOW_UID: u64 = 65534;
    client[4..8].copy_from_slice(&i32::from(authenticated).to_le_bytes());
    client[8..16].copy_from_slice(&u64::from(context.process_id()).to_le_bytes());
    client[16..24].copy_from_slice(&OVERFLOW_UID.to_le_bytes());
    client[24..40].fill(0);
    context
        .write(arg, &client)
        .map_err(|_| FsError::BadAddress)?;
    Ok(0)
}

/// `DRM_IOCTL_VERSION` and `DRM_IOCTL_GET_CAP` for an amdgpu card that has
/// no KMS state attached (no native display publication yet): libdrm's
/// `amdgpu_device_initialize` dereferences `drmGetVersion`'s result, so the
/// render node must answer even without a display owner. `None` for any
/// other ioctl or a card with KMS state (the card's own table answers).
#[cfg(feature = "amdgpu")]
pub fn without_kms(card_index: u32, cmd: u32, arg: usize) -> Option<Result<u64, FsError>> {
    if crate::drm_registry::driver_name(card_index) != Some("amdgpu")
        || crate::drm_registry::mode_state(card_index).is_some()
        || (cmd >> 8) & 0xff != u32::from(b'd')
    {
        return None;
    }
    match drm_uapi::ioc_nr(cmd) {
        0x00 => Some(amdgpu_version(card_index, arg)),
        0x0c => Some((|| {
            // SAFETY: `arg` is the ioctl struct pointer; 16 bytes.
            let mut b = unsafe { copy_in(arg, 16)? };
            let cap = u64::from_le_bytes(b[0..8].try_into().unwrap());
            let value = amdgpu_cap_value(cap);
            b[8..16].copy_from_slice(&value.to_le_bytes());
            // SAFETY: as above.
            unsafe { copy_out(arg, &b)? };
            Ok(0)
        })()),
        _ => None,
    }
}

/// `DRM_IOCTL_GET_CAP` for amdgpu: the generic table, plus
/// `DRM_CAP_SYNCOBJ_TIMELINE` = 1 (amdgpu has `DRIVER_SYNCOBJ_TIMELINE`).
#[cfg(feature = "amdgpu")]
pub fn amdgpu_cap_value(cap: u64) -> u64 {
    // amdgpu: DRIVER_SYNCOBJ_TIMELINE, and format modifiers are supported
    // (!fb_modifiers_not_supported); only LINEAR scans out natively.
    if cap == crate::drm::ioctl::drm_cap::SYNCOBJ_TIMELINE
        || cap == crate::drm::ioctl::drm_cap::ADDFB2_MODIFIERS
    {
        1
    } else {
        crate::drm::ioctl::cap_value(cap)
    }
}

/// `DRM_IOCTL_GET_CAP(SYNCOBJ_TIMELINE)` on an amdgpu open (with or without
/// KMS state); `None` for any other ioctl or capability, which the card's
/// generic table answers identically for amdgpu.
#[cfg(feature = "amdgpu")]
pub fn amdgpu_get_cap(cmd: u32, arg: usize) -> Option<Result<u64, FsError>> {
    if (cmd >> 8) & 0xff != u32::from(b'd') || drm_uapi::ioc_nr(cmd) != 0x0c {
        return None;
    }
    // SAFETY: `arg` is the ioctl struct pointer; drm_get_cap is 16 bytes.
    let mut b = match unsafe { copy_in(arg, 16) } {
        Ok(b) => b,
        Err(e) => return Some(Err(e)),
    };
    let cap = u64::from_le_bytes(b[0..8].try_into().unwrap());
    if cap != crate::drm::ioctl::drm_cap::SYNCOBJ_TIMELINE
        && cap != crate::drm::ioctl::drm_cap::ADDFB2_MODIFIERS
    {
        return None;
    }
    b[8..16].copy_from_slice(&amdgpu_cap_value(cap).to_le_bytes());
    // SAFETY: as above.
    Some(unsafe { copy_out(arg, &b) }.map(|()| 0))
}

/// `DRM_IOCTL_AMDGPU_GEM_METADATA` on one of the native amdgpu card's dumb
/// BOs (Linux dumb buffers are amdgpu BOs, so the ioctl takes them): SET
/// records the tiling flags a later ADDFB2 without modifiers converts
/// (convert_tiling_flags_to_modifier_gfx12), GET returns them with no
/// metadata blob. `None` for another ioctl or a handle that is not a dumb
/// BO of a native amdgpu card (the per-open amdgpu GEM table answers it).
#[cfg(feature = "amdgpu")]
pub fn amdgpu_dumb_metadata(card_index: u32, cmd: u32, arg: usize) -> Option<Result<u64, FsError>> {
    let nr = drm_uapi::ioc_nr(cmd);
    if (cmd >> 8) & 0xff != u32::from(b'd')
        || nr != drm_uapi::DRM_COMMAND_BASE + crate::amdgpu_uapi::DRM_AMDGPU_GEM_METADATA
    {
        return None;
    }
    let mode_state = crate::drm_registry::mode_state(card_index)?;
    // SAFETY: `arg` is the ioctl pointer; drm_amdgpu_gem_metadata is 288 bytes.
    let mut b = match unsafe { copy_in(arg, 288) } {
        Ok(b) => b,
        Err(e) => return Some(Err(e)),
    };
    let field = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let (handle, op) = (field(&b, 0), field(&b, 4));
    let mut card = mode_state.lock();
    if !card.gfx12_modifiers || card.gem.lookup(handle).is_none() {
        return None;
    }
    match op {
        crate::amdgpu_uapi::AMDGPU_GEM_METADATA_OP_SET_METADATA => {
            if field(&b, 24) > 256 {
                return Some(Err(FsError::InvalidData));
            }
            let tiling = u64::from_le_bytes(b[16..24].try_into().unwrap());
            // A dumb BO is never created with AMDGPU_GEM_CREATE_GFX12_DCC.
            card.set_bo_tiling(handle, tiling, false);
            Some(Ok(0))
        }
        crate::amdgpu_uapi::AMDGPU_GEM_METADATA_OP_GET_METADATA => {
            let tiling = card
                .bo_tiling
                .iter()
                .find(|t| t.0 == handle)
                .map_or(0, |t| t.1);
            drop(card);
            b[8..16].fill(0);
            b[16..24].copy_from_slice(&tiling.to_le_bytes());
            b[24..28].fill(0);
            // SAFETY: as above.
            Some(unsafe { copy_out(arg, &b) }.map(|()| 0))
        }
        _ => Some(Ok(0)),
    }
}

/// `DRM_IOCTL_MODE_ADDFB` / `ADDFB2` on the native amdgpu card naming an amdgpu GEM
/// handle of the calling open (`gem`, owner `open_id`):
/// amdgpu_display_user_framebuffer_create's drm_gem_object_lookup in the
/// file's own handle table, then `Card::addfb2_bo`. `None` for another
/// ioctl, another card, or a handle that is not one of the open's amdgpu
/// GEM buffers (the card's ADDFB2 then answers it as before).
#[cfg(feature = "amdgpu")]
pub fn amdgpu_addfb2_bo(
    card_index: u32,
    open_id: u64,
    cmd: u32,
    arg: usize,
    gem: &crate::amdgpu_gem::GemState,
) -> Option<Result<u64, FsError>> {
    let legacy = cmd == drm_uapi::DRM_IOCTL_MODE_ADDFB;
    if (!legacy && cmd != drm_uapi::DRM_IOCTL_MODE_ADDFB2) || arg == 0 {
        return None;
    }
    let mode_state = crate::drm_registry::mode_state(card_index)?;
    if !mode_state.lock().gfx12_modifiers {
        return None;
    }
    let size = if legacy {
        drm_uapi::SZ_DRM_MODE_FB_CMD
    } else {
        drm_uapi::SZ_DRM_MODE_FB_CMD2
    };
    // SAFETY: `arg` is the ioctl pointer; the selected Linux request size is
    // 28 (fb_cmd) or 104 (fb_cmd2), checked by copy_in.
    let b = match unsafe { copy_in(arg, size as usize) } {
        Ok(b) => b,
        Err(e) => return Some(Err(e)),
    };
    let fb = if legacy {
        // This helper is reached only from the primary node. Match the
        // generic legacy handler's display-authority gate before allocating.
        if !mode_state.lock().is_master(open_id) {
            return Some(Err(FsError::PermissionDenied));
        }
        match crate::drm::ioctl::legacy_fb_cmd(&b) {
            Ok(fb) => fb,
            Err(e) => return Some(Err(map_err(e))),
        }
    } else {
        crate::drm::fb_cmd::FbCmd::parse(&b)?
    };
    if !gem.owns(fb.handles[0]) {
        return None;
    }
    let object = gem.object(fb.handles[0])?;
    let id = mode_state
        .lock()
        .addfb2_bo(&fb, object, open_id)
        .map_err(|e| match e {
            crate::drm::card::CardError::BadGemHandle => FsError::NotFound,
            _ => FsError::InvalidData,
        });
    Some(id.and_then(|id| {
        // SAFETY: as above; fb_id is the struct's first u32.
        unsafe { copy_out(arg, &id.to_le_bytes()) }.map(|()| 0)
    }))
}

/// Whether CREATE_DUMB on DRM card `card_index` makes an amdgpu GEM buffer
/// in VRAM (`amdgpu_mode_dumb_create`): the native Navi48 card, once its
/// client VRAM heap is up. Other cards, and the Navi48 card without a heap
/// (before bring-up, while suspended or recovering), keep the card's
/// system-memory dumb buffers.
#[cfg(feature = "amdgpu")]
fn amdgpu_vram_dumb(card_index: u32) -> bool {
    crate::drm_registry::mode_state(card_index).is_some_and(|m| m.lock().gfx12_modifiers)
        && crate::amdgpu_gem::vram_heap_usage(card_index).is_some()
}

#[cfg(feature = "amdgpu")]
fn amdgpu_dumb_live(card_index: u32) -> Result<(), FsError> {
    let native =
        crate::drm_registry::mode_state(card_index).is_some_and(|mode| mode.lock().gfx12_modifiers);
    if native {
        crate::amdgpu_gem::ensure_placement_live(card_index)?;
    }
    Ok(())
}

/// CREATE_DUMB's `struct drm_mode_create_dumb` at `arg`, filled in with the
/// `(handle, pitch, size)` of `made` on success. `NoSpace` is ENOMEM, as
/// amdgpu_mode_dumb_create returns it.
#[cfg(feature = "amdgpu")]
fn finish_amdgpu_dumb(
    arg: usize,
    req: DrmModeCreateDumbUapi,
    made: Result<(u32, u32, u64), FsError>,
) -> Result<u64, FsError> {
    let (handle, pitch, size) = made.map_err(|e| match e {
        FsError::NoSpace => FsError::OutOfMemory,
        e => e,
    })?;
    let out = DrmModeCreateDumbUapi {
        handle,
        pitch,
        size,
        ..req
    };
    // SAFETY: DrmModeCreateDumbUapi is #[repr(C)] POD of 32 bytes.
    let bytes: [u8; 32] = unsafe { core::mem::transmute(out) };
    // SAFETY: `arg` is the ioctl pointer, 32 bytes as copied in.
    unsafe { copy_out(arg, &bytes) }.map(|()| 0)
}

/// `struct drm_mode_create_dumb` at `arg`.
fn read_create_dumb(arg: usize) -> Result<DrmModeCreateDumbUapi, FsError> {
    // SAFETY: `arg` is the ioctl pointer; copy_in bounds-checks.
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCreateDumbUapi>())? };
    // SAFETY: `bytes` holds exactly one repr(C) POD struct.
    Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeCreateDumbUapi) })
}

/// The dumb-buffer ioctls of an amdgpu card open whose GEM table is `gem`
/// (drm_mode_create_dumb / drm_mode_mmap_dumb_ioctl / drm_mode_destroy_dumb
/// on Linux's one per-file handle space):
/// - CREATE_DUMB on the Navi48 card ([`amdgpu_vram_dumb`]) is
///   `GemState::create_dumb`: a VRAM buffer in the open's own table, which
///   ADDFB2 then scans out in place (`amdgpu_addfb2_bo`);
/// - MAP_DUMB and DESTROY_DUMB of one of the open's amdgpu GEM handles, on
///   any amdgpu card, are amdgpu_mode_dumb_mmap (the GEM_MMAP offset) and
///   drm_gem_handle_delete.
///
/// `None` for another ioctl, another card, or a handle the open's table
/// does not hold: the card's dumb-buffer table answers those as before.
#[cfg(feature = "amdgpu")]
pub fn amdgpu_dumb(
    card_index: u32,
    cmd: u32,
    arg: usize,
    gem: &crate::amdgpu_gem::GemState,
) -> Option<Result<u64, FsError>> {
    if cmd == drm_uapi::DRM_IOCTL_MODE_CREATE_DUMB {
        if let Err(error) = amdgpu_dumb_live(card_index) {
            return Some(Err(error));
        }
    }
    if arg == 0 {
        return None;
    }
    match cmd {
        drm_uapi::DRM_IOCTL_MODE_CREATE_DUMB if amdgpu_vram_dumb(card_index) => {
            Some(read_create_dumb(arg).and_then(|req| {
                finish_amdgpu_dumb(arg, req, gem.create_dumb(req.width, req.height, req.bpp))
            }))
        }
        drm_uapi::DRM_IOCTL_MODE_MAP_DUMB => {
            // SAFETY: `arg` is the ioctl pointer; drm_mode_map_dumb is 16 bytes.
            let mut b = match unsafe { copy_in(arg, 16) } {
                Ok(b) => b,
                Err(e) => return Some(Err(e)),
            };
            let handle = u32::from_le_bytes(b[0..4].try_into().unwrap());
            let offset = match gem.map_dumb(handle)? {
                Ok(offset) => offset,
                Err(e) => return Some(Err(e)),
            };
            b[8..16].copy_from_slice(&offset.to_le_bytes());
            // SAFETY: as above.
            Some(unsafe { copy_out(arg, &b) }.map(|()| 0))
        }
        drm_uapi::DRM_IOCTL_MODE_DESTROY_DUMB => {
            // SAFETY: `arg` is the ioctl pointer; drm_mode_destroy_dumb is 4 bytes.
            let b = match unsafe { copy_in(arg, 4) } {
                Ok(b) => b,
                Err(e) => return Some(Err(e)),
            };
            gem.destroy_dumb(u32::from_le_bytes(b[0..4].try_into().unwrap()))
                .then_some(Ok(0))
        }
        _ => None,
    }
}

/// CREATE_DUMB from a user open of the Navi48 card, which may sleep: when
/// visible VRAM is full, TTM's eviction (`amdgpu_gem::create_dumb_async`)
/// before ENOMEM. `None` where [`amdgpu_dumb`] answers `None`.
#[cfg(feature = "amdgpu")]
pub async fn amdgpu_create_dumb_async(
    card_index: u32,
    cmd: u32,
    arg: usize,
    gem: &crate::amdgpu_gem::GemState,
) -> Option<Result<u64, FsError>> {
    if cmd == drm_uapi::DRM_IOCTL_MODE_CREATE_DUMB {
        if let Err(error) = amdgpu_dumb_live(card_index) {
            return Some(Err(error));
        }
    }
    if cmd != drm_uapi::DRM_IOCTL_MODE_CREATE_DUMB || arg == 0 || !amdgpu_vram_dumb(card_index) {
        return None;
    }
    let req = match read_create_dumb(arg) {
        Ok(req) => req,
        Err(e) => return Some(Err(e)),
    };
    let made = crate::amdgpu_gem::create_dumb_async(gem, req.width, req.height, req.bpp).await;
    Some(finish_amdgpu_dumb(arg, req, made))
}

#[path = "amdgpu_scanout_kms.rs"]
mod scanout_kms;
#[cfg(feature = "amdgpu")]
pub(crate) use scanout_kms::dispatch as amdgpu_kms_async;

/// DRM_IOCTL_MODE_CURSOR{,2} with DRM_MODE_CURSOR_BO on the Navi48 card
/// naming one of open `open_id`'s amdgpu GEM handles (a dumb buffer from
/// CREATE_DUMB, say): drm_mode_cursor_universal wraps the buffer itself
/// (drm_internal_framebuffer_create's lookup in the file's table), as
/// `Card::addfb2_bo`. `None` for another ioctl, card or handle.
#[cfg(feature = "amdgpu")]
pub fn amdgpu_cursor_bo(
    card_index: u32,
    open_id: u64,
    cmd: u32,
    arg: usize,
    gem: &crate::amdgpu_gem::GemState,
) -> Option<Result<u64, FsError>> {
    const DRM_MODE_CURSOR_BO: u32 = 0x01;
    let nr = drm_uapi::ioc_nr(cmd);
    if (cmd >> 8) & 0xff != u32::from(b'd') || !matches!(nr, 0xA3 | 0xBB) || arg == 0 {
        return None;
    }
    let mode_state = crate::drm_registry::mode_state(card_index)?;
    {
        let card = mode_state.lock();
        if !card.gfx12_modifiers || card.native_planes.is_empty() {
            return None;
        }
    }
    let want = if nr == 0xBB { 36 } else { 28 };
    // SAFETY: `arg` is the ioctl pointer; copy_in bounds-checks `want`.
    let bytes = match unsafe { copy_in(arg, want) } {
        Ok(b) => b,
        Err(e) => return Some(Err(e)),
    };
    let rd = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    let (flags, handle) = (rd(0), rd(24));
    if flags & DRM_MODE_CURSOR_BO == 0 || handle == 0 || !gem.owns(handle) {
        return None;
    }
    let object = gem.object(handle)?;
    let ctx = DrmFileCtx::primary(mode_state.lock().is_master(open_id));
    Some(cursor_universal(
        card_index,
        &mode_state,
        &ctx,
        LegacyCursor {
            flags,
            crtc_id: rd(4),
            position: (rd(8) as i32, rd(12) as i32),
            size: (rd(16), rd(20)),
            handle,
        },
        Some(object),
        None,
    ))
}

/// `struct drm_version` for the amdgpu driver: `amdgpu`, `20150101`,
/// `AMD GPU`, `KMS_DRIVER_*` — 3.64.0 on a Navi 22 whose submission path is
/// wired, the base 3.0.0 otherwise.
#[cfg(feature = "amdgpu")]
fn amdgpu_version(card_index: u32, arg: usize) -> Result<u64, FsError> {
    // SAFETY: `arg` is the ioctl struct pointer; drm_version is 64 bytes.
    let mut b = unsafe { copy_in(arg, 64)? };
    let navi22 = crate::drm_registry::pci_id(card_index)
        == Some((crate::amdgpu::AMD_VENDOR, crate::amdgpu::NAVI22));
    let (major, minor, patch) = if navi22 {
        crate::amdgpu_info_navi22::drm_version()
    } else {
        (3, 0, 0)
    };
    b[0..4].copy_from_slice(&(major as i32).to_le_bytes());
    b[4..8].copy_from_slice(&(minor as i32).to_le_bytes());
    b[8..12].copy_from_slice(&(patch as i32).to_le_bytes());
    for (i, text) in [&b"amdgpu"[..], b"20150101", b"AMD GPU"].iter().enumerate() {
        let at = 16 + i * 16;
        let cap = u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) as usize;
        let ptr = u64::from_le_bytes(b[at + 8..at + 16].try_into().unwrap()) as usize;
        if ptr != 0 && cap != 0 {
            // SAFETY: the caller's own buffer of `cap` bytes.
            unsafe { copy_out(ptr, &text[..text.len().min(cap)])? };
        }
        b[at..at + 8].copy_from_slice(&(text.len() as u64).to_le_bytes());
    }
    // SAFETY: as above.
    unsafe { copy_out(arg, &b)? };
    Ok(0)
}
