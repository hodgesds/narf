//! Per-open Intel GEM storage. Host pages are owned by the object, not its
//! handle: CPU mappings, VM bindings and submitted jobs retain the same Arc.
//! Xe-LP and Xe-LPG integrated GPUs both use system-memory objects here.
//! An iGPU object created with DRM_XE_GEM_CPU_CACHING_WC lives in pages whose
//! kernel aliases are write-combining (`narf_memory::pageattr::WcPages`, the
//! TTM `ttm_write_combined` pool): CPU writes bypass the caches, so the
//! non-snooping display and non-coherent PATs see them without CLFLUSH.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::dma_buf::{dma_resv_usage_rw, DmaBufObject, DmaResvFence, DmaResvUsage};
use narf_filesystem::{FsError, MmapBacking};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::frame::{alloc_frame, free_frame, PhysFrame};

const PAGE: u64 = 4096;
const HANDLE_BASE: u32 = 0x4000_0000;
const MMAP_BASE: u64 = 0x1000_0000_0000;
const MAX_OBJECTS: usize = 4096;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static NEXT_MMAP: AtomicU64 = AtomicU64::new(MMAP_BASE);
// All reservation writers, including PRIME imports, and kernel CPU copies
// take this gate. Poll foreign fences/identity before it; retire references
// after it. Never retain the gate across an await or user-memory callback.
static RESERVATIONS: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

#[derive(Debug)]
pub struct GemObject {
    frames: Vec<PhysFrame>,
    /// USERPTR: retained caller pages instead of owned frames. Such objects
    /// have no handle, mmap offset, CPU copy path or PRIME export.
    pins: Vec<narf_memory::address_space::UserPagePin>,
    /// Local memory; reached by the CPU only through the LMEM BAR, after
    /// private initialization completes.
    vram: Option<crate::intel_gpu_vram::VramAllocation>,
    /// 1 private/uninitialized, 2 clear prepared/completed, 3 CPU clear in
    /// progress, 4 published. Zero is ordinary storage. No public handle,
    /// mmap or user VM reaches states 1..3.
    ccs: core::sync::atomic::AtomicU8,
    /// Zeroed write-combining system pages, in place of `frames`.
    wc: Option<narf_memory::pageattr::WcPages>,
    /// XE_BO_FLAG_SCANOUT: created for scanout, or made a framebuffer.
    scanout: core::sync::atomic::AtomicBool,
    /// Published VM bindings naming this object (Linux xe_bo_is_vm_bound).
    vm_binds: core::sync::atomic::AtomicU32,
    size: u64,
    /// `size` is charged to the system-memory LIVE_BYTES bound.
    charged: bool,
    offset: u64,
    vm_owner: Option<u64>,
    /// Serializes kernel CPU copies; never forms references to mapped data.
    cpu: IrqSafeSpinLock<()>,
    pub(crate) dma_buf: DmaBufObject,
}

/// Where [`GemState::create_placed`] puts an object's storage.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Placement<'a> {
    /// Write-back system pages.
    System,
    /// System pages every kernel alias maps write-combining.
    SystemWc,
    /// Zeroed VRAM, tried first; `true` permits write-back system memory when
    /// VRAM is exhausted.
    Vram(&'a Arc<crate::intel_gpu_vram::Vram>, bool),
}

/// Charge `size` bytes to the system-memory bound for an object's lifetime,
/// including after GEM_CLOSE while a VMA/VM/job still owns it. Closing
/// handles cannot bypass this bound.
fn charge(size: u64) -> Result<(), FsError> {
    let limit = ((narf_memory::frame::stats().total as u64 * PAGE) / 2).min(512 * 1024 * 1024);
    LIVE_BYTES
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
            live.checked_add(size).filter(|next| *next <= limit)
        })
        .map(|_| ())
        .map_err(|_| FsError::OutOfMemory)
}

impl GemObject {
    fn allocate(size: u64, offset: u64) -> Result<Self, FsError> {
        charge(size)?;
        let mut object = Self {
            frames: Vec::new(),
            pins: Vec::new(),
            vram: None,
            ccs: core::sync::atomic::AtomicU8::new(0),
            wc: None,
            scanout: core::sync::atomic::AtomicBool::new(false),
            vm_binds: core::sync::atomic::AtomicU32::new(0),
            size,
            charged: true,
            offset,
            vm_owner: None,
            cpu: IrqSafeSpinLock::new(()),
            dma_buf: DmaBufObject::new(),
        };
        object
            .frames
            .try_reserve_exact((size / PAGE) as usize)
            .map_err(|_| FsError::OutOfMemory)?;
        for _ in 0..size / PAGE {
            let frame = alloc_frame().map_err(|_| FsError::OutOfMemory)?;
            // SAFETY: newly allocated private frame, not published until zeroed.
            unsafe {
                core::ptr::write_bytes(
                    frame.start_address().kernel_mut_ptr::<u8>(),
                    0,
                    PAGE as usize,
                )
            };
            object.frames.push(frame);
        }
        Ok(object)
    }

    /// As `allocate`, in zeroed write-combining pages. A kernel that cannot
    /// retype RAM (aarch64) refuses with NotImplemented.
    fn allocate_wc(size: u64, offset: u64) -> Result<Self, FsError> {
        let mut object = Self::allocate(0, offset)?;
        charge(size)?;
        // From here the drop releases the charge, including on failure below.
        object.size = size;
        let pages =
            narf_memory::pageattr::WcPages::allocate((size / PAGE) as usize).map_err(|error| {
                match error {
                    narf_memory::pageattr::PageAttrError::NoFrame => FsError::OutOfMemory,
                    _ => FsError::NotImplemented,
                }
            })?;
        object.wc = Some(pages);
        Ok(object)
    }

    /// Owned system pages: write-back `frames` or the write-combining set.
    fn system_frames(&self) -> &[PhysFrame] {
        self.wc.as_ref().map_or(&self.frames, |wc| wc.frames())
    }

    /// System pages whose kernel and user CPU aliases are write-combining.
    pub(crate) fn is_wc(&self) -> bool {
        self.wc.is_some()
    }

    /// DRM_XE_GEM_CREATE_FLAG_SCANOUT, or made a framebuffer since.
    pub(crate) fn scanout(&self) -> bool {
        self.scanout.load(Ordering::Acquire)
    }

    pub(crate) fn mark_scanout(&self) {
        self.scanout.store(true, Ordering::Release);
    }

    /// Bound in some VM's published mapping set (Linux xe_bo_is_vm_bound).
    pub(crate) fn vm_bound(&self) -> bool {
        self.vm_binds.load(Ordering::Acquire) != 0
    }

    pub(crate) fn vm_bind(&self) {
        self.vm_binds.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn vm_unbind(&self) {
        let _ = self
            .vm_binds
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
    }

    /// Make device writes visible to CPU reads: CLFLUSH evicts any stale
    /// line of a write-back page; write-combining pages are never cached.
    pub(crate) fn sync_for_cpu_read(&self) -> bool {
        self.publish_for_device()
    }

    /// A VM-private USERPTR object over `pins`, charged like owned storage.
    pub(crate) fn from_user_pins(
        pins: Vec<narf_memory::address_space::UserPagePin>,
        vm: u64,
    ) -> Result<Arc<Self>, FsError> {
        let size = (pins.len() as u64)
            .checked_mul(PAGE)
            .filter(|size| *size != 0)
            .ok_or(FsError::InvalidData)?;
        let mut object = Self::allocate(0, 0)?;
        charge(size)?;
        object.size = size;
        object.pins = pins;
        object.vm_owner = Some(vm);
        Ok(Arc::new(object))
    }

    pub(crate) fn is_userptr(&self) -> bool {
        !self.pins.is_empty()
    }

    /// Device-memory pages carry the PPGTT DM bit and a VRAM address.
    pub(crate) fn is_vram(&self) -> bool {
        self.vram.is_some()
    }

    pub(crate) fn in_vram_pool(&self, pool: &Arc<crate::intel_gpu_vram::Vram>) -> bool {
        self.vram.as_ref().is_some_and(|vram| vram.pool_is(pool))
    }
    pub(crate) fn vram_page_size(&self) -> u64 {
        self.vram.as_ref().map_or(PAGE, |vram| vram.page_size())
    }
    pub(crate) fn begin_ccs_clear(&self) -> Result<(), FsError> {
        if !self.vram.as_ref().is_some_and(|v| v.requires_ccs_clear()) {
            return Err(FsError::Unsupported);
        }
        self.ccs
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| FsError::InvalidData)
    }

    /// Retain a private Xe2-style object for bounded CPU initialization.
    /// DG2 must use the trusted GPU data/flat-CCS clear instead.
    pub(crate) fn begin_cpu_vram_clear(self: &Arc<Self>) -> Result<CpuVramClear, FsError> {
        if self.vram.as_ref().is_none_or(|v| v.requires_ccs_clear()) {
            return Err(FsError::Unsupported);
        }
        self.ccs
            .compare_exchange(1, 3, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| FsError::InvalidData)?;
        Ok(CpuVramClear {
            object: self.clone(),
            next: 0,
            fence: Arc::new(crate::intel_gpu_fence::CompletionFence::new()),
        })
    }

    /// Kernel WC alias of byte `offset` of a VRAM object.
    fn vram_byte(&self, offset: u64) -> Option<*mut u8> {
        self.vram
            .as_ref()
            .map(|vram| (vram.kernel_virt() + offset) as *mut u8)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn vm_owner(&self) -> Option<u64> {
        self.vm_owner
    }

    pub fn pages(&self) -> impl Iterator<Item = u64> + '_ {
        self.system_frames()
            .iter()
            .map(|frame| frame.start_address().raw())
            .chain(self.pins.iter().map(|pin| pin.phys().raw()))
            .chain(self.vram.iter().flat_map(|vram| {
                (0..vram.size() / PAGE).map(move |page| vram.device_address() + page * PAGE)
            }))
    }

    /// i915 render-class reader (upper bits) and writer (lower bits).
    pub fn busy(&self) -> u32 {
        let snapshot = self.dma_buf.resv.snapshot();
        if snapshot.has_fences(DmaResvUsage::Write) {
            0x10001
        } else if snapshot.has_fences(DmaResvUsage::Read) {
            0x10000
        } else {
            0
        }
    }

    pub(crate) fn idle(&self, write: bool) -> bool {
        self.dma_buf
            .resv
            .fences(dma_resv_usage_rw(write))
            .is_empty()
    }

    /// Wait without holding any IRQ-safe guard or restarting a relative
    /// timeout. A terminal reset releases reservations just like completion.
    pub(crate) async fn wait_idle(
        &self,
        write: bool,
        deadline: Option<u64>,
    ) -> Result<(), FsError> {
        loop {
            if self.idle(write) {
                return Ok(());
            }
            let now = narf_time::monotonic_ns();
            if deadline.is_some_and(|deadline| now >= deadline) {
                return Err(FsError::TimedOut);
            }
            let delay = deadline.map_or(100_000, |end| (end - now).min(100_000));
            narf_time::SleepUntil::new(narf_time::Deadline::after_ns(delay).as_instant()).await;
        }
    }

    /// IMPORT_SYNC_FILE: descriptor lookup and all foreign fence callbacks
    /// precede the common CPU/GPU admission lock; mutation is one batch.
    pub(crate) fn import_fences(
        &self,
        fences: Vec<Arc<dyn narf_filesystem::DrmFence>>,
        write: bool,
    ) {
        if fences.is_empty() {
            return;
        }
        let usage = if write {
            DmaResvUsage::Write
        } else {
            DmaResvUsage::Read
        };
        let prepared: Vec<_> = fences
            .into_iter()
            .map(|fence| (DmaResvFence::new(fence), usage))
            .collect();
        let snapshot = self.dma_buf.resv.snapshot();
        let retired = {
            let _gate = RESERVATIONS.lock();
            self.dma_buf.resv.add_prepared(&snapshot, &prepared)
        };
        drop(retired);
    }

    pub(crate) fn publish_for_device(&self) -> bool {
        if self.is_wc() {
            // Nothing is cached; order earlier write-combining stores.
            wc_fence();
            return true;
        }
        crate::intel_gpu_gtt::publish_system_pages(self.frames.iter())
            && crate::intel_gpu_gtt::publish_system_phys(self.pins.iter().map(|pin| pin.phys()))
    }

    pub fn range(&self, offset: u64, len: usize) -> Result<(), FsError> {
        if self.is_userptr() || matches!(self.ccs.load(Ordering::Acquire), 1..=3) {
            return Err(FsError::InvalidData);
        }
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }

    /// Relative mapping used by PRIME exports as well as GEM mmap offsets.
    pub fn backing(self: &Arc<Self>, offset: u64, len: usize) -> Result<MmapBacking, FsError> {
        if len == 0 || offset % PAGE != 0 {
            return Err(FsError::InvalidData);
        }
        self.range(offset, len)?;
        let pages =
            (offset / PAGE) as usize..(offset / PAGE) as usize + len.div_ceil(PAGE as usize);
        if let Some(vram) = &self.vram {
            // LMEM BAR frames, write-combining as Linux's VRAM mmap.
            return Ok(MmapBacking {
                frames: pages
                    .map(|page| vram.cpu_address() + page as u64 * PAGE)
                    .collect(),
                lifetime: Some(self.clone()),
                memory_type: narf_memory::MemoryType::WriteCombining,
            });
        }
        let frames = self.pages().skip(pages.start).take(pages.len()).collect();
        Ok(MmapBacking {
            frames,
            lifetime: Some(self.clone()),
            // memory/ maps retyped pages with their recorded WC type.
            memory_type: if self.is_wc() {
                narf_memory::MemoryType::WriteCombining
            } else {
                narf_memory::MemoryType::WriteBack
            },
        })
    }

    pub fn read(&self, offset: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.range(offset, bytes.len())?;
        let snapshot = self.dma_buf.resv.snapshot();
        let _reservation = RESERVATIONS.lock();
        if !snapshot.is_current() || snapshot.has_fences(dma_resv_usage_rw(false)) {
            return Err(FsError::WouldBlock);
        }
        let _guard = self.cpu.lock();
        for (i, byte) in bytes.iter_mut().enumerate() {
            let at = offset + i as u64;
            if let Some(alias) = self.vram_byte(at) {
                // SAFETY: range checked; the allocation's WC alias is live.
                *byte = unsafe { core::ptr::read_volatile(alias) };
                continue;
            }
            let base = self.system_frames()[(at / PAGE) as usize]
                .start_address()
                .kernel_ptr::<u8>();
            // SAFETY: range checked; raw volatile access also tolerates concurrent
            // device/user mappings without creating aliased Rust references.
            *byte = unsafe { core::ptr::read_volatile(base.add((at % PAGE) as usize)) };
        }
        Ok(())
    }

    pub fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), FsError> {
        self.range(offset, bytes.len())?;
        let snapshot = self.dma_buf.resv.snapshot();
        let _reservation = RESERVATIONS.lock();
        if !snapshot.is_current() || snapshot.has_fences(dma_resv_usage_rw(true)) {
            return Err(FsError::WouldBlock);
        }
        let _guard = self.cpu.lock();
        for (i, byte) in bytes.iter().enumerate() {
            let at = offset + i as u64;
            if let Some(alias) = self.vram_byte(at) {
                // SAFETY: range checked; the allocation's WC alias is live.
                unsafe { core::ptr::write_volatile(alias, *byte) };
                continue;
            }
            let base = self.system_frames()[(at / PAGE) as usize]
                .start_address()
                .kernel_mut_ptr::<u8>();
            // SAFETY: same owned, range-checked pages as read().
            unsafe { core::ptr::write_volatile(base.add((at % PAGE) as usize), *byte) };
        }
        if self.is_wc() || self.is_vram() {
            // Write-combining stores are weakly ordered: drain them before a
            // later submission or fence publishes the bytes.
            wc_fence();
        }
        Ok(())
    }
}

/// SFENCE: retire this CPU's write-combining buffers.
fn wc_fence() {
    core::sync::atomic::fence(Ordering::SeqCst);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SFENCE has no memory operands or preconditions.
    unsafe {
        core::arch::asm!("sfence", options(nostack, preserves_flags))
    };
}

/// Atomic all-or-nothing conflict check followed by publication of the job's
/// terminal fence on every leaf. Read-only jobs may overlap; writes are
/// exclusive. The caller retains the residency graph until signalling it.
pub(crate) fn reserve_gpu(
    objects: &[(Arc<GemObject>, bool)],
    completion: &Arc<crate::intel_gpu_fence::CompletionFence>,
) -> Result<(), FsError> {
    let prepared = DmaResvFence::new(completion.clone());
    let snapshots: Vec<_> = objects
        .iter()
        .map(|(object, _)| object.dma_buf.resv.snapshot())
        .collect();
    if snapshots
        .iter()
        .zip(objects)
        .any(|(snapshot, (_, write))| snapshot.has_fences(dma_resv_usage_rw(*write)))
    {
        return Err(FsError::WouldBlock);
    }
    let retired: Vec<_> = {
        let _gate = RESERVATIONS.lock();
        if snapshots.iter().any(|snapshot| !snapshot.is_current()) {
            return Err(FsError::WouldBlock);
        }
        objects
            .iter()
            .zip(&snapshots)
            .map(|((object, write), snapshot)| {
                object.dma_buf.resv.add_prepared(
                    snapshot,
                    &[(
                        prepared.clone(),
                        if *write {
                            DmaResvUsage::Write
                        } else {
                            DmaResvUsage::Read
                        },
                    )],
                )
            })
            .collect()
    };
    drop(retired);
    Ok(())
}

/// Xe GPU clients supply explicit ordering. Imported READ/WRITE fences do not
/// create hidden GPU dependencies; every terminal fence still excludes CPU IO.
pub(crate) fn reserve_gpu_explicit(
    objects: &[(Arc<GemObject>, bool)],
    completion: &Arc<crate::intel_gpu_fence::CompletionFence>,
) {
    let prepared = DmaResvFence::new(completion.clone());
    let snapshots: Vec<_> = objects
        .iter()
        .map(|(object, _)| object.dma_buf.resv.snapshot())
        .collect();
    let retired: Vec<_> = {
        let _gate = RESERVATIONS.lock();
        objects
            .iter()
            .zip(&snapshots)
            .map(|((object, write), snapshot)| {
                object.dma_buf.resv.add_prepared(
                    snapshot,
                    &[(
                        prepared.clone(),
                        if *write {
                            DmaResvUsage::Write
                        } else {
                            DmaResvUsage::Read
                        },
                    )],
                )
            })
            .collect()
    };
    drop(retired);
}

impl Drop for GemObject {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            free_frame(frame);
        }
        if self.charged {
            LIVE_BYTES.fetch_sub(self.size, Ordering::AcqRel);
        }
    }
}

#[derive(Debug)]
struct Handles {
    next: u32,
    bytes: u64,
    objects: BTreeMap<u32, Arc<GemObject>>,
}

#[derive(Debug)]
pub struct GemState {
    handles: IrqSafeSpinLock<Handles>,
}

impl Default for GemState {
    fn default() -> Self {
        Self::new()
    }
}

impl GemState {
    pub const fn new() -> Self {
        Self {
            handles: IrqSafeSpinLock::new(Handles {
                next: HANDLE_BASE,
                bytes: 0,
                objects: BTreeMap::new(),
            }),
        }
    }

    /// Report before publishing. EFAULT consumes neither a handle nor pages.
    pub fn create(
        &self,
        size: u64,
        report: impl FnOnce(u32, u64) -> Result<(), FsError>,
    ) -> Result<u32, FsError> {
        self.create_for_vm(size, None, report)
    }

    pub(crate) fn create_for_vm(
        &self,
        size: u64,
        owner: Option<u64>,
        report: impl FnOnce(u32, u64) -> Result<(), FsError>,
    ) -> Result<u32, FsError> {
        self.create_placed(size, owner, Placement::System, report)
    }

    /// As `create_for_vm`, in `placement`. A VRAM object is not charged to the
    /// system-memory object limit.
    pub(crate) fn create_placed(
        &self,
        size: u64,
        owner: Option<u64>,
        placement: Placement<'_>,
        report: impl FnOnce(u32, u64) -> Result<(), FsError>,
    ) -> Result<u32, FsError> {
        if matches!(placement, Placement::Vram(..)) {
            // Only the asynchronous private-clear transaction may publish
            // local memory. A sync compatibility call cannot bypass its
            // retained power/GT owner, even for CPU-initialized Xe2 storage.
            return Err(FsError::Unsupported);
        }
        let size = size.checked_add(PAGE - 1).ok_or(FsError::InvalidData)? & !(PAGE - 1);
        if size == 0 || size > MAX_FILE_BYTES {
            return Err(FsError::InvalidData);
        }
        let mut handles = self.handles.lock();
        if handles.objects.len() >= MAX_OBJECTS || handles.bytes + size > MAX_FILE_BYTES {
            return Err(FsError::OutOfMemory);
        }
        let next = handles.next.checked_add(1).ok_or(FsError::OutOfMemory)?;
        // Global uniqueness lets imported objects keep one stable mmap
        // offset without colliding with this open's pre-existing objects.
        let offset = NEXT_MMAP
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |offset| {
                offset
                    .checked_add(size + PAGE)
                    .filter(|next| *next < 1 << 63)
            })
            .map_err(|_| FsError::OutOfMemory)?;
        let local = match placement {
            Placement::Vram(vram, fallback) => match vram.allocate(size) {
                Ok(allocation) => Some(allocation),
                Err(FsError::OutOfMemory) if fallback => None,
                Err(error) => return Err(error),
            },
            Placement::System | Placement::SystemWc => None,
        };
        let mut object = match (local, placement) {
            (Some(allocation), _) => {
                let mut object = GemObject::allocate(0, offset)?;
                object.vram = Some(allocation);
                object.size = size;
                object.charged = false;
                object
            }
            (None, Placement::SystemWc) => GemObject::allocate_wc(size, offset)?,
            (None, _) => GemObject::allocate(size, offset)?,
        };
        object.vm_owner = owner;
        let object = Arc::new(object);
        let handle = handles.next;
        report(handle, size)?;
        handles.objects.insert(handle, object);
        handles.next = next;
        handles.bytes += size;
        Ok(handle)
    }

    /// Reserve storage without any BAR access or public handle. Cancellation before or
    /// after submission drops only this reference; the scheduler retains its
    /// own target object through clear retirement or proven reset.
    pub(crate) fn prepare_vram(
        &self,
        size: u64,
        owner: Option<u64>,
        pool: &Arc<crate::intel_gpu_vram::Vram>,
    ) -> Result<PendingVram, FsError> {
        let size = size
            .checked_add(pool.page_size() - 1)
            .ok_or(FsError::InvalidData)?
            & !(pool.page_size() - 1);
        if size == 0 || size > MAX_FILE_BYTES {
            return Err(FsError::InvalidData);
        }
        {
            let handles = self.handles.lock();
            if handles.objects.len() >= MAX_OBJECTS || handles.bytes + size > MAX_FILE_BYTES {
                return Err(FsError::OutOfMemory);
            }
        }
        let offset = NEXT_MMAP
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |offset| {
                offset
                    .checked_add(size + PAGE)
                    .filter(|next| *next < 1 << 63)
            })
            .map_err(|_| FsError::OutOfMemory)?;
        let allocation = pool.allocate(size)?;
        let mut object = GemObject::allocate(0, offset)?;
        object.vram = Some(allocation);
        object.size = size;
        object.charged = false;
        object.vm_owner = owner;
        object.ccs.store(1, Ordering::Release);
        Ok(PendingVram {
            object: Arc::new(object),
        })
    }

    pub(crate) fn publish_vram(
        &self,
        pending: PendingVram,
        fence: &crate::intel_gpu_fence::CompletionFence,
        report: impl FnOnce(u32, u64) -> Result<(), FsError>,
    ) -> Result<u32, FsError> {
        if fence.result() != Some(Ok(())) || pending.object.ccs.load(Ordering::Acquire) != 2 {
            return Err(crate::intel_gpu_user::io_error());
        }
        let mut handles = self.handles.lock();
        let size = pending.object.size();
        if handles.objects.len() >= MAX_OBJECTS || handles.bytes + size > MAX_FILE_BYTES {
            return Err(FsError::OutOfMemory);
        }
        let next = handles.next.checked_add(1).ok_or(FsError::OutOfMemory)?;
        let handle = handles.next;
        report(handle, size)?;
        pending.object.ccs.store(4, Ordering::Release);
        handles.objects.insert(handle, pending.object);
        handles.next = next;
        handles.bytes += size;
        Ok(handle)
    }

    pub fn object(&self, handle: u32) -> Result<Arc<GemObject>, FsError> {
        self.handles
            .lock()
            .objects
            .get(&handle)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    pub(crate) fn export_object(&self, handle: u32) -> Result<Arc<GemObject>, FsError> {
        let object = self.object(handle)?;
        if object.vm_owner.is_some() {
            return Err(FsError::InvalidData);
        }
        // Importers expect host pages; VRAM would need migration or P2P.
        if object.is_vram() {
            return Err(FsError::NotImplemented);
        }
        Ok(object)
    }

    /// Same-card PRIME import. Reimporting the same object on an open returns
    /// its existing handle. The object retains its own allocation/accounting.
    pub fn import(&self, object: &Arc<GemObject>) -> Result<u32, FsError> {
        let mut handles = self.handles.lock();
        if let Some((handle, _)) = handles
            .objects
            .iter()
            .find(|(_, entry)| Arc::ptr_eq(entry, object))
        {
            return Ok(*handle);
        }
        if handles.objects.len() >= MAX_OBJECTS || handles.bytes + object.size > MAX_FILE_BYTES {
            return Err(FsError::OutOfMemory);
        }
        let handle = handles.next;
        handles.next = handle.checked_add(1).ok_or(FsError::OutOfMemory)?;
        handles.objects.insert(handle, object.clone());
        handles.bytes += object.size;
        Ok(handle)
    }

    pub fn close(&self, handle: u32) -> Result<(), FsError> {
        let mut handles = self.handles.lock();
        let object = handles.objects.remove(&handle).ok_or(FsError::NotFound)?;
        handles.bytes -= object.size;
        // Other owners (VMA, VM, jobs) retain this backing independently.
        drop(handles);
        drop(object);
        Ok(())
    }

    pub fn mmap_offset(&self, handle: u32) -> Result<u64, FsError> {
        Ok(self.object(handle)?.offset)
    }

    pub fn mapping_object(
        &self,
        offset: u64,
        len: usize,
    ) -> Result<(Arc<GemObject>, u64), FsError> {
        if len == 0 || offset % PAGE != 0 {
            return Err(FsError::InvalidData);
        }
        let handles = self.handles.lock();
        let object = handles
            .objects
            .values()
            .find(|object| offset >= object.offset && offset < object.offset + object.size)
            .cloned()
            .ok_or(FsError::NotFound)?;
        let within = offset - object.offset;
        object.range(within, len)?;
        Ok((object, within))
    }

    pub fn mmap_backing(&self, offset: u64, len: usize) -> Result<MmapBacking, FsError> {
        let (object, within) = self.mapping_object(offset, len)?;
        object.backing(within, len)
    }
}

pub(crate) struct PendingVram {
    object: Arc<GemObject>,
}

/// Sequential initialization token. Its object remains private and retains
/// the VRAM reservation throughout every CPU write and cancellation point.
pub(crate) struct CpuVramClear {
    object: Arc<GemObject>,
    next: u64,
    fence: Arc<crate::intel_gpu_fence::CompletionFence>,
}
impl CpuVramClear {
    /// Initialize and drain at most 64 KiB. Only the final completed chunk
    /// returns the operation's successful terminal fence.
    ///
    /// # Safety
    /// The caller holds this card's runtime-PM reference and GT state mutex,
    /// and has checked its current PCI capability, D0 and pool/epoch identity
    /// before this call. That proof remains valid throughout these writes.
    pub(crate) unsafe fn clear_next(
        &mut self,
    ) -> Option<Arc<crate::intel_gpu_fence::CompletionFence>> {
        if self.next == self.object.size {
            return Some(self.fence.clone());
        }
        let end = (self.next + 65536).min(self.object.size);
        let base = self
            .object
            .vram
            .as_ref()
            .expect("CPU VRAM token")
            .kernel_virt();
        for offset in (self.next..end).step_by(8) {
            // SAFETY: the token owns this private reservation; the caller
            // supplies current power/capability authority for the WC BAR.
            unsafe { core::ptr::write_volatile((base + offset) as *mut u64, 0) };
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        #[cfg(target_arch = "x86_64")]
        // SAFETY: SFENCE has no memory operands or preconditions.
        unsafe {
            core::arch::asm!("sfence", options(nostack, preserves_flags))
        };
        self.next = end;
        if end == self.object.size {
            self.object.ccs.store(2, Ordering::Release);
            self.fence.signal(Ok(()));
            Some(self.fence.clone())
        } else {
            None
        }
    }
}
impl PendingVram {
    pub(crate) fn object(&self) -> Arc<GemObject> {
        self.object.clone()
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::intel_gpu_fence::{CompletionFence, JobError};
    use narf_filesystem::DrmFence;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_reservations_conflicts_aliases_and_rollback() -> TestResult {
        let gem = GemState::new();
        let a = gem
            .object(gem.create(PAGE, |_, _| Ok(())).unwrap())
            .unwrap();
        let b = gem
            .object(gem.create(PAGE, |_, _| Ok(())).unwrap())
            .unwrap();
        let reader = Arc::new(CompletionFence::new());
        let reader2 = Arc::new(CompletionFence::new());
        let writer = Arc::new(CompletionFence::new());
        reserve_gpu(&[(a.clone(), false)], &reader).unwrap();
        reserve_gpu(&[(a.clone(), false)], &reader2).unwrap();
        assert_eq!(a.busy(), 0x10000);
        assert_eq!(a.read(0, &mut [0]), Ok(()));
        assert_eq!(a.write(0, &[1]), Err(FsError::WouldBlock));
        // The first object must not acquire a fence if a later one conflicts.
        let before = b.dma_buf.resv.generation();
        assert_eq!(
            reserve_gpu(&[(b.clone(), true), (a.clone(), true)], &writer),
            Err(FsError::WouldBlock)
        );
        assert_eq!(b.dma_buf.resv.generation(), before);
        assert_eq!(b.busy(), 0);
        reader2.signal(Ok(()));
        assert_eq!(a.busy(), 0x10000, "independent contexts collapsed");
        reader.signal(Err(JobError::Reset));
        assert!(DrmFence::wait(&*reader, 0));
        // Aliases requesting different access must retain the stronger usage.
        reserve_gpu(&[(a.clone(), false), (a.clone(), true)], &writer).unwrap();
        assert_eq!(a.busy(), 0x10001);
        assert_eq!(a.read(0, &mut [0]), Err(FsError::WouldBlock));
        let importer = GemState::new();
        let imported = importer.import(&a).unwrap();
        let alias = importer.object(imported).unwrap();
        assert_eq!(alias.busy(), 0x10001);
        assert!(!DrmFence::wait(&*writer, 0));
        assert_eq!(writer.context(), None);
        writer.signal(Ok(()));
        assert_eq!(alias.busy(), 0);
        assert_eq!(alias.write(0, &[7]), Ok(()));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gem",
        smoke_reservations_conflicts_aliases_and_rollback
    );
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_prime_sync_tests.rs"]
mod prime_sync_tests;
