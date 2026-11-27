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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use narf_filesystem::dma_buf::{dma_resv_usage_rw, DmaBufObject, DmaResvFence, DmaResvUsage};
use narf_filesystem::{FsError, IoctlContext, MmapBacking};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_memory::frame::{alloc_frame, free_frame, PhysFrame};

const PAGE: u64 = 4096;
const HANDLE_BASE: u32 = 0x4000_0000;
const MMAP_BASE: u64 = 0x1000_0000_0000;
const MAX_OBJECTS: usize = 4096;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const STORAGE_SYSTEM: u8 = 0;
const STORAGE_VRAM_VISIBLE: u8 = 1;
const STORAGE_VRAM_GPU_ONLY: u8 = 2;
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static NEXT_MMAP: AtomicU64 = AtomicU64::new(MMAP_BASE);
// All reservation writers, including PRIME imports, and kernel CPU copies
// take this gate. Poll foreign fences/identity before it; retire references
// after it. Never retain the gate across an await or user-memory callback.
static RESERVATIONS: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

#[path = "intel_gpu_cpu_mapping.rs"]
pub(crate) mod cpu_mapping;

#[derive(Debug)]
struct GemBacking {
    frames: Vec<PhysFrame>,
    /// Local memory; reached by the CPU only through the LMEM BAR, after
    /// private initialization completes.
    vram: Option<crate::intel_gpu_vram::VramAllocation>,
    /// Saved Flat-CCS auxiliary metadata retained while an Alchemist VRAM
    /// object is evicted to system memory.
    ccs_backup: Option<Arc<GemObject>>,
    /// A foreign dma-buf's mapped DMA addresses, one per 4 KiB page, once
    /// its attachment is mapped (`xe_bo_move` of a `ttm_bo_type_sg` BO). The
    /// exporter owns the memory; nothing here is freed.
    foreign: Vec<u64>,
    /// The attachment's move count `foreign` was mapped at: a later move
    /// notification makes the pages stale until the import maps again.
    foreign_generation: u64,
    /// `bo->backup_obj` of a dma-buf-pinned VRAM object across system
    /// suspend ([`GemObject::backup_pinned`]): its data saved to system
    /// memory while `vram` stays reserved, until the resume copies it back.
    suspend_backup: Option<SuspendBackup>,
    /// `size` is charged to the system-memory LIVE_BYTES bound.
    charged: bool,
}

/// A pinned VRAM object's saved contents (`xe_bo_evict_pinned`): the data
/// and, on Alchemist, its Flat-CCS metadata.
#[derive(Clone, Debug)]
struct SuspendBackup {
    data: Arc<GemObject>,
    ccs: Option<Arc<GemObject>>,
}

pub struct GemPages<'a> {
    backing: narf_lib::sync::IrqSafeSpinLockGuard<'a, GemBacking>,
    pins: &'a [narf_memory::address_space::UserPagePin],
    wc: Option<&'a narf_memory::pageattr::WcPages>,
    index: usize,
    /// An import whose exporter moved since its pages were mapped: it has
    /// no pages until it maps again.
    stale: bool,
}

impl core::fmt::Debug for GemPages<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GemPages")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl Iterator for GemPages<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stale {
            return None;
        }
        if !self.backing.foreign.is_empty() {
            let page = self.backing.foreign.get(self.index).copied();
            self.index += usize::from(page.is_some());
            return page;
        }
        let frame_count = self.backing.frames.len();
        if self.index < frame_count {
            let phys = self.backing.frames[self.index].start_address().raw();
            self.index += 1;
            return Some(phys);
        }
        let wc_count = self.wc.map_or(0, |wc| wc.frames().len());
        if let Some(wc) = self.wc {
            let wc_idx = self.index - frame_count;
            if wc_idx < wc_count {
                self.index += 1;
                return Some(wc.frames()[wc_idx].start_address().raw());
            }
        }
        let pin_idx = self.index - frame_count - wc_count;
        if pin_idx < self.pins.len() {
            self.index += 1;
            return Some(self.pins[pin_idx].phys().raw());
        }
        let vram_idx = pin_idx - self.pins.len();
        if let Some(vram) = &self.backing.vram {
            let vram_pages = (vram.size() / PAGE) as usize;
            if vram_idx < vram_pages {
                self.index += 1;
                return Some(vram.device_address() + vram_idx as u64 * PAGE);
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct GemObject {
    backing: IrqSafeSpinLock<GemBacking>,
    storage: AtomicU8,
    vram_page_sz: AtomicU64,
    preferred_vram: AtomicBool,
    migrating: Mutex<()>,
    private_staging: bool,
    /// Opted-in pending allocation quota follows the actual BO/job graph,
    /// independently of the ioctl waiter and without a back-reference cycle.
    pending_quota: IrqSafeSpinLock<Option<PendingCharge>>,
    /// USERPTR: retained caller pages instead of owned frames. Such objects
    /// have no handle, mmap offset, CPU copy path or PRIME export.
    pins: Vec<narf_memory::address_space::UserPagePin>,
    /// 1 private/uninitialized, 2 clear prepared/completed, 3 CPU clear in
    /// progress, 4 published. Zero is ordinary storage. No public handle,
    /// mmap or user VM reaches states 1..3.
    ccs: AtomicU8,
    /// Zeroed write-combining system pages, in place of `frames`.
    wc: Option<narf_memory::pageattr::WcPages>,
    /// XE_BO_FLAG_SCANOUT: created for scanout, or made a framebuffer.
    scanout: AtomicBool,
    /// DRM_XE_GEM_CPU_CACHING_WC on a discrete part, whose system pages stay
    /// write-back because PCIe snoops (xe_ttm_tt_create); the object still
    /// counts as WC for XE_COH_NONE binds, as `bo->cpu_caching` does.
    wc_caching: AtomicBool,
    /// DRM_XE_GEM_CREATE_FLAG_NO_COMPRESSION: no compressed PAT binds.
    no_compression: AtomicBool,
    /// Integrated Xe2/Xe3: the flat-CCS metadata behind these pages has been
    /// zeroed (`bo->ccs_cleared`). Held across the clear so concurrent
    /// first compressed binds run it once.
    system_ccs: Mutex<bool>,
    /// Published VM bindings naming this object (Linux xe_bo_is_vm_bound).
    vm_binds: core::sync::atomic::AtomicU32,
    /// `bo->pxp_key_instance`: the PXP key iteration a HWDRM object was
    /// created against (xe_pxp_key_assign); 0 for an unprotected object.
    pxp_key: core::sync::atomic::AtomicU32,
    size: u64,
    offset: u64,
    vm_owner: Option<u64>,
    read_only: bool,
    pat_index: Option<u8>,
    /// Serializes kernel CPU copies; never forms references to mapped data.
    cpu: IrqSafeSpinLock<()>,
    /// The reservation and name every dma-buf of this object shares, and
    /// that a foreign import shares too (Linux `dma_buf->resv`).
    pub(crate) dma_buf: Arc<DmaBufObject>,
    /// Exported dma-buf attachments and their pins.
    prime: IrqSafeSpinLock<PrimeState>,
    /// DRM_XE_GEM_CREATE placed this object in VRAM only: no system
    /// placement, so `xe_bo_can_migrate(bo, XE_PL_TT)` is false.
    vram_only: AtomicBool,
    /// Another device's dma-buf imported into this open: Linux
    /// `xe_dma_buf_create_obj`'s `ttm_bo_type_sg` BO and its attachment.
    import: Option<crate::intel_gpu_prime::Import>,
}

/// The dma-buf side of an exporter object (Linux `dmabuf->attachments` and
/// `xe_bo_pin_external`'s pin count).
#[derive(Debug, Default)]
struct PrimeState {
    /// Attachments whose importer reaches this object peer-to-peer.
    peer: u32,
    /// Attachments that need system memory.
    host: u32,
    /// External (dma-buf) pins.
    pins: u32,
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
    fn storage_of(vram: &crate::intel_gpu_vram::VramAllocation) -> u8 {
        if vram.cpu_address().is_none() {
            STORAGE_VRAM_GPU_ONLY
        } else {
            STORAGE_VRAM_VISIBLE
        }
    }

    fn allocate(size: u64, offset: u64) -> Result<Self, FsError> {
        charge(size)?;
        let mut frames = Vec::new();
        if let Err(err) = frames
            .try_reserve_exact((size / PAGE) as usize)
            .map_err(|_| FsError::OutOfMemory)
        {
            LIVE_BYTES.fetch_sub(size, Ordering::AcqRel);
            return Err(err);
        }
        for _ in 0..size / PAGE {
            let frame = match alloc_frame() {
                Ok(frame) => frame,
                Err(_) => {
                    for frame in frames.drain(..) {
                        free_frame(frame);
                    }
                    LIVE_BYTES.fetch_sub(size, Ordering::AcqRel);
                    return Err(FsError::OutOfMemory);
                }
            };
            // SAFETY: newly allocated private frame, not published until zeroed.
            unsafe {
                core::ptr::write_bytes(
                    frame.start_address().kernel_mut_ptr::<u8>(),
                    0,
                    PAGE as usize,
                )
            };
            frames.push(frame);
        }
        Ok(Self {
            backing: IrqSafeSpinLock::new(GemBacking {
                frames,
                vram: None,
                ccs_backup: None,
                foreign: Vec::new(),
                foreign_generation: 0,
                suspend_backup: None,
                charged: true,
            }),
            storage: AtomicU8::new(STORAGE_SYSTEM),
            vram_page_sz: AtomicU64::new(PAGE),
            preferred_vram: AtomicBool::new(false),
            migrating: Mutex::new(()),
            private_staging: false,
            pending_quota: IrqSafeSpinLock::new(None),
            pins: Vec::new(),
            ccs: AtomicU8::new(0),
            wc: None,
            scanout: AtomicBool::new(false),
            wc_caching: AtomicBool::new(false),
            no_compression: AtomicBool::new(false),
            system_ccs: Mutex::new(false),
            vm_binds: core::sync::atomic::AtomicU32::new(0),
            pxp_key: core::sync::atomic::AtomicU32::new(0),
            size,
            offset,
            vm_owner: None,
            read_only: false,
            pat_index: None,
            cpu: IrqSafeSpinLock::new(()),
            dma_buf: Arc::new(DmaBufObject::new()),
            prime: IrqSafeSpinLock::new(PrimeState::default()),
            vram_only: AtomicBool::new(false),
            import: None,
        })
    }

    pub(crate) fn private_system(size: u64) -> Result<Arc<Self>, FsError> {
        if size == 0 || size & 4095 != 0 || size > MAX_FILE_BYTES {
            return Err(FsError::InvalidData);
        }
        let mut object = Self::allocate(size, 0)?;
        object.private_staging = true;
        Ok(Arc::new(object))
    }
    pub(crate) fn private_staging(&self) -> bool {
        self.private_staging
    }
    pub(crate) fn is_gpu_only(&self) -> bool {
        self.storage.load(Ordering::Acquire) == STORAGE_VRAM_GPU_ONLY
    }
    pub(crate) fn gpu_only_access(
        &self,
        m: &impl crate::intel_gpu_aux::MmioWindow,
    ) -> Result<(), crate::intel_gpu_gt::lnl::Error> {
        if !self.is_gpu_only() {
            return Err(crate::intel_gpu_gt::lnl::Error::Unsupported);
        }
        self.backing
            .lock()
            .vram
            .as_ref()
            .ok_or(crate::intel_gpu_gt::lnl::Error::State)?
            .smallbar_access(m)
    }
    pub(crate) fn initialization_complete(
        &self,
        fence: &crate::intel_gpu_fence::CompletionFence,
    ) -> bool {
        self.is_vram() && fence.result() == Some(Ok(())) && self.ccs.load(Ordering::Acquire) == 2
    }
    pub(crate) fn begin_gpu_vram_clear(&self) -> Result<(), FsError> {
        if !self.is_gpu_only() {
            return Err(FsError::Unsupported);
        }
        self.ccs
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| FsError::InvalidData)
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

    pub(crate) fn is_wc(&self) -> bool {
        self.wc.is_some()
    }

    /// Created with DRM_XE_GEM_CPU_CACHING_WC on a discrete part.
    pub(crate) fn mark_wc_caching(&self) {
        self.wc_caching.store(true, Ordering::Release);
    }

    /// `bo->cpu_caching == DRM_XE_GEM_CPU_CACHING_WB`: CPU writes may sit in
    /// caches the GPU only sees through a snooping PAT. WC system pages, VRAM
    /// and discrete WC objects are not.
    pub(crate) fn cpu_caching_wb(&self) -> bool {
        !(self.is_wc() || self.is_vram() || self.wc_caching.load(Ordering::Acquire))
    }

    pub(crate) fn mark_no_compression(&self) {
        self.no_compression.store(true, Ordering::Release);
    }

    /// DRM_XE_GEM_CREATE_FLAG_NO_COMPRESSION.
    pub(crate) fn no_compression(&self) -> bool {
        self.no_compression.load(Ordering::Acquire)
    }

    /// Whether this object's flat-CCS metadata has been zeroed; see
    /// [`crate::intel_gpu_exec::prepare_system_ccs_clear`].
    pub(crate) fn system_ccs(&self) -> &Mutex<bool> {
        &self.system_ccs
    }

    /// DRM_XE_GEM_CREATE_FLAG_SCANOUT, or made a framebuffer since.
    pub(crate) fn scanout(&self) -> bool {
        self.scanout.load(Ordering::Acquire)
    }

    pub(crate) fn mark_scanout(&self) {
        self.scanout.store(true, Ordering::Release);
    }

    /// xe_pxp_key_assign: mark a new HWDRM object with the current key.
    pub(crate) fn set_pxp_key(&self, instance: u32) {
        self.pxp_key.store(instance, Ordering::Release);
    }

    /// `bo->pxp_key_instance` (xe_bo_is_protected when nonzero).
    pub(crate) fn pxp_key(&self) -> u32 {
        self.pxp_key.load(Ordering::Acquire)
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

    /// An i915 USERPTR object over `pins`, charged like owned storage.
    pub(crate) fn from_userptr_pins(
        pins: Vec<narf_memory::address_space::UserPagePin>,
        read_only: bool,
    ) -> Result<Arc<Self>, FsError> {
        let size = (pins.len() as u64)
            .checked_mul(PAGE)
            .filter(|size| *size != 0)
            .ok_or(FsError::InvalidData)?;
        let mut object = Self::allocate(0, 0)?;
        charge(size)?;
        object.size = size;
        object.pins = pins;
        object.read_only = read_only;
        object.vm_owner = None;
        Ok(Arc::new(object))
    }

    pub(crate) fn is_read_only(&self) -> bool {
        self.read_only
    }

    #[allow(dead_code)]
    pub(crate) fn set_pat_index(&mut self, pat: u8) {
        self.pat_index = Some(pat);
    }

    #[allow(dead_code)]
    pub(crate) fn pat_index(&self) -> Option<u8> {
        self.pat_index
    }

    pub(crate) fn is_userptr(&self) -> bool {
        !self.pins.is_empty()
    }

    /// Device-memory pages carry the PPGTT DM bit and a VRAM address.
    pub(crate) fn is_vram(&self) -> bool {
        self.storage.load(Ordering::Acquire) != STORAGE_SYSTEM
    }

    pub(crate) fn in_vram_pool(&self, pool: &crate::intel_gpu_vram::Vram) -> bool {
        self.backing
            .lock()
            .vram
            .as_ref()
            .is_some_and(|vram| vram.pool_is_ref(pool))
    }
    pub(crate) fn vram_pool(&self) -> Option<Arc<crate::intel_gpu_vram::Vram>> {
        self.backing
            .lock()
            .vram
            .as_ref()
            .map(|vram| vram.pool().clone())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn has_ccs_backup(&self) -> bool {
        self.backing.lock().ccs_backup.is_some()
    }
    pub(crate) fn preferred_vram(&self) -> bool {
        self.preferred_vram.load(Ordering::Acquire)
    }
    pub(crate) fn set_preferred_vram(&self) {
        self.preferred_vram.store(true, Ordering::Release);
    }
    pub(crate) fn is_evictable(&self, allow_scanout: bool) -> bool {
        if !self.is_vram()
            || self.vm_owner.is_some()
            || self.private_staging
            || self.is_userptr()
            || self.is_wc()
        {
            return false;
        }
        if !allow_scanout && self.scanout() {
            return false;
        }
        if self.externally_pinned() || self.restore_pending() || !self.idle(true) {
            return false;
        }
        !cpu_mapping::has_active_aliases(self)
    }

    /// Record a VRAM-only DRM_XE_GEM_CREATE placement (no system bit).
    pub(crate) fn mark_vram_only(&self) {
        self.vram_only.store(true, Ordering::Release);
    }
    /// Linux `xe_bo_can_migrate(bo, XE_PL_TT)`: the creation placements
    /// include system memory. It is a property of the placement list, not of
    /// the current placement: an evicted VRAM-only object still answers no.
    /// An imported (`ttm_bo_type_sg`) object never migrates.
    pub(crate) fn can_migrate_to_system(&self) -> bool {
        !self.vram_only.load(Ordering::Acquire) && self.import.is_none()
    }
    /// A foreign device's dma-buf imported into this open.
    pub(crate) fn is_imported(&self) -> bool {
        self.import.is_some()
    }
    pub(crate) fn import(&self) -> Option<&crate::intel_gpu_prime::Import> {
        self.import.as_ref()
    }
    /// The exporter object and card a re-export of this import names: Linux
    /// `drm_gem_prime_handle_to_dmabuf` returns `import_attach->dmabuf`.
    pub(crate) fn prime_origin(&self) -> Option<(u32, Arc<GemObject>)> {
        self.import
            .as_ref()
            .map(|import| (import.card(), import.exporter_object().clone()))
    }
    /// The mapped attachment's pages are installed (see `GemBacking::foreign`)
    /// and no move notification has made them stale since.
    pub(crate) fn import_mapped(&self) -> bool {
        let backing = self.backing.lock();
        !backing.foreign.is_empty() && self.import_current(backing.foreign_generation)
    }
    fn import_current(&self, generation: u64) -> bool {
        self.import
            .as_ref()
            .is_some_and(|import| import.attachment().current(generation))
    }
    /// Install an import's pages, mapped at the attachment's move count
    /// `generation`; they must cover the object. A move notified since that
    /// mapping refuses with `WouldBlock`: the caller maps again. Checked
    /// under the backing lock that [`Self::pages`] reads under, so a
    /// notification either precedes the check or makes the installed pages
    /// stale.
    pub(crate) fn install_import_pages(
        &self,
        pages: Vec<u64>,
        generation: u64,
    ) -> Result<(), FsError> {
        if self.import.is_none() || pages.len() as u64 * PAGE != self.size {
            return Err(FsError::InvalidData);
        }
        let stale = {
            let mut backing = self.backing.lock();
            if !self.import_current(generation) {
                return Err(FsError::WouldBlock);
            }
            backing.foreign_generation = generation;
            core::mem::replace(&mut backing.foreign, pages)
        };
        drop(stale);
        Ok(())
    }
    /// `xe_dma_buf_attach` / `xe_dma_buf_detach` on this exporter object.
    pub(crate) fn prime_attach(&self, peer2peer: bool) {
        let mut prime = self.prime.lock();
        if peer2peer {
            prime.peer += 1;
        } else {
            prime.host += 1;
        }
    }
    pub(crate) fn prime_detach(&self, peer2peer: bool) {
        let mut prime = self.prime.lock();
        let count = if peer2peer {
            &mut prime.peer
        } else {
            &mut prime.host
        };
        *count = count.checked_sub(1).expect("balanced dma-buf attachment");
    }
    /// Pinned by a dma-buf importer (`xe_bo_pin_external`).
    pub(crate) fn externally_pinned(&self) -> bool {
        self.prime.lock().pins != 0
    }
    /// The CPU (and PCI bus) address of a wholly CPU-visible VRAM object
    /// through the LMEM BAR; `None` for system memory or any nonvisible part
    /// (`xe_ttm_vram_mgr_alloc_sgt` refuses `used_visible_size < size`).
    pub(crate) fn lmem_bar_address(&self) -> Option<u64> {
        self.backing.lock().vram.as_ref()?.cpu_address()
    }

    /// `xe_dma_buf_pin`'s placement rules, then `xe_bo_pin_external`.
    /// VRAM stays only while every attachment of the buffer is
    /// peer-to-peer; otherwise an unpinned object migrates to system memory
    /// first (`xe_bo_migrate(bo, XE_PL_TT)`, here the eviction copy job). An
    /// object already pinned in VRAM refuses a system-memory pin (EINVAL,
    /// "Can't migrate pinned bo for dma-buf pin"). NARF has no display pin
    /// count, so a VRAM scanout object counts as pinned. Pins exclude
    /// eviction and migration until [`Self::unpin_external`]. A CPU-mapped
    /// object migrates only with `mapped_moves` ([`Self::evict_locked`]).
    pub(crate) async fn pin_external(
        self: &Arc<Self>,
        backend: &dyn crate::intel_gpu_user::UserBackend,
        epoch: Option<u64>,
        mapped_moves: bool,
    ) -> Result<(), FsError> {
        let _migrating = self.migrating.lock().await;
        let (allow_vram, pinned) = {
            let prime = self.prime.lock();
            (prime.host == 0, prime.pins != 0)
        };
        let pinned = pinned || (self.scanout() && self.is_vram());
        if pinned && self.is_vram() && !allow_vram {
            return Err(FsError::InvalidData);
        }
        if !allow_vram && self.is_vram() {
            // xe_bo_migrate: -EINVAL without a system placement.
            if !self.can_migrate_to_system() {
                return Err(FsError::InvalidData);
            }
            let epoch = epoch.ok_or(FsError::NoDevice)?;
            // TTM waits for the object's fences before the move; the NARF
            // eviction copy requires an idle object.
            self.wait_idle(true, None).await?;
            self.evict_locked(backend, epoch, false, mapped_moves).await?;
        }
        self.prime.lock().pins += 1;
        Ok(())
    }
    /// `xe_bo_unpin_external`.
    pub(crate) fn unpin_external(&self) {
        let mut prime = self.prime.lock();
        prime.pins = prime.pins.checked_sub(1).expect("balanced dma-buf pin");
    }
    /// `xe_dma_buf_map`'s placement step for an unpinned (dynamic)
    /// attachment, under the lock every move of this object takes (Linux
    /// holds the reservation): an importer without peer-to-peer needs system
    /// memory (`xe_bo_migrate(bo, XE_PL_TT)`, which notifies the dynamic
    /// importers first), while a peer takes the object where it is (NARF's
    /// `xe_bo_validate` keeps the current placement). A pinned object is not
    /// moved (`xe_bo_is_pinned` skips the migration). The returned guard
    /// holds the placement while the caller builds its table. A CPU-mapped
    /// object migrates only with `mapped_moves`.
    pub(crate) async fn validate_for_dma_buf(
        self: &Arc<Self>,
        backend: &dyn crate::intel_gpu_user::UserBackend,
        epoch: Option<u64>,
        peer2peer: bool,
        mapped_moves: bool,
    ) -> Result<narf_lib::mutex::MutexGuard<'_, ()>, FsError> {
        let placement = self.migrating.lock().await;
        let pinned = self.externally_pinned() || (self.scanout() && self.is_vram());
        if !peer2peer && self.is_vram() && !pinned {
            if !self.can_migrate_to_system() {
                return Err(FsError::Unsupported);
            }
            let epoch = epoch.ok_or(FsError::NoDevice)?;
            self.wait_idle(true, None).await?;
            self.evict_locked(backend, epoch, false, mapped_moves).await?;
        }
        Ok(placement)
    }
    /// `xe_bo_migrate(bo, XE_PL_TT)` for CPU reads of an export
    /// (`xe_dma_buf_begin_cpu_access`), under the lock every move takes:
    /// `Ok(true)` once a VRAM object moved to system memory (its dynamic
    /// importers notified first and its CPU mappings retired, so they fault
    /// in the new pages), `Ok(false)` when it already is in system memory. A
    /// pinned object is -EBUSY (`xe_bo_is_pinned`; a VRAM scanout object
    /// counts as pinned), one without a system placement -EINVAL
    /// (`xe_bo_can_migrate`), and a move the eviction copy cannot make keeps
    /// its error. A CPU-mapped object moves only with `mapped_moves` (its
    /// mappings then follow it, [`Self::evict_mapped`]), else `Busy`. The
    /// object stays where it was on any error.
    pub(crate) async fn migrate_for_cpu_access(
        self: &Arc<Self>,
        backend: &dyn crate::intel_gpu_user::UserBackend,
        epoch: Option<u64>,
        mapped_moves: bool,
    ) -> Result<bool, FsError> {
        let _placement = self.migrating.lock().await;
        if !self.is_vram() {
            return Ok(false);
        }
        if self.externally_pinned() || self.scanout() {
            return Err(FsError::Busy);
        }
        if !self.can_migrate_to_system() {
            return Err(FsError::InvalidData);
        }
        let epoch = epoch.ok_or(FsError::NoDevice)?;
        // TTM waits for the object's fences before the move; the NARF
        // eviction copy requires an idle object.
        self.wait_idle(true, None).await?;
        self.evict_locked(backend, epoch, false, mapped_moves).await?;
        Ok(true)
    }
    /// A suspend backup awaits [`Self::restore_pinned`]: until then the VRAM
    /// holds nothing of this object's (S3 lost it), so no CPU access,
    /// mapping, scanout, move or GPU use may reach it first.
    pub(crate) fn restore_pending(&self) -> bool {
        self.backing.lock().suspend_backup.is_some()
    }
    /// The bytes of `pool` a suspend backup of this object saved.
    pub(crate) fn suspend_saved_bytes(&self, pool: &crate::intel_gpu_vram::Vram) -> u64 {
        let backing = self.backing.lock();
        match (&backing.suspend_backup, &backing.vram) {
            (Some(_), Some(vram)) if vram.pool_is_ref(pool) => vram.size(),
            _ => 0,
        }
    }
    /// `xe_bo_evict_pinned` at system suspend for a VRAM object a dma-buf
    /// importer pins (`xe->pinned.late.external`): copy its data (and DG2
    /// Flat-CCS) into a new system backup with the eviction copy and keep
    /// the VRAM allocation, so [`Self::restore_pinned`] puts it back in the
    /// same placement. The importers keep their tables. Returns the VRAM
    /// bytes saved: 0 for anything else, and the existing backup's size when
    /// an earlier suspend's backup was never restored (it still holds the
    /// data). Busy work or a live CPU alias refuses: S3 loses the BAR
    /// contents a process would still see.
    pub(crate) async fn backup_pinned(
        self: &Arc<Self>,
        backend: &dyn crate::intel_gpu_user::UserBackend,
        epoch: u64,
    ) -> Result<u64, FsError> {
        let _migrating = self.migrating.lock().await;
        if !self.is_vram() || !self.externally_pinned() {
            return Ok(0);
        }
        let (requires_ccs, bytes) = {
            let backing = self.backing.lock();
            let Some(vram) = &backing.vram else {
                return Ok(0);
            };
            if backing.suspend_backup.is_some() {
                return Ok(vram.size());
            }
            (vram.requires_ccs_clear(), vram.size())
        };
        if !self.idle(true) || cpu_mapping::has_active_aliases(self) {
            return Err(FsError::Busy);
        }
        let data = GemObject::private_system(self.size)?;
        let ccs = if requires_ccs {
            let ccs_bytes = ((self.size / 256).div_ceil(PAGE) * PAGE).max(PAGE);
            Some(GemObject::private_system(ccs_bytes)?)
        } else {
            None
        };
        let request = crate::intel_gpu_exec::copy::CopyRequest::for_migration(
            self.clone(),
            data.clone(),
            ccs.clone(),
            self.size,
        )?;
        let fence = backend.copy_objects(request, epoch).await?;
        if fence.wait().await.is_err() {
            return Err(crate::intel_gpu_user::io_error());
        }
        {
            // As the eviction swap: no writer may have overtaken the copy.
            let _reservation = RESERVATIONS.lock();
            if !self.idle(true) {
                return Err(FsError::Busy);
            }
            self.backing.lock().suspend_backup = Some(SuspendBackup { data, ccs });
        }
        Ok(bytes)
    }
    /// `xe_bo_restore_pinned`: copy a suspend backup back into this
    /// object's unchanged VRAM allocation (data and DG2 Flat-CCS), then drop
    /// it. Returns whether a backup was restored.
    pub(crate) async fn restore_pinned(
        self: &Arc<Self>,
        backend: &dyn crate::intel_gpu_user::UserBackend,
        epoch: u64,
    ) -> Result<bool, FsError> {
        let _migrating = self.migrating.lock().await;
        let backup = { self.backing.lock().suspend_backup.clone() };
        let Some(backup) = backup else {
            return Ok(false);
        };
        let request = crate::intel_gpu_exec::copy::CopyRequest::for_migration(
            backup.data.clone(),
            self.clone(),
            backup.ccs.clone(),
            self.size,
        )?;
        let fence = backend.copy_objects(request, epoch).await?;
        if fence.wait().await.is_err() {
            return Err(crate::intel_gpu_user::io_error());
        }
        let restored = self.backing.lock().suspend_backup.take();
        drop(restored);
        Ok(true)
    }
    /// Drop a suspend backup whose VRAM never lost power (the suspend was
    /// refused after the save): the VRAM still holds the data.
    pub(crate) async fn discard_backup(&self) {
        let _migrating = self.migrating.lock().await;
        let backup = self.backing.lock().suspend_backup.take();
        drop(backup);
    }
    pub(crate) fn vram_page_size(&self) -> u64 {
        self.vram_page_sz.load(Ordering::Acquire)
    }
    pub(crate) fn begin_ccs_clear(&self) -> Result<(), FsError> {
        if !self
            .backing
            .lock()
            .vram
            .as_ref()
            .is_some_and(|v| v.requires_ccs_clear())
        {
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
        if self.is_gpu_only()
            || self
                .backing
                .lock()
                .vram
                .as_ref()
                .is_none_or(|v| v.requires_ccs_clear())
        {
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

    pub fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn vm_owner(&self) -> Option<u64> {
        self.vm_owner
    }

    pub fn pages(&self) -> GemPages<'_> {
        let backing = self.backing.lock();
        let stale = self.import.is_some() && !self.import_current(backing.foreign_generation);
        GemPages {
            backing,
            pins: &self.pins,
            wc: self.wc.as_ref(),
            index: 0,
            stale,
        }
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
        let backing = self.backing.lock();
        crate::intel_gpu_gtt::publish_system_pages(backing.frames.iter())
            && crate::intel_gpu_gtt::publish_system_phys(self.pins.iter().map(|pin| pin.phys()))
    }

    pub fn range(&self, offset: u64, len: usize) -> Result<(), FsError> {
        if self.is_userptr() || matches!(self.ccs.load(Ordering::Acquire), 1..=3) {
            return Err(FsError::InvalidData);
        }
        // A foreign import's pages belong to the exporter (or are a peer
        // BAR): no kernel copy or CPU alias reaches them through the import.
        // Its mmap maps the exporter's object instead (`mapping_object`).
        if self.is_imported() {
            return Err(FsError::Unsupported);
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
        cpu_mapping::backing(self.clone(), offset, len)
    }

    /// CPU physical frames, including BAR addresses for LMEM. GPU `pages()`
    /// deliberately uses device-local addresses instead and cannot supply
    /// the CPU alias census.
    fn cpu_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        if self.is_gpu_only() || self.private_staging {
            return Err(FsError::Unsupported);
        }
        // The BAR holds nothing of a pinned export until its resume restore.
        if self.restore_pending() {
            return Err(FsError::WouldBlock);
        }
        if len == 0 || offset % PAGE != 0 {
            return Err(FsError::InvalidData);
        }
        self.range(offset, len)?;
        let pages =
            (offset / PAGE) as usize..(offset / PAGE) as usize + len.div_ceil(PAGE as usize);
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(pages.len())
            .map_err(|_| FsError::OutOfMemory)?;
        let backing = self.backing.lock();
        if let Some(vram) = &backing.vram {
            // LMEM BAR frames, write-combining as Linux's VRAM mmap.
            let base = vram.cpu_address().ok_or(FsError::Unsupported)?;
            frames.extend(pages.map(|page| base + page as u64 * PAGE));
        } else {
            drop(backing);
            frames.extend(self.pages().skip(pages.start).take(pages.len()));
        }
        Ok(frames)
    }

    pub fn read(&self, offset: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        if self.is_gpu_only() {
            return Err(FsError::Unsupported);
        }
        self.range(offset, bytes.len())?;
        if self.restore_pending() {
            return Err(FsError::WouldBlock);
        }
        let snapshot = self.dma_buf.resv.snapshot();
        let _reservation = RESERVATIONS.lock();
        if !snapshot.is_current() || snapshot.has_fences(dma_resv_usage_rw(false)) {
            return Err(FsError::WouldBlock);
        }
        let _guard = self.cpu.lock();
        let pool = self.vram_pool();
        // The LMEM BAR does not decode while the GT owner has the function
        // runtime-suspended; callers that may resume it hold a wakeref first.
        let _bar = match &pool {
            Some(pool) => Some(pool.cpu_access().ok_or(FsError::Busy)?),
            None => None,
        };
        let backing = self.backing.lock();
        if backing
            .vram
            .as_ref()
            .is_some_and(|v| v.cpu_address().is_none())
        {
            return Err(FsError::Unsupported);
        }
        let vram_virt = backing.vram.as_ref().and_then(|v| v.kernel_virt());
        if backing.vram.is_some() && vram_virt.is_none() {
            return Err(FsError::Unsupported);
        }
        let frames = self
            .wc
            .as_ref()
            .map_or(backing.frames.as_slice(), |wc| wc.frames());
        for (i, byte) in bytes.iter_mut().enumerate() {
            let at = offset + i as u64;
            if let Some(base) = vram_virt {
                // SAFETY: range checked; the allocation's WC alias is live.
                *byte = unsafe { core::ptr::read_volatile((base + at) as *const u8) };
                continue;
            }
            if self.is_userptr() {
                let pin = &self.pins[(at / PAGE) as usize];
                let base = pin.phys().kernel_ptr::<u8>();
                // SAFETY: userptr pages remain pinned and mapped into kernel direct map; volatile access tolerates concurrent mappings.
                *byte = unsafe { core::ptr::read_volatile(base.add((at % PAGE) as usize)) };
                continue;
            }
            let base = frames[(at / PAGE) as usize]
                .start_address()
                .kernel_ptr::<u8>();
            // SAFETY: range checked; raw volatile access also tolerates concurrent
            // device/user mappings without creating aliased Rust references.
            *byte = unsafe { core::ptr::read_volatile(base.add((at % PAGE) as usize)) };
        }
        Ok(())
    }

    /// Privileged, passive crash observation of a retained system-memory
    /// mapping. Unlike CPU access admission this must not wait on the job's
    /// own unfinished reservation fence or clean/invalidate caches. The caller
    /// selects only coherent/WC mappings and renews current D0/wake/authority
    /// before each page. VRAM needs independent BAR-access proof and is refused.
    pub(crate) fn diagnostic_read(
        &self,
        offset: u64,
        bytes: &mut [u8],
        access: &mut dyn FnMut() -> bool,
    ) -> bool {
        if self.is_vram()
            || self.is_imported()
            || offset % PAGE != 0
            || bytes.is_empty()
            || bytes.len() > 16384
            || bytes.len() % PAGE as usize != 0
            || offset
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > self.size)
        {
            return false;
        }
        for (index, output) in bytes.chunks_exact_mut(PAGE as usize).enumerate() {
            if !access() {
                bytes.fill(0);
                return false;
            }
            let page = (offset / PAGE) as usize + index;
            if self.is_userptr() {
                let Some(pin) = self.pins.get(page) else {
                    bytes.fill(0);
                    return false;
                };
                pin.copy_into(0, output);
                continue;
            }
            let Some(phys) = self.pages().nth(page) else {
                bytes.fill(0);
                return false;
            };
            let base = narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>();
            core::sync::atomic::fence(Ordering::Acquire);
            for (i, byte) in output.iter_mut().enumerate() {
                // SAFETY: this object owns/pins the selected host frame for
                // the complete snapshot. Raw volatile reads form no aliased
                // Rust references to concurrently user/device-mapped data.
                *byte = unsafe { core::ptr::read_volatile(base.add(i)) };
            }
        }
        if !access() {
            bytes.fill(0);
            return false;
        }
        core::sync::atomic::fence(Ordering::Acquire);
        true
    }

    pub fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), FsError> {
        if self.is_gpu_only() {
            return Err(FsError::Unsupported);
        }
        if self.is_read_only() {
            return Err(FsError::PermissionDenied);
        }
        if self.restore_pending() {
            return Err(FsError::WouldBlock);
        }
        self.range(offset, bytes.len())?;
        let snapshot = self.dma_buf.resv.snapshot();
        let _reservation = RESERVATIONS.lock();
        if !snapshot.is_current() || snapshot.has_fences(dma_resv_usage_rw(true)) {
            return Err(FsError::WouldBlock);
        }
        let _guard = self.cpu.lock();
        let pool = self.vram_pool();
        let _bar = match &pool {
            Some(pool) => Some(pool.cpu_access().ok_or(FsError::Busy)?),
            None => None,
        };
        let backing = self.backing.lock();
        if backing
            .vram
            .as_ref()
            .is_some_and(|v| v.cpu_address().is_none())
        {
            return Err(FsError::Unsupported);
        }
        let vram_virt = backing.vram.as_ref().and_then(|v| v.kernel_virt());
        if backing.vram.is_some() && vram_virt.is_none() {
            return Err(FsError::Unsupported);
        }
        let frames = self
            .wc
            .as_ref()
            .map_or(backing.frames.as_slice(), |wc| wc.frames());
        for (i, byte) in bytes.iter().enumerate() {
            let at = offset + i as u64;
            if let Some(base) = vram_virt {
                // SAFETY: range checked; the allocation's WC alias is live.
                unsafe { core::ptr::write_volatile((base + at) as *mut u8, *byte) };
                continue;
            }
            if self.is_userptr() {
                let pin = &self.pins[(at / PAGE) as usize];
                let base = pin.phys().kernel_mut_ptr::<u8>();
                // SAFETY: userptr pages remain pinned and mapped into kernel direct map; volatile write tolerates concurrent mappings.
                unsafe { core::ptr::write_volatile(base.add((at % PAGE) as usize), *byte) };
                continue;
            }
            let base = frames[(at / PAGE) as usize]
                .start_address()
                .kernel_mut_ptr::<u8>();
            // SAFETY: same owned, range-checked pages as read().
            unsafe { core::ptr::write_volatile(base.add((at % PAGE) as usize), *byte) };
        }
        if self.is_wc() || backing.vram.is_some() {
            // Write-combining stores are weakly ordered: drain them before a
            // later submission or fence publishes the bytes.
            wc_fence();
        }
        Ok(())
    }

    fn swap_to_system(
        self: &Arc<Self>,
        staging: &Arc<Self>,
        ccs_backup: Option<Arc<GemObject>>,
        allow_scanout: bool,
    ) -> Result<u64, FsError> {
        let released = {
            let _reservation = RESERVATIONS.lock();
            let _cpu = self.cpu.lock();
            let mut backing = self.backing.lock();
            if backing.vram.is_none() {
                return Ok(0);
            }
            if !self.idle(true)
                || (!allow_scanout && self.scanout())
                || cpu_mapping::has_active_aliases(self)
            {
                return Err(FsError::Busy);
            }
            self.exchange_for_system(&mut backing, staging, ccs_backup)
        };
        drop(released);
        Ok(self.size)
    }

    /// The placement swap of an eviction, under the caller's reservation,
    /// CPU and backing locks: `staging`'s system frames (and its charge)
    /// become this object's, and the VRAM allocation, frames and Flat-CCS
    /// backup it gave up are returned, to be released after the locks. It
    /// neither allocates nor frees.
    fn exchange_for_system(
        &self,
        backing: &mut GemBacking,
        staging: &GemObject,
        ccs_backup: Option<Arc<GemObject>>,
    ) -> Released {
        let mut staging_backing = staging.backing.lock();
        let new_frames = core::mem::take(&mut staging_backing.frames);
        if !backing.charged && staging_backing.charged {
            backing.charged = true;
            staging_backing.charged = false;
        }
        drop(staging_backing);
        let vram = backing.vram.take();
        let frames = core::mem::replace(&mut backing.frames, new_frames);
        let ccs = backing.ccs_backup.take();
        backing.ccs_backup = ccs_backup;
        self.storage.store(STORAGE_SYSTEM, Ordering::Release);
        self.vram_page_sz.store(PAGE, Ordering::Release);
        Released { ccs, vram, frames }
    }

    /// `ttm_bo_handle_move_mem` of a VRAM object a process has mmapped
    /// (`xe_bo_migrate(bo, XE_PL_TT)` on a PRIME path): Linux takes the CPU
    /// translations away (`ttm_bo_unmap_virtual`), copies on the GPU and
    /// faults the new pages in (`xe_bo_cpu_fault`). NARF's revocation
    /// transaction cannot await a GPU copy, so the move runs inside it with
    /// every CPU alias frozen: the bytes are copied through the LMEM BAR's
    /// kernel mapping into new system frames, the placement is swapped and
    /// every alias is rebound to the new frames
    /// ([`cpu_mapping::relocate`]). Dynamic importers are notified first, as
    /// for any move. Refused (`Busy`, nothing moved): a DG2 object whose
    /// Flat-CCS metadata a CPU copy cannot carry, a closed BAR (runtime
    /// suspend), work on the object, a pin or scanout, or any refusal of the
    /// relocation. `Ok(None)`: the CPU mapping went away meanwhile; the
    /// caller moves the object as an unmapped one.
    fn evict_mapped(self: &Arc<Self>, allow_scanout: bool) -> Result<Option<u64>, FsError> {
        let pool = {
            let backing = self.backing.lock();
            let Some(vram) = &backing.vram else {
                return Ok(Some(0));
            };
            if vram.requires_ccs_clear() || vram.kernel_virt().is_none() {
                return Err(FsError::Busy);
            }
            vram.pool().clone()
        };
        let _bar = pool.cpu_access().ok_or(FsError::Busy)?;
        // Any reservation change after this sample refuses the commit: no
        // GPU job may write the VRAM while the CPU copies it.
        let generation = self.dma_buf.resv.generation();
        if !self.idle(true) || self.externally_pinned() || (!allow_scanout && self.scanout()) {
            return Err(FsError::Busy);
        }
        let staging = GemObject::private_system(self.size)?;
        let new: Vec<u64> = staging.pages().collect();
        // xe_bo_move_notify: dynamic importers drop their mappings first.
        self.dma_buf.invalidate_mappings();
        let mut released = None;
        let moved = cpu_mapping::relocate(self, &new, &mut || {
            let _reservation = RESERVATIONS.lock();
            if self.dma_buf.resv.generation() != generation
                || self.externally_pinned()
                || (!allow_scanout && self.scanout())
            {
                return Err(FsError::Busy);
            }
            let _cpu = self.cpu.lock();
            let mut backing = self.backing.lock();
            let source = backing
                .vram
                .as_ref()
                .and_then(|vram| vram.kernel_virt())
                .ok_or(FsError::Busy)?;
            {
                let staging_backing = staging.backing.lock();
                for (index, frame) in staging_backing.frames.iter().enumerate() {
                    let from = (source + index as u64 * PAGE) as *const u64;
                    let to = frame.start_address().kernel_mut_ptr::<u64>();
                    for word in 0..(PAGE / 8) as usize {
                        // SAFETY: the visible allocation's WC alias and the
                        // staging frame are both live, page-sized and owned
                        // here; every CPU alias is frozen and the
                        // reservation is unchanged, so nothing else writes
                        // either while they are copied.
                        unsafe {
                            core::ptr::write_volatile(
                                to.add(word),
                                core::ptr::read_volatile(from.add(word)),
                            )
                        };
                    }
                }
            }
            released = Some(self.exchange_for_system(&mut backing, &staging, None));
            Ok(())
        })?;
        // The VRAM is released only once no CPU alias names it.
        drop(released);
        Ok(moved.then_some(self.size))
    }

    /// Evict an idle VRAM object to newly allocated system frames using
    /// `backend.copy_objects`. On Alchemist (`DG2`), saves Flat-CCS metadata
    /// alongside the data so a subsequent migration back to VRAM restores it.
    pub(crate) async fn evict_to_system(
        self: &Arc<Self>,
        backend: &dyn crate::intel_gpu_user::UserBackend,
        epoch: u64,
        allow_scanout: bool,
    ) -> Result<u64, FsError> {
        let _migrating = self.migrating.lock().await;
        self.evict_locked(backend, epoch, allow_scanout, false).await
    }

    /// [`Self::evict_to_system`] under the caller's `migrating` guard. A
    /// dma-buf pin holds the placement (`xe_bo_migrate` -EBUSY). A live CPU
    /// mapping refuses the move (`Busy`) unless `mapped_moves`, which moves
    /// it with its mappings ([`Self::evict_mapped`]).
    async fn evict_locked(
        self: &Arc<Self>,
        backend: &dyn crate::intel_gpu_user::UserBackend,
        epoch: u64,
        allow_scanout: bool,
        mapped_moves: bool,
    ) -> Result<u64, FsError> {
        if !self.is_vram() {
            return Ok(0);
        }
        if self.vm_owner.is_some() || self.private_staging || self.is_userptr() || self.is_wc() {
            return Err(FsError::Unsupported);
        }
        // A suspend backup not yet restored holds the data, not the VRAM.
        if (!allow_scanout && self.scanout())
            || self.externally_pinned()
            || self.restore_pending()
            || !self.idle(true)
        {
            return Err(FsError::Busy);
        }
        match cpu_mapping::retire_object(self) {
            Err(FsError::Busy) if mapped_moves => {
                if let Some(bytes) = self.evict_mapped(allow_scanout)? {
                    return Ok(bytes);
                }
                cpu_mapping::retire_object(self)?;
            }
            result => result?,
        }
        // xe_bo_move_notify: dynamic importers drop their mappings before
        // the move (dma_buf_invalidate_mappings). Their submitted work is in
        // the shared reservation, which the swap finds idle or refuses.
        self.dma_buf.invalidate_mappings();
        let requires_ccs = {
            let backing = self.backing.lock();
            let Some(vram) = &backing.vram else {
                return Ok(0);
            };
            vram.requires_ccs_clear()
        };
        let staging = GemObject::private_system(self.size)?;
        let ccs_backup = if requires_ccs {
            let ccs_bytes = ((self.size / 256).div_ceil(PAGE) * PAGE).max(PAGE);
            Some(GemObject::private_system(ccs_bytes)?)
        } else {
            None
        };
        let request = crate::intel_gpu_exec::copy::CopyRequest::for_migration(
            self.clone(),
            staging.clone(),
            ccs_backup.clone(),
            self.size,
        )?;
        let fence = backend.copy_objects(request, epoch).await?;
        if fence.wait().await.is_err() {
            return Err(crate::intel_gpu_user::io_error());
        }
        self.swap_to_system(&staging, ccs_backup, allow_scanout)
    }

    fn swap_to_vram(
        self: &Arc<Self>,
        target: &Arc<Self>,
        pool: &Arc<crate::intel_gpu_vram::Vram>,
    ) -> Result<(), FsError> {
        let (old_frames, old_ccs, uncharge) = {
            let _reservation = RESERVATIONS.lock();
            let _cpu = self.cpu.lock();
            let mut backing = self.backing.lock();
            if backing.vram.is_some() {
                return Ok(());
            }
            if !self.idle(true) || cpu_mapping::has_active_aliases(self) {
                return Err(FsError::Busy);
            }
            let vram = target
                .backing
                .lock()
                .vram
                .take()
                .ok_or(FsError::InvalidData)?;
            let storage = Self::storage_of(&vram);
            backing.vram = Some(vram);
            self.storage.store(storage, Ordering::Release);
            self.vram_page_sz.store(pool.page_size(), Ordering::Release);
            self.ccs.store(4, Ordering::Release);
            let old_frames = core::mem::take(&mut backing.frames);
            let old_ccs = backing.ccs_backup.take();
            let uncharge = core::mem::replace(&mut backing.charged, false);
            (old_frames, old_ccs, uncharge)
        };
        drop(old_ccs);
        for frame in old_frames {
            free_frame(frame);
        }
        if uncharge {
            LIVE_BYTES.fetch_sub(self.size, Ordering::AcqRel);
        }
        pool.track(self);
        Ok(())
    }

    /// Migrate a system-backed object (including an evicted VRAM object with
    /// retained Flat-CCS metadata) back into `pool`.
    pub(crate) async fn migrate_to_vram(
        self: &Arc<Self>,
        backend: &dyn crate::intel_gpu_user::UserBackend,
        pool: &Arc<crate::intel_gpu_vram::Vram>,
        visible: bool,
        epoch: u64,
    ) -> Result<(), FsError> {
        let _migrating = self.migrating.lock().await;
        if self.is_vram() {
            return if self.in_vram_pool(pool) {
                Ok(())
            } else {
                Err(FsError::InvalidData)
            };
        }
        if self.vm_owner.is_some()
            || self.private_staging
            || self.is_userptr()
            || self.is_wc()
            || self.is_imported()
        {
            return Err(FsError::Unsupported);
        }
        if self.size == 0 || self.size % pool.page_size() != 0 {
            return Err(FsError::InvalidData);
        }
        if self.externally_pinned() || !self.idle(true) {
            return Err(FsError::Busy);
        }
        cpu_mapping::retire_object(self)?;
        // xe_bo_move_notify, as for eviction.
        self.dma_buf.invalidate_mappings();
        let ccs_backup = self.backing.lock().ccs_backup.clone();
        let allocation = pool.allocate_class(self.size, visible)?;
        let target_storage = Self::storage_of(&allocation);
        let mut target_obj = Self::allocate(0, 0)?;
        target_obj.private_staging = true;
        target_obj.size = self.size;
        {
            let mut tb = target_obj.backing.lock();
            tb.charged = false;
            tb.vram = Some(allocation);
        }
        target_obj.storage.store(target_storage, Ordering::Release);
        target_obj
            .vram_page_sz
            .store(pool.page_size(), Ordering::Release);
        target_obj.ccs.store(4, Ordering::Release);
        let target = Arc::new(target_obj);
        let request = crate::intel_gpu_exec::copy::CopyRequest::for_migration(
            self.clone(),
            target.clone(),
            ccs_backup,
            self.size,
        )?;
        let fence = backend.copy_objects(request, epoch).await?;
        if fence.wait().await.is_err() {
            return Err(crate::intel_gpu_user::io_error());
        }
        self.swap_to_vram(&target, pool)
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

#[path = "intel_gpu_gem_async.rs"]
mod object_async;
pub(crate) use object_async::reserve_gpu_mixed;

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

/// What a placement swap gave up, released once no lock is held: the
/// Flat-CCS backup, then the VRAM allocation, then the frames.
struct Released {
    ccs: Option<Arc<GemObject>>,
    vram: Option<crate::intel_gpu_vram::VramAllocation>,
    frames: Vec<PhysFrame>,
}

impl Drop for Released {
    fn drop(&mut self) {
        drop(self.ccs.take());
        drop(self.vram.take());
        for frame in self.frames.drain(..) {
            free_frame(frame);
        }
    }
}

impl Drop for GemObject {
    fn drop(&mut self) {
        let (frames, vram, ccs_backup, charged) = {
            let mut backing = self.backing.lock();
            (
                core::mem::take(&mut backing.frames),
                backing.vram.take(),
                backing.ccs_backup.take(),
                backing.charged,
            )
        };
        drop(ccs_backup);
        drop(vram);
        for frame in frames {
            free_frame(frame);
        }
        if charged {
            LIVE_BYTES.fetch_sub(self.size, Ordering::AcqRel);
        }
    }
}

#[derive(Debug, Default)]
struct PendingTotals {
    count: usize,
    bytes: u64,
}
#[derive(Debug)]
struct PendingBudget {
    totals: IrqSafeSpinLock<PendingTotals>,
}
impl Default for PendingBudget {
    fn default() -> Self {
        Self {
            totals: IrqSafeSpinLock::new(PendingTotals::default()),
        }
    }
}
#[derive(Debug)]
struct PendingCharge {
    budget: Arc<PendingBudget>,
    size: u64,
    active: bool,
}
impl Drop for PendingCharge {
    fn drop(&mut self) {
        if self.active {
            let mut totals = self.budget.totals.lock();
            totals.count = totals.count.checked_sub(1).expect("private GEM count");
            totals.bytes = totals
                .bytes
                .checked_sub(self.size)
                .expect("private GEM bytes");
        }
    }
}

#[derive(Debug)]
struct Handles {
    next: u32,
    bytes: u64,
    objects: BTreeMap<u32, Arc<GemObject>>,
    reserved: BTreeMap<u32, u64>,
}

#[derive(Debug)]
pub struct GemState {
    handles: IrqSafeSpinLock<Handles>,
    pending_budget: IrqSafeSpinLock<Option<Arc<PendingBudget>>>,
}

impl Default for GemState {
    fn default() -> Self {
        Self::new()
    }
}

impl GemState {
    pub const fn new() -> Self {
        Self {
            pending_budget: IrqSafeSpinLock::new(None),
            handles: IrqSafeSpinLock::new(Handles {
                next: HANDLE_BASE,
                bytes: 0,
                objects: BTreeMap::new(),
                reserved: BTreeMap::new(),
            }),
        }
    }

    /// Called only under handles, so published↔pending transfer and every
    /// other writer use the same admission order. Object retirement can only
    /// reduce pending totals, and never takes handles in the inverse order.
    fn capacity(&self, handles: &Handles, size: u64) -> bool {
        let slot = self.pending_budget.lock();
        let (count, bytes) = slot.as_ref().map_or((0, 0), |budget| {
            let totals = budget.totals.lock();
            (totals.count, totals.bytes)
        });
        handles
            .objects
            .len()
            .checked_add(count)
            .is_some_and(|n| n < MAX_OBJECTS)
            && handles
                .bytes
                .checked_add(bytes)
                .and_then(|n| n.checked_add(size))
                .is_some_and(|n| n <= MAX_FILE_BYTES)
    }
    fn charge_pending(&self, size: u64) -> Result<PendingCharge, FsError> {
        // Allocate prospective metadata before taking any IRQ-safe guard.
        let prospective = Arc::new(PendingBudget::default());
        let handles = self.handles.lock();
        let budget = {
            let mut slot = self.pending_budget.lock();
            slot.get_or_insert_with(|| prospective.clone()).clone()
        };
        let mut totals = budget.totals.lock();
        if handles
            .objects
            .len()
            .checked_add(totals.count)
            .is_none_or(|n| n >= MAX_OBJECTS)
            || handles
                .bytes
                .checked_add(totals.bytes)
                .and_then(|n| n.checked_add(size))
                .is_none_or(|n| n > MAX_FILE_BYTES)
        {
            return Err(FsError::OutOfMemory);
        }
        totals.count += 1;
        totals.bytes += size;
        drop(totals);
        drop(handles);
        Ok(PendingCharge {
            budget,
            size,
            active: true,
        })
    }

    #[cfg(feature = "kernel-test")]
    pub(crate) fn fixture_pending_usage(&self) -> (usize, u64) {
        let _handles = self.handles.lock();
        let slot = self.pending_budget.lock();
        slot.as_ref().map_or((0, 0), |budget| {
            let totals = budget.totals.lock();
            (totals.count, totals.bytes)
        })
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
        self.create_with_pat(size, owner, placement, None, report)
    }

    /// As `create_placed`, optionally programming a PAT index on the created object.
    pub(crate) fn create_with_pat(
        &self,
        size: u64,
        owner: Option<u64>,
        placement: Placement<'_>,
        pat: Option<u8>,
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
        if !self.capacity(&handles, size) {
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
        let mut track_pool = None;
        let mut object = match (local, placement) {
            (Some(allocation), _) => {
                let storage = GemObject::storage_of(&allocation);
                let page_size = allocation.page_size();
                track_pool = Some(allocation.pool().clone());
                let mut object = GemObject::allocate(0, offset)?;
                {
                    let mut backing = object.backing.lock();
                    backing.charged = false;
                    backing.vram = Some(allocation);
                }
                object.storage.store(storage, Ordering::Release);
                object.vram_page_sz.store(page_size, Ordering::Release);
                object.preferred_vram.store(true, Ordering::Release);
                object.size = size;
                object
            }
            (None, Placement::SystemWc) => GemObject::allocate_wc(size, offset)?,
            (None, _) => GemObject::allocate(size, offset)?,
        };
        object.vm_owner = owner;
        if let Some(p) = pat {
            object.pat_index = Some(p);
        }
        let object = Arc::new(object);
        let handle = handles.next;
        report(handle, size)?;
        let tracked = object.clone();
        handles.objects.insert(handle, object);
        handles.next = next;
        handles.bytes += size;
        drop(handles);
        if let Some(pool) = track_pool {
            pool.track(&tracked);
        }
        Ok(handle)
    }

    /// `i915_gem_userptr_ioctl`: allocate a GEM buffer object over user-provided
    /// memory addresses. The range must be page-aligned and within user virtual
    /// address limits.
    pub fn userptr(
        &self,
        user_ptr: u64,
        user_size: u64,
        flags: u32,
        user: &dyn IoctlContext,
    ) -> Result<u32, FsError> {
        use crate::intel_gpu_uapi as abi;
        if flags
            & !(abi::I915_USERPTR_READ_ONLY
                | abi::I915_USERPTR_PROBE
                | abi::I915_USERPTR_UNSYNCHRONIZED)
            != 0
        {
            return Err(FsError::InvalidData);
        }
        if (user_ptr | user_size) % PAGE != 0 || user_size == 0 || user_size > MAX_FILE_BYTES {
            return Err(FsError::InvalidData);
        }
        let end = user_ptr.checked_add(user_size).ok_or(FsError::BadAddress)?;
        #[cfg(not(target_arch = "aarch64"))]
        const USER_VA_LIMIT: u64 = (1 << 47) - 4096;
        #[cfg(target_arch = "aarch64")]
        const USER_VA_LIMIT: u64 = (1 << 48) - 4096;
        if end > USER_VA_LIMIT {
            return Err(FsError::BadAddress);
        }
        let handles = self.handles.lock();
        if !self.capacity(&handles, user_size) {
            return Err(FsError::OutOfMemory);
        }
        drop(handles);

        let read_only = flags & abi::I915_USERPTR_READ_ONLY != 0;
        let pages = user_size / PAGE;

        let notifier = if flags & abi::I915_USERPTR_UNSYNCHRONIZED == 0 {
            user.mmu_interval_notifier(
                user_ptr,
                user_size,
                Arc::new(crate::intel_gpu_xe_vm::UserptrNotifier),
            )
            .ok()
        } else {
            None
        };

        let seq = notifier.as_ref().map(|n| n.read_begin()).unwrap_or(0);
        let pins = match user.pin_user_pages(user_ptr, pages, !read_only) {
            Ok(pins) => pins,
            Err(FsError::Unsupported) => {
                if let Some(space) = narf_scheduler::current_address_space() {
                    let mut pins = Vec::new();
                    pins.try_reserve_exact(pages as usize)
                        .map_err(|_| FsError::OutOfMemory)?;
                    for i in 0..pages {
                        let va = user_ptr + i * PAGE;
                        let at = narf_memory::VirtAddr::new(va);
                        // SAFETY: caller address space is active; resolving page table entry writability.
                        let writable = unsafe { space.user_page_writable_or_resolve(at) };
                        if !read_only && !writable {
                            return Err(FsError::BadAddress);
                        }
                        pins.push(space.pin_user_page(at).ok_or(FsError::BadAddress)?);
                    }
                    pins
                } else {
                    return Err(FsError::Unsupported);
                }
            }
            Err(e) => return Err(e),
        };

        if let Some(n) = &notifier {
            if n.read_retry(seq) {
                return Err(FsError::Busy);
            }
        }

        let object = GemObject::from_userptr_pins(pins, read_only)?;
        let mut handles = self.handles.lock();
        if !self.capacity(&handles, user_size) {
            return Err(FsError::OutOfMemory);
        }
        let handle = handles.next;
        handles.next = handle.checked_add(1).ok_or(FsError::OutOfMemory)?;
        handles.objects.insert(handle, object);
        handles.bytes += user_size;
        Ok(handle)
    }

    /// Reserve storage without any BAR access or public handle. Cancellation before or
    /// after submission drops only this reference; the scheduler retains its
    /// own target object through clear retirement or proven reset.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn prepare_vram(
        &self,
        size: u64,
        owner: Option<u64>,
        pool: &Arc<crate::intel_gpu_vram::Vram>,
    ) -> Result<PendingVram, FsError> {
        self.prepare_vram_class(size, owner, pool, true)
    }
    pub(crate) fn prepare_vram_class(
        &self,
        size: u64,
        owner: Option<u64>,
        pool: &Arc<crate::intel_gpu_vram::Vram>,
        visible: bool,
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
            if !self.capacity(&handles, size) {
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
        let quota = if pool.smallbar_enabled() {
            Some(self.charge_pending(size)?)
        } else {
            None
        };
        let allocation = pool.allocate_class(size, visible)?;
        let storage = GemObject::storage_of(&allocation);
        let mut object = GemObject::allocate(0, offset)?;
        *object.pending_quota.lock() = quota;
        {
            let mut backing = object.backing.lock();
            backing.charged = false;
            backing.vram = Some(allocation);
        }
        object.storage.store(storage, Ordering::Release);
        object
            .vram_page_sz
            .store(pool.page_size(), Ordering::Release);
        object.preferred_vram.store(true, Ordering::Release);
        object.size = size;
        object.vm_owner = owner;
        object.ccs.store(1, Ordering::Release);
        Ok(PendingVram {
            object: Arc::new(object),
        })
    }

    /// Reserve a private monotonic ID and charge capacity before faultable
    /// output. The token is invisible to object/close/import/mmap lookup.
    /// Its drop releases both capacity and the private graph outside IRQ locks.
    pub(crate) fn reserve_smallbar_publication(
        &self,
        pending: PendingVram,
        fence: &crate::intel_gpu_fence::CompletionFence,
    ) -> Result<VramPublication<'_>, FsError> {
        if !pending.object.initialization_complete(fence) {
            return Err(crate::intel_gpu_user::io_error());
        }
        let size = pending.object.size();
        let handle = {
            let mut handles = self.handles.lock();
            let quota = pending.object.pending_quota.lock();
            let quota = quota.as_ref().ok_or(FsError::InvalidData)?;
            if !quota.active
                || quota.size != size
                || self
                    .pending_budget
                    .lock()
                    .as_ref()
                    .is_none_or(|b| !Arc::ptr_eq(b, &quota.budget))
            {
                return Err(FsError::InvalidData);
            }
            let handle = handles.next;
            handles.next = handle.checked_add(1).ok_or(FsError::OutOfMemory)?;
            assert!(handles.reserved.insert(handle, size).is_none());
            handle
        };
        Ok(VramPublication {
            gem: self,
            handle,
            size,
            object: Some(pending.object),
            settled: None,
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
        if !self.capacity(&handles, size) {
            return Err(FsError::OutOfMemory);
        }
        let next = handles.next.checked_add(1).ok_or(FsError::OutOfMemory)?;
        let handle = handles.next;
        report(handle, size)?;
        pending.object.ccs.store(4, Ordering::Release);
        pending.object.set_preferred_vram();
        let tracked = pending.object.clone();
        handles.objects.insert(handle, pending.object);
        handles.next = next;
        handles.bytes += size;
        drop(handles);
        if let Some(pool) = tracked.vram_pool() {
            pool.track(&tracked);
        }
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

    /// `xe_gem_prime_export`'s admission. A VRAM object exports as it is:
    /// each importer's attachment decides peer-to-peer access or migration
    /// (`crate::intel_gpu_prime`). A same-card import shares the object.
    // LINUX-GAP: xe_gem_prime_export first validates the object into its
    // preferred placement; NARF leaves an evicted object where it is.
    pub(crate) fn export_object(&self, handle: u32) -> Result<Arc<GemObject>, FsError> {
        let object = self.object(handle)?;
        if object.vm_owner.is_some() || object.is_userptr() {
            return Err(FsError::InvalidData);
        }
        Ok(object)
    }

    /// The handle this open already holds for an import of `exporter`
    /// (`drm_prime_lookup_buf_handle` on a reimport of the same dma-buf).
    pub(crate) fn imported_handle(&self, exporter: &Arc<GemObject>) -> Option<u32> {
        self.handles
            .lock()
            .objects
            .iter()
            .find(|(_, object)| {
                object
                    .import
                    .as_ref()
                    .is_some_and(|import| Arc::ptr_eq(import.exporter_object(), exporter))
            })
            .map(|(handle, _)| *handle)
    }

    /// `xe_dma_buf_create_obj` + `drm_gem_handle_create` for a foreign
    /// dma-buf: a system-placed object over the attachment, sharing the
    /// exporter's reservation. Its pages appear when the attachment is mapped
    /// (first VM bind). It is never migrated or compressed, its mmap maps the
    /// exporter's object, and it is not charged to the system-memory bound:
    /// the exporter owns the memory.
    pub(crate) fn import_attachment(
        &self,
        import: crate::intel_gpu_prime::Import,
    ) -> Result<u32, FsError> {
        let exporter = import.exporter_object().clone();
        let size = exporter.size;
        let offset = NEXT_MMAP
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |offset| {
                offset
                    .checked_add(size + PAGE)
                    .filter(|next| *next < 1 << 63)
            })
            .map_err(|_| FsError::OutOfMemory)?;
        let mut object = GemObject::allocate(0, offset)?;
        object.backing.lock().charged = false;
        object.size = size;
        object.dma_buf = exporter.dma_buf.clone();
        object.no_compression.store(true, Ordering::Release);
        object.import = Some(import);
        let object = Arc::new(object);
        let mut handles = self.handles.lock();
        let existing = handles
            .objects
            .iter()
            .find(|(_, entry)| {
                entry
                    .import
                    .as_ref()
                    .is_some_and(|import| Arc::ptr_eq(import.exporter_object(), &exporter))
            })
            .map(|(handle, _)| *handle);
        let next = handles.next.checked_add(1);
        let result = match (existing, next) {
            // A racing reimport won; this attachment detaches below.
            (Some(handle), _) => Ok(handle),
            (None, Some(next)) if self.capacity(&handles, size) => {
                let handle = handles.next;
                handles.next = next;
                handles.objects.insert(handle, object.clone());
                handles.bytes += size;
                Ok(handle)
            }
            (None, _) => Err(FsError::OutOfMemory),
        };
        drop(handles);
        // An unpublished import's attachment detaches outside the handle lock.
        drop(object);
        result
    }

    /// Same-card PRIME import. Reimporting the same object on an open returns
    /// its existing handle. The object retains its own allocation/accounting.
    pub fn import(&self, object: &Arc<GemObject>) -> Result<u32, FsError> {
        if object.private_staging {
            return Err(FsError::Unsupported);
        }
        let mut handles = self.handles.lock();
        if let Some((handle, _)) = handles
            .objects
            .iter()
            .find(|(_, entry)| Arc::ptr_eq(entry, object))
        {
            return Ok(*handle);
        }
        if !self.capacity(&handles, object.size) {
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

    /// The fake mmap offset of `handle`. A foreign import has one too
    /// (`xe_gem_mmap_offset_ioctl` creates it for any BO): mapping it maps
    /// the exporter's object ([`Self::mapping_object`]).
    pub fn mmap_offset(&self, handle: u32) -> Result<u64, FsError> {
        let object = self.object(handle)?;
        if object.is_gpu_only() || object.private_staging || object.is_userptr() {
            return Err(FsError::Unsupported);
        }
        if let Some(import) = object.import() {
            let exporter = import.exporter_object();
            if exporter.is_gpu_only() || exporter.private_staging {
                return Err(FsError::Unsupported);
            }
        }
        Ok(object.offset)
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
        drop(handles);
        // TTM refuses to fault an imported sg BO's pages ("handled (if at all)
        // by redirecting mmap to the exporter"); NARF redirects, as
        // drm_gem_shmem_mmap does for an import: dma_buf_mmap(obj->dma_buf,
        // vma, 0) bounds the range by the buffer (-EINVAL past its end) and
        // maps the exporter's pages through the exporter's own mmap
        // (drm_gem_dmabuf_mmap -> xe_gem_object_mmap): its system pages or
        // its LMEM BAR, with the exporter's caching, alias census and
        // eviction exclusion. CPU access is ordered by DMA_BUF_IOCTL_SYNC on
        // the shared reservation (dma_buf_begin_cpu_access).
        let exporter = object
            .import()
            .map(|import| import.exporter_object().clone());
        let object = exporter.unwrap_or(object);
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
            .backing
            .lock()
            .vram
            .as_ref()
            .expect("CPU VRAM token")
            .kernel_virt()
            .expect("visible CPU VRAM token");
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
/// Private handle reservation; never inserted before successful copyout and
/// a second owner/VM identity validation. A nonce cannot be guessed/reused:
/// IDs are monotonically consumed even on cancellation or failed output.
#[derive(Debug)]
pub(crate) struct VramPublication<'a> {
    gem: &'a GemState,
    pub(crate) handle: u32,
    size: u64,
    object: Option<Arc<GemObject>>,
    settled: Option<PendingCharge>,
}
impl VramPublication<'_> {
    pub(crate) fn commit(&mut self) -> Result<(), FsError> {
        let mut handles = self.gem.handles.lock();
        if handles.reserved.get(&self.handle) != Some(&self.size)
            || handles.objects.contains_key(&self.handle)
        {
            return Err(FsError::InvalidData);
        }
        let object = self.object.as_ref().ok_or(FsError::InvalidData)?;
        let mut quota = object.pending_quota.lock();
        let charge = quota.as_ref().ok_or(FsError::InvalidData)?;
        if !charge.active || charge.size != self.size {
            return Err(FsError::InvalidData);
        }
        let mut totals = charge.budget.totals.lock();
        if totals.count == 0 || totals.bytes < self.size {
            return Err(FsError::InvalidData);
        }
        // One transfer under handles+budget: never double charge, no gap.
        totals.count -= 1;
        totals.bytes -= self.size;
        handles.bytes += self.size;
        drop(totals);
        let mut charge = quota.take().expect("verified pending charge");
        charge.active = false;
        self.settled = Some(charge); // defer Arc metadata drop until outside names
        drop(quota);
        let object = self.object.take().expect("verified private object");
        object.ccs.store(4, Ordering::Release);
        object.set_preferred_vram();
        let tracked = object.clone();
        handles.reserved.remove(&self.handle);
        handles.objects.insert(self.handle, object);
        drop(handles);
        if let Some(pool) = tracked.vram_pool() {
            pool.track(&tracked);
        }
        Ok(())
    }
}
impl Drop for VramPublication<'_> {
    fn drop(&mut self) {
        let object = self.object.take();
        if object.is_some() {
            let mut handles = self.gem.handles.lock();
            handles.reserved.remove(&self.handle);
        }
        // Pending charge stays with any scheduler/VM reference to the object;
        // abandoned output cannot reduce quota before actual GPU retirement.
        drop(object);
        drop(self.settled.take());
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
