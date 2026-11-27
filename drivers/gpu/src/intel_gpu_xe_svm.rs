//! Xe CPU-address-mirror VMs (shared virtual memory), behind the strict boot
//! option `narf.intel.svm=1` (default off). MIT Linux 7.4-rc4: `xe_svm.c`,
//! `xe_vm.c` (the `DRM_XE_VM_BIND_FLAG_CPU_ADDR_MIRROR` bind paths and
//! `prefetch_ranges`), `xe_pagefault.c`, `xe_guc_pagefault.c`, `xe_query.c`
//! and `drm/drm_gpusvm.c`.
//!
//! A mirror bind (`DRM_XE_VM_BIND_OP_MAP` with `CPU_ADDR_MIRROR`) on a
//! fault-mode VM reserves a GPU VA range that mirrors the same addresses of
//! the VM creator's address space (`gpusvm->mm`, `current->mm` at
//! `xe_svm_init`). It maps nothing. A GPU fault inside it inserts an SVM
//! range (`drm_gpusvm_range_find_or_insert`, in 2 MiB, 64 KiB or 4 KiB
//! chunks) with its own interval notifier and collects the CPU's pages for it
//! (`drm_gpusvm_get_pages`); every later job maps those pages. A CPU
//! invalidation (munmap, mprotect, MADV_DONTNEED, COW, migration) zaps the
//! range (`xe_svm_invalidate`), and an UNMAP event also queues it for the
//! garbage collector (`xe_svm_garbage_collector`), which removes it before
//! the next fault, bind or job is processed.
//!
//! # The NARF model, and where it departs from Linux
//!
//! - **Fault delivery.** [`guc::PageFault`] decodes the GuC
//!   `REPORT_PAGE_FAULT_REQ_DESC` descriptor (`xe_guc_pagefault_handler`) and
//!   encodes the `PAGE_FAULT_RES_DESC` reply (`guc_ack_fault`). The GuC
//!   scheduler queues decoded faults on the device's USM state
//!   (`intel_gpu_xe_vm::usm`), whose service looks the VM up by ASID and
//!   collects through the creator's address space grabbed at VM creation
//!   (`gpusvm->mm`, [`narf_filesystem::RemoteMm`]); the GT owner then writes
//!   the result into the tables of the VM's running jobs, invalidates their
//!   TLB and answers the GuC. The firmware delivers no fault yet: NARF
//!   registers no UM queues (see `usm`). From the creator's own syscall,
//!   `XeFile::service_page_fault` runs the same service, and EXEC refaults
//!   invalidated ranges; from another process both are ENOSYS, as USERPTR
//!   re-collection is. `DRM_XE_VM_BIND_OP_PREFETCH` over a mirror VMA
//!   (`prefetch_ranges`) populates ranges ahead of any fault.
//! - **Zap and refault at the job boundary.** Invalidation callbacks run under
//!   IRQ-masked mapping locks and cannot wait for jobs or touch page tables.
//!   The registry publishes the new sequence before the callback runs, so a
//!   range is invalid from that point; a job built before keeps the pins it
//!   was built with until it retires (the USERPTR safety argument: the GPU
//!   never reaches a released frame), and no job built after maps the old
//!   pages. Because a NARF GPU cannot refault on its own, EXEC re-collects
//!   every invalidated range that still mirrors a live mapping (the refault
//!   the GPU would take) and leaves it unmapped if that fails. A range an
//!   UNMAP removed is gone: only a new fault recreates it.
//! - **Chunk sizing without a CPU VMA walk.** `drm_gpusvm_range_chunk_size`
//!   requires the chunk to lie inside one CPU VMA. NARF has no VMA lookup for
//!   drivers, so the collection itself is the check: a chunk whose pages are
//!   not all readable (writable for a writable mirror) falls back to the next
//!   smaller size, and a 4 KiB chunk that fails is `vma_lookup`'s -ENOENT (or
//!   -EPERM). Two adjacent CPU VMAs may therefore share one chunk.
//! - **One interval per range.** Linux groups ranges under 512 MiB notifiers
//!   (`xe_modparam.svm_notifier_size`); a 2 MiB-aligned chunk never crosses
//!   one, so the notifier bound never constrains a chunk. NARF registers one
//!   interval per range, so each callback names exactly one range.
//! - **No device memory.** NARF behaves as Linux built without
//!   `CONFIG_DRM_XE_PAGEMAP`: [`Pagemap`] is uninhabited, so mirrored pages
//!   stay in system memory on Battlemage too, and a PREFETCH to VRAM or an
//!   atomic fault collects system pages (`xe_svm_range_needs_migrate_to_vram`
//!   is false without a pagemap).
//! - **Budget.** Populated ranges count against the job tables' 4096 entries
//!   and 512 MiB (`ResidentBatch::from_vm`); a fault past either is ENOMEM.
//!   PREFETCH probes CPU holes page by page, so one mirror PREFETCH spans at
//!   most 512 MiB.
//! - **Admission.** A mirror bind with a compressed PAT index, or with
//!   `DRM_XE_VM_BIND_FLAG_NULL`, is refused (Linux admits both). There is no
//!   `DRM_IOCTL_XE_MADVISE`, so `MADVISE_AUTORESET` is admitted and has
//!   nothing to reset.
use super::{State, Vm, MAX_MAPPINGS, MAX_VA, USERPTR_PIN_ROUNDS};
use crate::{
    intel_gpu_exec::VmMapping, intel_gpu_gem::GemObject, intel_gpu_gt::GtPlatform,
    intel_gpu_render::DeviceInfo,
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::{FsError, IoctlContext, RemoteMm};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{
    address_space::UserPagePin,
    mmu_notifier::{
        MmuInterval, MmuIntervalNotifier, MmuIntervalNotifierOps, MmuNotifierEvent,
        MmuNotifierRange,
    },
};

/// The strict boot option.
pub(crate) const OPTION: &str = "narf.intel.svm";

/// `narf.intel.svm=1` is on the command line.
pub(crate) fn opted_in() -> bool {
    crate::intel_gpu_gt::boot_opt_in(narf_boot::args(), OPTION)
}

/// `xe->info.has_usm` (`xe_pci.c` `XE2_GFX_FEATURES`): graphics 20 and later.
/// Xe-LPG (Meteor/Arrow Lake), DG2 and Gen12 have none, so Linux refuses
/// their FAULT_MODE VMs (`xe_vm_create_ioctl`) and never reaches a mirror.
pub(crate) const fn has_usm(platform: GtPlatform) -> bool {
    platform.is_xe2()
}

/// `xe->info.has_usm && IS_ENABLED(CONFIG_DRM_XE_GPUSVM)`, GPUSVM being
/// present only when the backend publishes it (`narf.intel.svm=1`).
pub(crate) fn admitted(info: &DeviceInfo) -> bool {
    has_usm(info.platform)
        && info
            .backend
            .as_ref()
            .is_some_and(|backend| backend.cpu_addr_mirror())
}

/// `DRM_XE_VM_BIND_FLAG_NULL`.
pub(crate) const BIND_FLAG_NULL: u32 = 1 << 2;
/// `DRM_XE_VM_BIND_FLAG_CPU_ADDR_MIRROR`.
pub(crate) const BIND_FLAG_CPU_ADDR_MIRROR: u32 = 1 << 5;
/// `DRM_XE_VM_BIND_FLAG_MADVISE_AUTORESET`.
pub(crate) const BIND_FLAG_MADVISE_AUTORESET: u32 = 1 << 6;
/// `DRM_XE_QUERY_CONFIG_FLAG_HAS_CPU_ADDR_MIRROR`.
pub(crate) const QUERY_CONFIG_HAS_CPU_ADDR_MIRROR: u64 = 1 << 2;

const PAGE: u64 = 4096;
/// `fault_chunk_sizes` (`xe_svm.c`), largest first.
pub(crate) const CHUNK_SIZES: [u64; 3] = [2 << 20, 64 << 10, PAGE];
/// The job tables' byte budget (`ResidentBatch::from_vm`, `State::prepare`).
const TABLE_BYTES: u64 = 512 * 1024 * 1024;

/// `drm_pagemap`: a device-memory home for mirrored pages. NARF builds as
/// Linux does without `CONFIG_DRM_XE_PAGEMAP` (`xe_vma_resolve_pagemap` and
/// `xe_tile_local_pagemap` return NULL), so the type has no value and no
/// path can migrate a range to VRAM: the `match pagemap {}` at each would-be
/// migration point proves it. That is where migration stops: Linux's
/// `xe_pagemap_create` registers VRAM as `MEMORY_DEVICE_PRIVATE` pages
/// (`devm_memremap_pages`), `drm_pagemap_migrate_to_devmem` moves a range's
/// anonymous pages there through `migrate_vma_setup`/`migrate_vma_pages`,
/// and a CPU touch faults back through the device-private entry
/// (`drm_pagemap_migrate_to_ram`, `drm_pagemap_evict_to_ram`). NARF memory/
/// has no ZONE_DEVICE pages or device-private entries, which no small
/// driver-facing API can add.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Pagemap {}

/// `xe_vma_resolve_pagemap` (or `xe_tile_local_pagemap` for an atomic fault
/// or a PREFETCH to `region` 1): never a pagemap, so
/// `xe_svm_range_needs_migrate_to_vram` is false and every range collects
/// system pages.
fn pagemap(_region: u32) -> Option<Pagemap> {
    None
}

/// The `DRM_IOCTL_XE_MADVISE` attributes of a mirror VMA other than its PAT
/// index (`struct xe_vma_mem_attr`). The default is
/// `DRM_XE_PREFERRED_LOC_DEFAULT_DEVICE`, `DRM_XE_MIGRATE_ALL_PAGES` and
/// `DRM_XE_ATOMIC_UNDEFINED`, all zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MemAttr {
    /// `preferred_loc.devmem_fd`.
    pub devmem_fd: u32,
    /// `preferred_loc.migration_policy`.
    pub migration_policy: u16,
    /// `atomic_access`.
    pub atomic: u32,
}

/// One CPU-address-mirror VMA (`XE_VMA_SYSTEM_ALLOCATOR`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MirrorVma {
    pub start: u64,
    pub end: u64,
    /// `vma->attr.pat_index`, equal to `default_pat_index` without madvise.
    pub pat: u8,
    /// `XE_VMA_READ_ONLY`.
    pub read_only: bool,
    /// `vma->attr.default_pat_index`: the bind's PAT index.
    pub default_pat: u8,
    pub attr: MemAttr,
    /// `XE_VMA_MADV_AUTORESET` (`DRM_XE_VM_BIND_FLAG_MADVISE_AUTORESET`).
    pub autoreset: bool,
}

impl MirrorVma {
    /// A mirror bind's VMA, with default attributes.
    pub(crate) fn new(start: u64, end: u64, pat: u8, read_only: bool, autoreset: bool) -> Self {
        Self {
            start,
            end,
            pat,
            read_only,
            default_pat: pat,
            attr: MemAttr::default(),
            autoreset,
        }
    }
    /// `xe_vma_has_default_mem_attrs`.
    pub(crate) fn has_default_attrs(&self) -> bool {
        self.attr == MemAttr::default() && self.pat == self.default_pat
    }
    /// `xe_vma_set_default_attributes`.
    pub(crate) fn set_default_attrs(&mut self) {
        self.attr = MemAttr::default();
        self.pat = self.default_pat;
    }
    pub(crate) fn contains(&self, address: u64) -> bool {
        (self.start..self.end).contains(&address)
    }
    pub(crate) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

/// `xe_vm_find_cpu_addr_mirror_vma_range`: widen `[start, end)` over the
/// mirror VMAs holding `start - 4K` and `end + 1` that have default
/// attributes (`is_cpu_addr_vma_with_default_attr`).
pub(crate) fn merge_extent(vmas: &[MirrorVma], start: u64, end: u64) -> (u64, u64) {
    let absorbs = |address: u64| {
        vmas.iter()
            .find(|vma| vma.contains(address))
            .filter(|vma| vma.has_default_attrs())
    };
    let start = start
        .checked_sub(PAGE)
        .and_then(absorbs)
        .map_or(start, |prev| prev.start);
    let end = Some(end)
        .filter(|end| *end < MAX_VA)
        .and_then(|end| absorbs(end + 1))
        .map_or(end, |next| next.end);
    (start, end)
}

/// Remove `[start, end)` from the mirror VMAs (the REMAP and UNMAP of each one
/// it overlaps). `busy` names a live SVM range inside a removed part:
/// `vm_bind_ioctl_ops_parse` refuses that with -EBUSY unless the op is itself
/// a mirror MAP (`XE_VMA_OPS_FLAG_ALLOW_SVM_UNMAP`), which passes `None`.
pub(crate) fn carve(
    vmas: &mut Vec<MirrorVma>,
    start: u64,
    end: u64,
    busy: Option<&dyn Fn(u64, u64) -> bool>,
) -> Result<(), FsError> {
    let mut kept = Vec::new();
    kept.try_reserve(vmas.len() + 1)
        .map_err(|_| FsError::OutOfMemory)?;
    for vma in vmas.iter() {
        if !vma.overlaps(start, end) {
            kept.push(*vma);
            continue;
        }
        if busy.is_some_and(|busy| busy(vma.start.max(start), vma.end.min(end))) {
            return Err(FsError::Busy);
        }
        if vma.start < start {
            kept.push(MirrorVma { end: start, ..*vma });
        }
        if vma.end > end {
            kept.push(MirrorVma { start: end, ..*vma });
        }
    }
    *vmas = kept;
    Ok(())
}

/// Whether `[address, address + size)` is covered by the union of the
/// mappings and the mirror VMAs (PREFETCH admission).
pub(crate) fn covered(mappings: &[VmMapping], vmas: &[MirrorVma], address: u64, size: u64) -> bool {
    let Some(end) = address.checked_add(size).filter(|_| size != 0) else {
        return false;
    };
    let mut spans: Vec<(u64, u64)> = mappings
        .iter()
        .map(|m| (m.va, m.va.saturating_add(m.length)))
        .chain(vmas.iter().map(|vma| (vma.start, vma.end)))
        .filter(|(start, limit)| *start < end && address < *limit)
        .collect();
    spans.sort_unstable();
    let mut reached = address;
    for (start, limit) in spans {
        if start > reached {
            return false;
        }
        reached = reached.max(limit);
    }
    reached >= end
}

// ── SVM ranges (drm_gpusvm.c) ─────────────────────────────────────────

/// Where a range's pages are collected: the VM creator's own syscall, or the
/// creator's address space grabbed at VM creation (`gpusvm->mm`), from the
/// GPU page-fault service.
#[derive(Clone, Copy)]
pub(crate) enum Collector<'a> {
    Syscall(&'a dyn IoctlContext),
    Remote(&'a dyn RemoteMm),
}

impl Collector<'_> {
    fn identity(&self) -> Option<u64> {
        match self {
            Self::Syscall(user) => user.address_space_identity(),
            Self::Remote(mm) => Some(mm.identity()),
        }
    }
    fn pin(&self, address: u64, pages: u64, writable: bool) -> Result<Vec<UserPagePin>, FsError> {
        match self {
            Self::Syscall(user) => user.pin_user_pages(address, pages, writable),
            Self::Remote(mm) => mm.pin_user_pages(address, pages, writable),
        }
    }
    fn notifier(
        &self,
        address: u64,
        length: u64,
        ops: Arc<dyn MmuIntervalNotifierOps>,
    ) -> Result<MmuIntervalNotifier, FsError> {
        match self {
            Self::Syscall(user) => user.mmu_interval_notifier(address, length, ops),
            Self::Remote(mm) => mm.mmu_interval_notifier(address, length, ops),
        }
    }
}

/// A range's interval-notifier consumer (`xe_svm_invalidate`). The registry
/// has already stored the new sequence, which invalidates the range's pages
/// for every job built from here on; an UNMAP (or the address space's
/// release) also marks the range for the garbage collector
/// (`drm_gpusvm_range_set_unmapped`). Non-blocking: one atomic store.
#[derive(Debug, Default)]
struct RangeEvents {
    unmapped: AtomicBool,
}

impl MmuIntervalNotifierOps for RangeEvents {
    fn invalidate(&self, _interval: &MmuInterval, range: &MmuNotifierRange, _cur_seq: u64) {
        if matches!(
            range.event,
            MmuNotifierEvent::Unmap | MmuNotifierEvent::Release
        ) {
            self.unmapped.store(true, Ordering::Release);
        }
    }
}

/// A range's collected pages (`struct drm_gpusvm_pages`): a VM-private
/// object of user pins and the interval sequence they were collected under.
#[derive(Debug)]
struct Pages {
    object: Arc<GemObject>,
    seq: u64,
}

/// One SVM range (`struct xe_svm_range`).
#[derive(Debug)]
struct Range {
    start: u64,
    end: u64,
    notifier: MmuIntervalNotifier,
    events: Arc<RangeEvents>,
    /// The PTE attributes of the mirror VMA it was last collected for.
    writable: bool,
    pat: u8,
    /// `None` once zapped and not yet refaulted.
    pages: Option<Pages>,
}

impl Range {
    fn contains(&self, address: u64) -> bool {
        (self.start..self.end).contains(&address)
    }
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
    fn gone(&self) -> bool {
        self.events.unmapped.load(Ordering::Acquire) || self.notifier.is_released()
    }
    /// `xe_svm_range_is_valid`: bound, and not invalidated since.
    fn valid(&self) -> bool {
        self.pages
            .as_ref()
            .is_some_and(|pages| !self.notifier.read_retry(pages.seq))
    }
    fn mapping(&self) -> Option<VmMapping> {
        let pages = self.pages.as_ref()?;
        Some(VmMapping {
            object: Some(pages.object.clone()),
            va: self.start,
            offset: 0,
            length: self.end - self.start,
            writable: self.writable,
            pat: self.pat,
            dumpable: false,
        })
    }

    /// `drm_gpusvm_range_find_or_insert` (the interval), then
    /// `xe_svm_range_get_pages`.
    fn insert(
        vm: &Vm,
        user: Collector<'_>,
        start: u64,
        end: u64,
        vma: &MirrorVma,
    ) -> Result<Self, FsError> {
        let events = Arc::new(RangeEvents::default());
        let notifier = user.notifier(start, end - start, events.clone())?;
        let mut range = Self {
            start,
            end,
            notifier,
            events,
            writable: !vma.read_only,
            pat: vma.pat,
            pages: None,
        };
        range.collect(vm, user, vma)?;
        Ok(range)
    }

    /// `drm_gpusvm_get_pages` for `vma`'s attributes (`ctx.read_only`):
    /// collect the range inside `read_begin`/`read_retry` until no
    /// invalidation raced it; -EFAULT once the range is unmapped, -EBUSY when
    /// every round was raced (`HMM_RANGE_DEFAULT_TIMEOUT`).
    fn collect(&mut self, vm: &Vm, user: Collector<'_>, vma: &MirrorVma) -> Result<(), FsError> {
        self.pages = None;
        self.writable = !vma.read_only;
        self.pat = vma.pat;
        for _ in 0..USERPTR_PIN_ROUNDS {
            if self.gone() {
                return Err(FsError::BadAddress);
            }
            let seq = self.notifier.read_begin();
            let pins = user.pin(self.start, (self.end - self.start) / PAGE, self.writable)?;
            // drm_gpusvm_get_pages: a range unmapped meanwhile is -EFAULT.
            if self.gone() {
                return Err(FsError::BadAddress);
            }
            if self.notifier.read_retry(seq) {
                continue;
            }
            self.pages = Some(Pages {
                object: GemObject::from_user_pins(pins, vm.identity)?,
                seq,
            });
            return Ok(());
        }
        Err(FsError::Busy)
    }
}

/// What `xe_svm_init` mirrors: the creator's address space (`current->mm`)
/// by identity, grabbed when the creator's context offers it, on a device
/// that is or is not discrete.
pub(crate) struct Mirror {
    pub space: u64,
    pub remote: Option<Arc<dyn RemoteMm>>,
    pub discrete: bool,
}

/// A fault-mode VM's GPU SVM (`vm->svm.gpusvm`).
#[derive(Debug)]
pub(crate) struct Svm {
    /// [`narf_memory::AddressSpace::identity`] of the mirrored address space.
    space: u64,
    /// That address space, grabbed at VM creation (`gpusvm->mm`), through
    /// which the GPU page-fault service collects pages. `None` when the
    /// creator's context offered none; then only the creator's own syscalls
    /// collect.
    remote: Option<Arc<dyn RemoteMm>>,
    /// `IS_DGFX`.
    discrete: bool,
    /// The CPU-address-mirror VMAs, sorted and disjoint from the VM's
    /// mappings. Published with them, with the VM's `state` held.
    vmas: IrqSafeSpinLock<Vec<MirrorVma>>,
    /// Changed only with the VM's `state` held; the lock is held only to move
    /// the list in or out, never across a pin or a notifier insert or drop.
    ranges: IrqSafeSpinLock<Vec<Range>>,
}

impl Svm {
    pub(crate) fn new(mirror: Mirror) -> Self {
        let Mirror {
            space,
            remote,
            discrete,
        } = mirror;
        Self {
            space,
            remote: remote.filter(|mm| mm.identity() == space),
            discrete,
            vmas: IrqSafeSpinLock::new(Vec::new()),
            ranges: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    /// The published mirror VMAs, with the VM state held.
    pub(crate) fn vmas(&self, _held: &State) -> Vec<MirrorVma> {
        self.vmas.lock().clone()
    }

    /// Publish a prepared mirror-VMA set, with the VM state held.
    pub(crate) fn set_vmas(&self, _held: &State, vmas: Vec<MirrorVma>) {
        *self.vmas.lock() = vmas;
    }

    /// The mirror VMA holding `address` (`xe_vm_find_vma_by_addr`).
    pub(crate) fn vma_at(&self, address: u64) -> Option<MirrorVma> {
        self.vmas
            .lock()
            .iter()
            .find(|vma| vma.contains(address))
            .copied()
    }

    /// Work on the range list unlocked: the caller holds the VM state, the
    /// only context that changes it. Garbage is collected first
    /// (`xe_svm_garbage_collector`: "Always process UNMAPs first").
    fn with<T>(&self, work: impl FnOnce(&mut Vec<Range>) -> T) -> T {
        let mut ranges = core::mem::take(&mut *self.ranges.lock());
        let mut unmapped = Vec::new();
        ranges.retain(|range| {
            let gone = range.gone();
            if gone && unmapped.try_reserve(1).is_ok() {
                unmapped.push((range.start, range.end));
            }
            !gone
        });
        for (start, end) in unmapped {
            self.reset_default_attrs(start, end);
        }
        let result = work(&mut ranges);
        *self.ranges.lock() = ranges;
        result
    }

    /// `xe_svm_range_set_default_attr` for a range the CPU unmapped, with the
    /// VM state held: in a mirror VMA bound with `MADVISE_AUTORESET`, the
    /// range's part (the whole VMA when it already has default attributes)
    /// becomes a default-attribute mirror VMA merged with its default
    /// neighbours (`xe_vm_alloc_cpu_addr_mirror_vma`).
    fn reset_default_attrs(&self, start: u64, end: u64) {
        let mut vmas = self.vmas.lock().clone();
        let Some(index) = vmas.iter().position(|vma| vma.contains(start)) else {
            return;
        };
        let vma = vmas[index];
        if !vma.autoreset {
            return;
        }
        let default = vma.has_default_attrs();
        let (start, end) = if default {
            (vma.start, vma.end)
        } else {
            if (vma.start, vma.end) == (start, end) {
                vmas[index].set_default_attrs();
            }
            (start, end)
        };
        let (start, end) = merge_extent(&vmas, start, end);
        if (vma.start, vma.end) == (start, end) && default {
            return;
        }
        if carve(&mut vmas, start, end, None).is_err() || vmas.try_reserve(1).is_err() {
            return;
        }
        vmas.push(MirrorVma::new(start, end, vma.default_pat, vma.read_only, true));
        vmas.sort_unstable_by_key(|vma| vma.start);
        *self.vmas.lock() = vmas;
    }

    /// `xe_svm_ranges_zap_ptes_in_range` over `[start, end)`, with the VM
    /// state held: every range there drops its pages, so the next job
    /// refaults it under its VMA's new attributes and no job built after maps
    /// it with the old ones. Returns whether any range was zapped.
    pub(crate) fn zap(&self, _held: &State, start: u64, end: u64) -> bool {
        self.with(|ranges| {
            let mut zapped = false;
            for range in ranges.iter_mut().filter(|range| range.overlaps(start, end)) {
                zapped |= range.pages.take().is_some();
            }
            zapped
        })
    }

    /// `xe_svm_garbage_collector`, with the VM state held.
    pub(crate) fn collect_garbage(&self, _held: &State) {
        self.with(|_| ());
    }

    /// `xe_svm_has_mapping`: an SVM range overlaps `[start, end)`.
    pub(crate) fn has_mapping(&self, start: u64, end: u64) -> bool {
        self.ranges
            .lock()
            .iter()
            .any(|range| range.overlaps(start, end))
    }

    /// Some bound range was invalidated after its pages were collected: a job
    /// built from the ranges must be rebuilt (the USERPTR `-EAGAIN` retry).
    pub(crate) fn stale(&self) -> bool {
        self.ranges.lock().iter().any(|range| {
            range
                .pages
                .as_ref()
                .is_some_and(|pages| range.notifier.read_retry(pages.seq))
        })
    }

    /// The mappings a job built now carries for the SVM ranges, with the VM
    /// state held. An invalidated range is zapped and, from the mirrored
    /// address space's own context, refaulted (re-collected) under its mirror
    /// VMA's attributes, the job boundary standing in for the GPU's next
    /// access. One that cannot be refaulted stays unmapped until a later job
    /// or fault succeeds.
    pub(crate) fn job_mappings(
        &self,
        vm: &Vm,
        _held: &State,
        user: &dyn IoctlContext,
    ) -> Vec<VmMapping> {
        let refault = user.address_space_identity() == Some(self.space);
        self.with(|ranges| {
            for range in ranges.iter_mut().filter(|range| !range.valid()) {
                range.pages = None;
                if let Some(vma) = self.vma_at(range.start).filter(|_| refault) {
                    let _ = range.collect(vm, Collector::Syscall(user), &vma);
                }
            }
            ranges.iter().filter_map(Range::mapping).collect()
        })
    }

    /// `__xe_svm_handle_pagefault` on a system-memory device (no pagemap, so
    /// never `devmem_only` and never a migration): find or insert the range
    /// holding `address`, collect its pages unless it is still valid, and
    /// bind it into every later job. Returns the range bounds.
    pub(crate) fn fault(
        &self,
        vm: &Vm,
        state: &State,
        vma: &MirrorVma,
        address: u64,
        user: Collector<'_>,
    ) -> Result<(u64, u64), FsError> {
        if user.identity() != Some(self.space) {
            return Err(FsError::NotImplemented);
        }
        self.with(|ranges| fault_locked(ranges, vm, state, vma, address, user))
    }

    /// The creator's grabbed address space, for the GPU page-fault service:
    /// ENOSYS without one, as for another process.
    pub(crate) fn remote(&self) -> Result<Collector<'_>, FsError> {
        self.remote
            .as_deref()
            .map(Collector::Remote)
            .ok_or(FsError::NotImplemented)
    }

    /// The mapping a job needs for the valid range starting at `start`
    /// (what `xe_svm_range_bind` writes).
    pub(crate) fn range_mapping(&self, start: u64) -> Option<VmMapping> {
        self.ranges
            .lock()
            .iter()
            .find(|range| range.start == start && range.valid())
            .and_then(Range::mapping)
    }

    /// `prefetch_ranges` for the mirror VMAs over `[start, start + length)`:
    /// every chunk with CPU pages is faulted in, CPU holes are skipped
    /// (`xe_svm_find_vma_start`, page by page here), and any other error
    /// fails the bind. A PREFETCH to `region` 1 (VRAM) collects system pages,
    /// there being no pagemap to migrate to.
    pub(crate) fn prefetch(
        &self,
        vm: &Vm,
        state: &State,
        start: u64,
        length: u64,
        region: u32,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        if let Some(pagemap) = pagemap(region) {
            match pagemap {}
        }
        let end = start + length;
        let mut vmas = self.vmas(state);
        vmas.retain(|vma| vma.overlaps(start, end));
        let span = vmas.iter().try_fold(0u64, |sum, vma| {
            sum.checked_add(vma.end.min(end) - vma.start.max(start))
        });
        if span.is_none_or(|span| span > TABLE_BYTES) {
            return Err(FsError::OutOfMemory);
        }
        for vma in &vmas {
            let (mut address, stop) = (vma.start.max(start), vma.end.min(end));
            while address < stop {
                address = match self.fault(vm, state, vma, address, Collector::Syscall(user)) {
                    Ok((_, range_end)) => range_end,
                    Err(FsError::NotFound) => address + PAGE,
                    Err(error) => return Err(error),
                };
            }
        }
        Ok(())
    }
}

/// `__xe_svm_handle_pagefault` with the range list in hand.
fn fault_locked(
    ranges: &mut Vec<Range>,
    vm: &Vm,
    state: &State,
    vma: &MirrorVma,
    address: u64,
    user: Collector<'_>,
) -> Result<(u64, u64), FsError> {
    // drm_gpusvm_range_find: an existing range is valid ("PAGE FAULT -
    // VALID") or collects its pages again. A CPU mapping gone without an
    // UNMAP event is vma_lookup's -ENOENT on Linux's retry.
    if let Some(range) = ranges.iter_mut().find(|range| range.contains(address)) {
        if !range.valid() {
            range.collect(vm, user, vma).map_err(|error| match error {
                FsError::BadAddress => FsError::NotFound,
                error => error,
            })?;
        }
        return Ok((range.start, range.end));
    }
    let (bytes, entries) = budget(state, vm.scratch, ranges);
    if entries == 0 {
        return Err(FsError::OutOfMemory);
    }
    // drm_gpusvm_range_chunk_size: the largest chunk around the fault inside
    // the mirror VMA that overlaps no range (a 4 KiB chunk always qualifies)
    // and whose pages the CPU maps.
    for size in CHUNK_SIZES {
        let start = address & !(size - 1);
        let end = start + size;
        if start < vma.start || end > vma.end {
            continue;
        }
        if size != PAGE && ranges.iter().any(|range| range.overlaps(start, end)) {
            continue;
        }
        if size > bytes {
            if size == PAGE {
                return Err(FsError::OutOfMemory);
            }
            continue;
        }
        match Range::insert(vm, user, start, end, vma) {
            Ok(range) => {
                ranges.push(range);
                return Ok((start, end));
            }
            Err(FsError::BadAddress | FsError::OperationNotPermitted) if size != PAGE => {}
            Err(FsError::BadAddress) => return Err(FsError::NotFound),
            Err(error) => return Err(error),
        }
    }
    // chunk_size == LONG_MAX: -EINVAL.
    Err(FsError::InvalidData)
}

/// The job tables' remaining bytes and entries (`ResidentBatch::from_vm`
/// caps both) after the published mappings and every SVM range.
fn budget(state: &State, scratch: bool, ranges: &[Range]) -> (u64, usize) {
    let mapped = state
        .mappings
        .iter()
        .filter(|m| m.object.is_some() || !scratch)
        .map(|m| m.length)
        .chain(ranges.iter().map(|range| range.end - range.start))
        .fold(0u64, u64::saturating_add);
    (
        TABLE_BYTES.saturating_sub(mapped),
        MAX_MAPPINGS.saturating_sub(state.mappings.len() + ranges.len()),
    )
}

/// GPU page-fault reports (`xe_guc_pagefault.c`, `xe_pagefault.c`), decoded
/// by the GuC scheduler and serviced by the device's fault service
/// (`intel_gpu_xe_vm::usm`).
pub(crate) mod guc {
    #![cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    use super::{pagemap, Collector, State, Vm};
    use crate::intel_gpu_exec::VmMapping;
    use alloc::vec::Vec;
    use narf_filesystem::{FsError, IoctlContext};

    /// `XE_GUC_ACTION_REPORT_PAGE_FAULT_REQ_DESC`.
    pub(crate) const ACTION_REPORT_PAGE_FAULT_REQ_DESC: u32 = 0x6002;
    /// `XE_GUC_ACTION_PAGE_FAULT_RES_DESC`.
    pub(crate) const ACTION_PAGE_FAULT_RES_DESC: u32 = 0x6003;
    /// `enum xe_pagefault_access_type`.
    pub(crate) const ACCESS_READ: u8 = 0;
    pub(crate) const ACCESS_WRITE: u8 = 1;
    pub(crate) const ACCESS_ATOMIC: u8 = 2;
    /// `XE_PAGEFAULT_ACCESS_TYPE_MASK`, `XE_PAGEFAULT_ACCESS_PREFETCH`.
    const ACCESS_TYPE_MASK: u8 = 3;
    pub(crate) const ACCESS_PREFETCH: u8 = 1 << 7;
    /// `XE_PAGEFAULT_TYPE_LEVEL_NACK`: the producer asks for a NACK.
    pub(crate) const TYPE_LEVEL_NACK: u8 = 0xff;

    const fn field(word: u32, low: u32, bits: u32) -> u32 {
        (word >> low) & ((1 << bits) - 1)
    }

    /// One GPU page fault (`struct xe_pagefault`): the consumer fields
    /// `xe_guc_pagefault_handler` decodes, and the producer message the reply
    /// echoes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct PageFault {
        /// `consumer.page_addr`: `PFD_VIRTUAL_ADDR_HI:LO`, page aligned.
        pub page_addr: u64,
        /// `PFD_ASID`.
        pub asid: u32,
        /// `PFD_SRC_ID`.
        pub srcid: u8,
        /// `PFD_ACCESS_TYPE`, with [`ACCESS_PREFETCH`] for `PFD_PREFETCH`.
        pub access_type: u8,
        /// `PFD_FAULT_LEVEL` in bits 2:0 and `PFD_FAULT_TYPE` from bit 3, or
        /// [`TYPE_LEVEL_NACK`] for an `XE2_PFD_TRVA_FAULT`.
        pub fault_type_level: u8,
        /// `PFD_ENG_CLASS`, `PFD_ENG_INSTANCE`.
        pub engine_class: u8,
        pub engine_instance: u8,
        msg: [u32; 4],
    }

    impl PageFault {
        /// `xe_guc_pagefault_handler`: a G2H `REPORT_PAGE_FAULT_REQ_DESC` payload
        /// is exactly the four dwords of `struct xe_guc_pagefault_desc`
        /// (-EPROTO otherwise).
        pub(crate) fn from_guc(msg: &[u32]) -> Result<Self, FsError> {
            let msg: [u32; 4] = msg.try_into().map_err(|_| FsError::Protocol)?;
            let fault_type_level = if msg[0] & 1 << 18 != 0 {
                TYPE_LEVEL_NACK
            } else {
                (field(msg[0], 0, 3) | field(msg[2], 2, 2) << 3) as u8
            };
            let prefetch = if msg[2] & 1 << 11 != 0 {
                ACCESS_PREFETCH
            } else {
                0
            };
            Ok(Self {
                page_addr: u64::from(msg[3]) << 32 | u64::from(field(msg[2], 12, 20)) << 12,
                asid: field(msg[1], 12, 20),
                srcid: field(msg[0], 3, 8) as u8,
                access_type: field(msg[2], 0, 2) as u8 | prefetch,
                fault_type_level,
                engine_class: field(msg[0], 25, 3) as u8,
                engine_instance: field(msg[0], 19, 6) as u8,
                msg,
            })
        }

        /// `xe_pagefault_access_is_atomic`.
        pub(crate) fn atomic(&self) -> bool {
            self.access_type & ACCESS_TYPE_MASK == ACCESS_ATOMIC
        }

        /// `guc_ack_fault`: the `PAGE_FAULT_RES_DESC` H2G (action, then
        /// `struct xe_guc_pagefault_reply` dw0 and dw1). `PFR_SUCCESS` carries
        /// `!!err`, and `PFR_PREFETCH` echoes the request only on error, exactly
        /// as Linux sends them.
        pub(crate) fn guc_reply(&self, error: bool) -> [u32; 3] {
            let msg = &self.msg;
            let pdata = field(msg[0], 28, 4) | field(msg[1], 0, 12) << 4;
            let prefetch = if error { field(msg[2], 11, 1) } else { 0 };
            [
                ACTION_PAGE_FAULT_RES_DESC,
                // PFR_VALID | PFR_SUCCESS | PFR_REPLY = PFR_ACCESS |
                // PFR_DESC_TYPE = FAULT_RESPONSE_DESC | PFR_ASID.
                1 | u32::from(error) << 1 | 1 << 10 | field(msg[1], 12, 20) << 12,
                field(msg[2], 4, 6)
                    | prefetch << 6
                    | field(msg[0], 19, 6) << 7
                    | field(msg[0], 25, 3) << 13
                    | pdata << 16,
            ]
        }
    }

    /// The outcome of one serviced fault: the service's result (the SVM range
    /// or VMA bounds Linux records as the ack hint) and the reply to the GuC.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ServicedFault {
        pub result: Result<(u64, u64), FsError>,
        pub reply: [u32; 3],
    }

    /// `xe_pagefault_service` once the producer's VM is known: a NACK is -EFAULT,
    /// a VM not in fault mode -EINVAL, a closed one -ENOENT, an address no VMA
    /// holds -EINVAL, and a write or atomic access to a read-only VMA -EPERM. A
    /// mirror VMA goes to `xe_svm_handle_pagefault` with the pages collected
    /// through `collector`; any other VMA is bound whole
    /// (`xe_pagefault_handle_vma`), so its mapping is returned. Returns the
    /// bounds Linux records as the ack hint.
    fn service_with<'a>(
        vm: &'a Vm,
        state: &State,
        fault: &PageFault,
        collector: impl FnOnce(&'a super::Svm) -> Result<Collector<'a>, FsError>,
    ) -> Result<(u64, u64, Option<VmMapping>), FsError> {
        if fault.fault_type_level == TYPE_LEVEL_NACK {
            return Err(FsError::BadAddress);
        }
        if !vm.fault {
            return Err(FsError::InvalidData);
        }
        vm.check()?;
        let address = fault.page_addr;
        let read = fault.access_type == ACCESS_READ;
        let mirror = vm
            .svm
            .as_ref()
            .and_then(|svm| Some((svm, svm.vma_at(address)?)));
        if let Some((svm, vma)) = mirror {
            if vma.read_only && !read {
                return Err(FsError::OperationNotPermitted);
            }
            // xe_vma_need_vram_for_atomic is 0 on an iGPU and -EACCES on a dGPU
            // for DRM_XE_ATOMIC_CPU; otherwise, without a pagemap,
            // `devmem_only` is false on a dGPU: an atomic fault collects system
            // pages like any other.
            if fault.atomic() {
                if svm.discrete && vma.attr.atomic == crate::intel_gpu_xe_vm::madvise::ATOMIC_CPU {
                    return Err(FsError::PermissionDenied);
                }
                if let Some(pagemap) = pagemap(1) {
                    match pagemap {}
                }
            }
            let (start, end) = svm.fault(vm, state, &vma, address, collector(svm)?)?;
            return Ok((start, end, None));
        }
        let mapping = state
            .mappings
            .iter()
            .find(|m| (m.va..m.va + m.length).contains(&address))
            .ok_or(FsError::InvalidData)?;
        if !mapping.writable && !read {
            return Err(FsError::OperationNotPermitted);
        }
        Ok((mapping.va, mapping.va + mapping.length, Some(mapping.clone())))
    }

    /// [`service_with`] from the VM creator's own syscall context.
    pub(crate) fn service(
        vm: &Vm,
        state: &State,
        fault: &PageFault,
        user: &dyn IoctlContext,
    ) -> Result<(u64, u64), FsError> {
        service_with(vm, state, fault, |_| Ok(Collector::Syscall(user)))
            .map(|(start, end, _)| (start, end))
    }

    /// [`service_with`] from the GPU page-fault service, collecting through
    /// the creator's grabbed address space: the bounds and the mappings the
    /// faulting jobs need (the range, or the whole VMA).
    pub(crate) fn service_remote(
        vm: &Vm,
        state: &State,
        fault: &PageFault,
    ) -> Result<(u64, u64, Vec<VmMapping>), FsError> {
        let (start, end, mapping) = service_with(vm, state, fault, super::Svm::remote)?;
        let mapping = match mapping {
            Some(mapping) => Some(mapping),
            None => vm
                .svm
                .as_ref()
                .and_then(|svm| svm.range_mapping(start)),
        };
        // A range invalidated again since it was collected is left out: the
        // GPU faults once more and the next service collects it again.
        Ok((start, end, mapping.into_iter().collect()))
    }
}
