//! Xe USM device state (`xe->usm`) behind `narf.intel.svm=1`: address-space
//! IDs, the GPU page-fault queue between the GuC producer and the fault
//! service, and the resolutions the GT owner applies to running jobs. MIT
//! Linux 7.4-rc4: `xe_vm.c` (`xe_vm_create`'s `usm.asid`,
//! `xe_vm_close_and_put`), `xe_device.c` (`xe_device_asid_to_vm`),
//! `xe_pagefault.c` (`xe_pagefault_queue_init`, `xe_pagefault_handler`,
//! `xe_pagefault_queue_work`, `xe_pagefault_service`), `xe_guc_pagefault.c`
//! and `xe_guc_tlb_inval.c` (`send_tlb_inval_ppgtt`,
//! `normalize_invalidation_range`).
//!
//! # The NARF model
//!
//! - **ASIDs.** Linux gives every userspace VM of a `has_asid` device an
//!   ASID from `xe->usm.asid_to_vm` (`xa_alloc_cyclic` over
//!   `[1, XE_MAX_ASID - 1]`) and writes it to `CTX_ASID` of every LRC of the
//!   VM's queues (`xe_lrc_init`). NARF does the same for the VMs of a device
//!   whose backend publishes [`Usm`] (`narf.intel.svm=1` on a USM device:
//!   `has_asid` and `has_usm` are both `XE2_GFX_FEATURES`), and writes the
//!   ASID into each job's LRC (`ResidentBatch::asid`). The ASID is erased
//!   at VM_DESTROY or when the VM is dropped, as `xe_vm_close_and_put` does.
//! - **Faults to the service.** The GuC scheduler of the primary GT decodes
//!   `XE_GUC_ACTION_REPORT_PAGE_FAULT_REQ_DESC` and queues it here
//!   (`xe_pagefault_handler`; a full queue is `-ENOSPC`, which Linux's CT
//!   treats as a dead channel and NARF as a lost GT). One service task
//!   (`xe_pagefault_queue_work` with `num_pf_work` 1) looks the ASID up,
//!   takes the VM state and services the fault (`xe_pagefault_service`),
//!   collecting mirror pages through the VM creator's grabbed address space
//!   ([`narf_filesystem::RemoteMm`], Linux `gpusvm->mm`). Its result is the
//!   mappings the faulting address needs, handed back to the GT owner.
//! - **Running jobs, not one VM table.** Linux rebinds the range or VMA into
//!   the VM's single page table and the GPU retries. A NARF job runs on
//!   private tables built at EXEC, so the GT owner writes the mappings into
//!   the tables of every job it holds for that ASID
//!   (`ResidentBatch::fault_map`), retaining their pages until the job
//!   retires, invalidates the GPU TLB for the range (`send_tlb_inval_ppgtt`,
//!   page-selective by ASID) and only then answers the GuC
//!   (`guc_ack_fault`). A failed service answers at once.
//! - **Not delivered by firmware yet.** The GuC reports recoverable faults
//!   only through the UM queues of `guc_um_init_params` (`xe_guc_ads.c`),
//!   which need 192 KiB of DMA-contiguous memory (`guc_ads_init` checks
//!   `xe_bo_sg_is_contiguous`; the iGPU rounds it to 256 KiB). NARF's GuC
//!   arena hands out discontiguous host frames, so its ADS has no
//!   `um_init_data` and no hardware fault reaches this queue: every path
//!   below runs, and is checked, against the native GuC model.
use crate::intel_gpu_exec::VmMapping;
use crate::intel_gpu_xe_vm::{
    svm::{self, guc::PageFault},
    Vm,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

/// `XE_MAX_ASID` (`xe_device_types.h`): `BIT(20)`.
pub(crate) const MAX_ASID: u32 = 1 << 20;
/// `XE_NUM_HW_ENGINES` (`xe_hw_engine_types.h`): RCS0, BCS0-8, VCS0-7,
/// VECS0-3, CCS0-3 and GSCCS0.
pub(crate) const NUM_HW_ENGINES: usize = 27;
/// `PF_MULTIPLIER` (`xe_pagefault_queue_init`).
const PF_MULTIPLIER: usize = 8;

/// `xe_pagefault_queue_init` with `xe_pagefault_queue_full`: the queue is
/// `roundup_pow_of_two((total_num_eus + XE_NUM_HW_ENGINES) * entry_size *
/// PF_MULTIPLIER)` bytes of power-of-two entries, and it is full while one
/// entry's space is left, so it holds one entry fewer than it has slots.
pub(crate) fn queue_capacity(total_eus: usize) -> usize {
    ((total_eus + NUM_HW_ENGINES) * PF_MULTIPLIER).next_power_of_two() - 1
}

/// The device's USM state: published by its backend under
/// `narf.intel.svm=1` and only on a USM device (`xe->info.has_asid` and
/// `has_usm` are both `XE2_GFX_FEATURES`).
pub(crate) fn for_device(info: &crate::intel_gpu_render::DeviceInfo) -> Option<Arc<Usm>> {
    info.backend
        .as_ref()
        .and_then(|backend| backend.usm())
        .filter(|_| svm::has_usm(info.platform))
}

/// The `PAGE_FAULT_RES_DESC` dwords for a fault the service answered.
pub(crate) type Reply = [u32; 2];

/// One serviced fault for the GT owner: the faults it answers (the serviced
/// one, then any the service's cache matched), the ASID whose jobs need the
/// mappings, and the service's result. `Ok` with no mappings is a fault the
/// running jobs already map.
#[derive(Debug)]
pub(crate) struct Resolution {
    pub faults: Vec<PageFault>,
    pub asid: u32,
    pub result: Result<Vec<VmMapping>, FsError>,
}

impl Resolution {
    /// `guc_ack_fault` for every fault this resolution answers.
    pub(crate) fn replies(&self, error: bool) -> impl Iterator<Item = Reply> + '_ {
        self.faults.iter().map(move |fault| {
            let [_, dw0, dw1] = fault.guc_reply(error);
            [dw0, dw1]
        })
    }
}

#[derive(Debug, Default)]
struct Asids {
    vms: BTreeMap<u32, Weak<Vm>>,
    /// `xe->usm.next_asid`.
    next: u32,
}

impl Asids {
    /// The lowest free index in `[min, max]` (`__xa_alloc` over `limit`).
    fn free_in(&self, min: u32, max: u32) -> Option<u32> {
        if min > max {
            return None;
        }
        let mut candidate = min;
        for &taken in self.vms.range(min..=max).map(|(id, _)| id) {
            if taken != candidate {
                break;
            }
            candidate = taken.checked_add(1)?;
        }
        (candidate <= max).then_some(candidate)
    }
}

#[derive(Debug, Default)]
struct Queue {
    /// Faults the queue holds (`queue_capacity`); 0 until the GT owner that
    /// produces them has read its topology.
    capacity: usize,
    faults: VecDeque<PageFault>,
    resolved: VecDeque<Resolution>,
    waker: Option<Waker>,
}

/// `xe->usm` of one device.
#[derive(Debug)]
pub struct Usm {
    asids: IrqSafeSpinLock<Asids>,
    queue: IrqSafeSpinLock<Queue>,
}

/// A VM's ASID (`vm->usm.asid`). Dropping it erases the ASID from the device
/// (`xe_vm_close_and_put`).
#[derive(Debug)]
pub struct Asid {
    id: u32,
    usm: Weak<Usm>,
}

impl Asid {
    pub(crate) fn id(&self) -> u32 {
        self.id
    }
}

impl Drop for Asid {
    fn drop(&mut self) {
        if let Some(usm) = self.usm.upgrade() {
            usm.asids.lock().vms.remove(&self.id);
        }
    }
}

impl Usm {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            asids: IrqSafeSpinLock::new(Asids::default()),
            queue: IrqSafeSpinLock::new(Queue::default()),
        })
    }

    /// `xa_alloc_cyclic(&xe->usm.asid_to_vm, &asid, vm, XA_LIMIT(1,
    /// XE_MAX_ASID - 1), &xe->usm.next_asid, GFP_NOWAIT)`: the lowest free
    /// ASID from `next_asid`, else from 1; `-EBUSY` when all are taken.
    pub(crate) fn alloc_asid(self: &Arc<Self>, vm: &Arc<Vm>) -> Result<Asid, FsError> {
        let mut asids = self.asids.lock();
        let id = asids
            .free_in(asids.next.max(1), MAX_ASID - 1)
            .or_else(|| asids.free_in(1, MAX_ASID - 1))
            .ok_or(FsError::Busy)?;
        asids.vms.insert(id, Arc::downgrade(vm));
        asids.next = id + 1;
        Ok(Asid {
            id,
            usm: Arc::downgrade(self),
        })
    }

    /// Move `xe->usm.next_asid`, as `xe_device_create` does under
    /// `CONFIG_DRM_XE_DEBUG` to force an early wrap.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn set_next_asid(&self, next: u32) {
        self.asids.lock().next = next;
    }

    /// `xe_device_asid_to_vm`: the live VM holding `asid`.
    pub(crate) fn asid_to_vm(&self, asid: u32) -> Option<Arc<Vm>> {
        self.asids.lock().vms.get(&asid).and_then(Weak::upgrade)
    }

    /// Size the fault queue for a GT with `total_eus` EUs
    /// (`xe_pagefault_queue_init`), reserving it so the producer never
    /// allocates.
    pub(crate) fn size_queue(&self, total_eus: usize) -> Result<(), FsError> {
        let capacity = queue_capacity(total_eus);
        let mut queue = self.queue.lock();
        let more = capacity.saturating_sub(queue.faults.len());
        queue
            .faults
            .try_reserve(more)
            .map_err(|_| FsError::OutOfMemory)?;
        queue.capacity = queue.capacity.max(capacity);
        Ok(())
    }

    /// `xe_pagefault_handler`: queue `fault` for the service; `-ENOSPC` when
    /// the queue is full.
    pub(crate) fn push(&self, fault: PageFault) -> Result<(), FsError> {
        let waker = {
            let mut queue = self.queue.lock();
            if queue.faults.len() >= queue.capacity {
                return Err(FsError::NoSpace);
            }
            queue.faults.push_back(fault);
            queue.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    fn pop(&self) -> Option<PageFault> {
        self.queue.lock().faults.pop_front()
    }

    /// The faults waiting for the service.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn queued(&self) -> usize {
        self.queue.lock().faults.len()
    }

    fn resolve(&self, resolution: Resolution) {
        self.queue.lock().resolved.push_back(resolution);
    }

    /// The next serviced fault for the GT owner.
    pub(crate) fn pop_resolved(&self) -> Option<Resolution> {
        self.queue.lock().resolved.pop_front()
    }

    /// Wait until a fault is queued.
    fn queued_fault(&self) -> QueuedFault<'_> {
        QueuedFault(self)
    }

    /// `xe_pagefault_queue_work` until the queue is empty. A fault inside the
    /// last successfully serviced range of the same ASID is answered with that
    /// range's mappings without servicing it again ("Last fault same address,
    /// ack immediately"); a failed fault that is not a prefetch clears that
    /// cache (`xe_pagefault_cache_start_invalidate`).
    pub(crate) async fn drain(&self) {
        let mut cache: Option<(u64, u64, u32, Vec<VmMapping>)> = None;
        while let Some(fault) = self.pop() {
            let hit = cache
                .as_ref()
                .filter(|(start, end, asid, _)| {
                    (*start..*end).contains(&fault.page_addr) && *asid == fault.asid
                })
                .map(|(_, _, _, mappings)| mappings.clone());
            let result = if let Some(mappings) = hit {
                Ok(mappings)
            } else {
                match self.service(&fault).await {
                    Ok((start, end, mappings)) => {
                        cache = Some((start, end, fault.asid, mappings.clone()));
                        Ok(mappings)
                    }
                    Err(error) => {
                        if fault.access_type & svm::guc::ACCESS_PREFETCH == 0 {
                            cache = None;
                        }
                        Err(error)
                    }
                }
            };
            self.resolve(Resolution {
                faults: alloc::vec![fault],
                asid: fault.asid,
                result,
            });
        }
    }

    /// `xe_pagefault_service`: a NACK is `-EFAULT`; an ASID no VM holds, or
    /// a VM not in fault mode, `-EINVAL`; then the VM's own service under its
    /// state. Returns the bounds Linux caches and the mappings to install.
    async fn service(&self, fault: &PageFault) -> Result<(u64, u64, Vec<VmMapping>), FsError> {
        if fault.fault_type_level == svm::guc::TYPE_LEVEL_NACK {
            return Err(FsError::BadAddress);
        }
        let vm = self
            .asid_to_vm(fault.asid)
            .filter(|vm| vm.fault)
            .ok_or(FsError::InvalidData)?;
        let state = vm.state.lock().await;
        svm::guc::service_remote(&vm, &state, fault)
    }
}

struct QueuedFault<'a>(&'a Usm);

impl Future for QueuedFault<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut queue = self.0.queue.lock();
        if queue.faults.is_empty() {
            queue.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

/// The device's page-fault service task (`xe->usm.pagefault_wq` with one
/// worker): drain the queue whenever a fault arrives, until the device's
/// [`Usm`] is gone.
pub(crate) async fn serve(usm: Weak<Usm>) {
    loop {
        let Some(usm) = usm.upgrade() else {
            return;
        };
        usm.queued_fault().await;
        usm.drain().await;
    }
}

// ── GuC TLB invalidation of a PPGTT range (xe_guc_tlb_inval.c) ──────────

/// `XE_GUC_TLB_INVAL_PAGE_SELECTIVE` with `XE_GUC_TLB_INVAL_MODE_HEAVY` and
/// `XE_GUC_TLB_INVAL_FLUSH_CACHE` (`MAKE_INVAL_OP`).
pub(crate) const OP_PAGE_SELECTIVE: u32 = 0x8000_0001;
/// `MAKE_INVAL_OP(XE_GUC_TLB_INVAL_FULL)`.
pub(crate) const OP_FULL: u32 = 0x8000_0000;

/// `normalize_invalidation_range`: the power-of-two, naturally aligned
/// window covering `[start, end)`, at least 4 KiB, and 16 MiB or more once it
/// reaches 2 MiB. Returns `(start, length)`.
pub(crate) fn normalize_invalidation_range(start: u64, end: u64) -> (u64, u64) {
    let orig_start = start;
    let mut length = (end - start).max(4096);
    let align = length.next_power_of_two();
    let mut start = start & !(align - 1);
    let end = (end + align - 1) & !(align - 1);
    length = align;
    while start + length < end {
        length <<= 1;
        start = orig_start & !(length - 1);
    }
    if length >= 2 << 20 {
        length = length.max(16 << 20);
        start = orig_start & !(length - 1);
    }
    (start, length)
}

/// `send_tlb_inval_ppgtt` for `XE_GUC_TLB_INVAL_PAGE_SELECTIVE` (no Xe2 or
/// Xe3 platform sets `has_ctx_tlb_inval`; all set `has_range_tlb_inval`) with
/// no page-reclaim list: the `XE_GUC_ACTION_TLB_INVALIDATION` payload after
/// the action dword. A range past `MAX_RANGE_TLB_INVALIDATION_LENGTH`
/// (`rounddown_pow_of_two(ULONG_MAX)`) is a full invalidation.
pub(crate) fn ppgtt_invalidation(seqno: u32, asid: u32, start: u64, end: u64) -> Vec<u32> {
    if end - start > 1 << 63 {
        return alloc::vec![seqno, OP_FULL];
    }
    let (start, length) = normalize_invalidation_range(start, end);
    alloc::vec![
        seqno,
        OP_PAGE_SELECTIVE,
        asid,
        start as u32,
        (start >> 32) as u32,
        length.trailing_zeros() - 12,
    ]
}
