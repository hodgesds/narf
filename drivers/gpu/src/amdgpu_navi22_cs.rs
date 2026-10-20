//! The Navi 22 card backend of the generic `AMDGPU_CS` / GEM / VA path:
//! an `amdgpu_cs::Submitter` over the cold boot's verified kernel queues
//! (`amdgpu_navi22_submit`), and the card's client VRAM heap
//! (`amdgpu_gem::register_vram_heap`).
//!
//! Clients' address spaces are the generic per-open `amdgpu_vm::VmState`
//! (GMC 11 layout, which GMC 10 shares; tables in system memory). Jobs run
//! on GFXHUB VMIDs 1–7, the contexts `amdgpu_gmc_navi22` lends for client
//! work (8–15 stay KFD's, as gmc_v10_0_sw_init sets `first_kfd_vmid` 8 and
//! amdgpu_vmid_mgr_init manages only VMIDs below it), granted per job by the
//! generic `amdgpu_vmid::VmidManager` as `amdgpu_vmid_grab` does with
//! concurrent flushes (every GC 10.3 part):
//!
//! - a job first needs some VMID with no unfinished job on any ring, or it
//!   waits (`amdgpu_vmid_grab_idle`), so one busy client cannot starve the
//!   others;
//! - it reuses the most recent VMID its own space used at the same root
//!   (`amdgpu_vmid_grab_used`) and flushes only when the space removed a
//!   mapping since that VMID's flush (`VmState::tlb_seq`) or that flush ran
//!   on another ring and has not completed; otherwise it takes the idle VMID
//!   and flushes;
//! - it rewrites the VMID's IH LUT entry (`gmc_v10_0_emit_pasid_mapping`)
//!   when the VMID last mapped another PASID or that write may not have run,
//!   so a fault's IV names the client's PASID and reaches its
//!   `AMDGPU_INFO_GPUVM_FAULT` (`amdgpu_vmid::record_fault`).
//!
//! A flush, or a job of another scheduler entity (`(VmState::owner, ctx)`),
//! makes the ring wait for its previous job first; consecutive jobs of one
//! entity pipeline. No `AMDGPU_VM_OP_RESERVE_VMID` (`grab_reserved`): there
//! is no SPM/debugger user.
//!
//! Tickets are `ring << 32 | sequence`; the ring index carries the GPU
//! recovery epoch above its four ring-id bits, so a ticket from before a
//! recovery names a ring no current queue has and reads as complete
//! (abandoned) instead of being compared with the new queues' sequences.
//!
//! A recovery registers a new submitter with a fresh manager, so every VMID
//! is flushed and remapped before its next use, as `amdgpu_vm_flush` does
//! after `amdgpu_vmid_had_gpu_reset`.
//!
//! VM programming has a dedicated writeback before client IBs. VMID reuse
//! waits for that writeback while active jobs retain their own final fences.
//! Per-ring FIFO admission parks later clients; the head waits for any fence
//! IRQ or its hard deadline, with per-future wakers and cancellation cleanup.
//! Dependencies wait in the ioctl (generic `dispatch_async`).
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_cp_navi22::FenceReader;
use crate::amdgpu_navi22_submit::{Ib, Ring, RingState, VmRef};
use crate::amdgpu_uapi as uapi;

const RINGS: [Option<Ring>; 10] = [
    Some(Ring::Gfx),
    Some(Ring::Compute),
    Some(Ring::Sdma(0)),
    Some(Ring::Sdma(1)),
    None,
    None,
    None,
    None,
    Some(Ring::Sdma(2)),
    Some(Ring::Sdma(3)),
];
fn fence_slot(id: usize) -> Option<usize> {
    match id {
        0..=3 => Some(id),
        8..=9 => Some(id - 4),
        _ => None,
    }
}
/// Bound on waiting out the per-ring throttle or for an idle VMID before
/// giving up with EBUSY.
const THROTTLE_NS: u64 = 10_000_000_000; // linux: n/a (NARF policy)

/// `amdgpu_ctx_get_entity` for this ASIC: gfx ring 0, compute rings 0–3 on
/// the one kernel compute queue, one entity per SDMA engine.
pub fn ring_id(ip_type: u32, ip_instance: u32, ring: u32) -> Option<usize> {
    match (ip_type, ip_instance, ring) {
        (uapi::AMDGPU_HW_IP_GFX, 0, 0) => Some(0),
        (uapi::AMDGPU_HW_IP_COMPUTE, 0, 0..=3) => Some(1),
        (uapi::AMDGPU_HW_IP_DMA, 0, r @ 0..=1) => Some(2 + r as usize),
        (uapi::AMDGPU_HW_IP_DMA, 0, r @ 2..=3) => Some(6 + r as usize),
        // VCN decode/encode and JPEG: ids 4..=7 (amdgpu_vcn_navi22_cs).
        _ => crate::amdgpu_vcn_navi22_cs::ring_id(ip_type, ip_instance, ring),
    }
}
/// Ticket ring ids: four original kernel queues, four media rings, SDMA2/3.
pub const RING_IDS: usize = 10; // linux: n/a (NARF ticket ring ids)
/// The ticket ring index of ring `id` in recovery epoch `epoch`.
pub const fn ring_index(epoch: u64, id: usize) -> u32 {
    ((epoch as u32 & 0x07ff_ffff) << 4) | id as u32
}
/// Whether `ticket` completed, given each ring's completed sequence in
/// `epoch`. Tickets of another epoch were abandoned by a recovery.
/// `completed` holds the first `N` ring ids' sequences (`RING_IDS` in
/// production); a ring beyond them has completed nothing.
pub fn job_done<const N: usize>(epoch: u64, completed: [u32; N], ticket: u64) -> bool {
    let index = (ticket >> 32) as u32;
    if index & !15 != ring_index(epoch, 0) {
        return true;
    }
    let done = completed.get((index & 15) as usize).copied().unwrap_or(0);
    crate::amdgpu_fence_navi22::signaled(done, ticket as u32)
}
/// The ring's scheduler entity for a job: Linux compares the entity's fence
/// context (`ring->current_ctx`), one per (open's VM, context) and ring. Low
/// 32 bits of the never-reused `VmState::owner` above the context id; 0 is
/// reserved for "none" and never produced (owners start at 1).
pub const fn entity(owner: u64, ctx_id: u32) -> u64 {
    owner << 32 | ctx_id as u64
}
/// The submission request `amdgpu_vmid_grab` decides on, for a job of `vm`
/// at root `pd_addr` on ticket ring `ring`.
pub fn grab_request(
    vm: &crate::amdgpu_vm::VmState,
    pd_addr: u64,
    pasid: crate::amdgpu_vmid::Pasid,
    ring: u32,
) -> crate::amdgpu_vmid::GrabRequest {
    crate::amdgpu_vmid::GrabRequest {
        owner: vm.owner(),
        pd_addr,
        tlb_seq: vm.tlb_seq(),
        pasid,
        ring,
    }
}
/// The ring-side VM state of a job granted `grant`.
pub fn vm_ref(
    request: &crate::amdgpu_vmid::GrabRequest,
    grant: crate::amdgpu_vmid::Grant,
) -> VmRef {
    VmRef {
        vmid: grant.vmid,
        page_table_base: request.pd_addr,
        pasid: request.pasid,
        flush: grant.needs_flush,
        map_pasid: grant.map_pasid,
    }
}
/// A fresh manager over the client VMIDs `amdgpu_gmc_navi22` lent.
pub fn vmid_manager(
    lent: &crate::amdgpu_gmc_navi22::ClientVmids,
) -> crate::amdgpu_vmid::VmidManager {
    let (first, last) = lent.range();
    crate::amdgpu_vmid::VmidManager::new(first, last)
}

/// The Navi 22 queues behind `AMDGPU_CS` on DRM card `card`.
#[derive(Debug)]
pub struct Submitter {
    card: u32,
    epoch: u64,
    reader: FenceReader,
    /// GFXHUB client VMIDs (gfx, compute and both SDMA engines all
    /// translate through GFXHUB on GC 10.3). Touched only under the
    /// platform owner, beside the submission it grants.
    vmids: IrqSafeSpinLock<crate::amdgpu_vmid::VmidManager>,
    rings: IrqSafeSpinLock<[RingState; RING_IDS]>,
    admission: [crate::amdgpu_admission::Queue; RING_IDS],
}

impl Submitter {
    fn vm_progress(&self) -> Option<[u32; RING_IDS]> {
        let mut completed = [0; RING_IDS];
        for (id, value) in completed.iter_mut().enumerate() {
            if let Some(slot) = fence_slot(id).filter(|&slot| self.reader.present(slot)) {
                *value = self.reader.vm_completed(slot).ok()?;
            }
        }
        Some(completed)
    }
    /// Every ring's completed sequence, retiring what completed jobs held
    /// and writing their user fences. None when the device stopped answering.
    fn progress(&self) -> Option<[u32; RING_IDS]> {
        if self.epoch != crate::amdgpu_fence_navi22::generation() {
            return None;
        }
        let mut completed = [0; RING_IDS];
        for (i, c) in completed.iter_mut().enumerate() {
            *c = if let Some(slot) = fence_slot(i) {
                if self.reader.present(slot) {
                    self.reader.completed(slot).ok()?
                } else {
                    0
                }
            } else {
                crate::amdgpu_vcn_navi22_cs::completed(i - crate::amdgpu_vcn_navi22_cs::FIRST_ID)
                    .ok()?
            };
        }
        let epoch = self.epoch;
        crate::amdgpu_cs::retire(self.card, &|t| job_done(epoch, completed, t));
        Some(completed)
    }
    async fn wait_for(&self, ticket: u64, deadline_ns: u64) -> Result<bool, FsError> {
        loop {
            let observed = crate::amdgpu_fence_navi22::change_sequence();
            let completed = self.progress().ok_or(FsError::NoDevice)?;
            if job_done(self.epoch, completed, ticket) {
                return Ok(true);
            }
            if narf_time::monotonic_ns() >= deadline_ns {
                return Ok(false);
            }
            crate::amdgpu_fence_navi22::wait_change(observed, deadline_ns).await;
        }
    }
}

impl crate::amdgpu_cs::Submitter for Submitter {
    fn ring_for(&self, ip_type: u32, ip_instance: u32, ring: u32) -> Option<u32> {
        ring_id(ip_type, ip_instance, ring)
            .filter(|id| fence_slot(*id).is_none_or(|slot| self.reader.present(slot)))
            .map(|id| ring_index(self.epoch, id))
    }
    fn signalled(&self, ticket: u64) -> bool {
        // A vanished device makes no more progress; report done so waiters
        // cannot wedge.
        self.progress()
            .is_none_or(|completed| job_done(self.epoch, completed, ticket))
    }
    fn submit<'a>(
        &'a self,
        vm: &'a crate::amdgpu_vm::VmState,
        submission: &'a crate::amdgpu_cs::Submission,
        _health: &'a alloc::sync::Arc<crate::amdgpu_ctx::Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        Box::pin(async move {
            let first = submission.ibs.first().ok_or(FsError::InvalidData)?;
            let id = ring_id(first.ip_type, first.ip_instance, first.ring)
                .ok_or(FsError::InvalidData)?;
            // One job runs on one ring (amdgpu_cs_pass1's entity check).
            if submission
                .ibs
                .iter()
                .any(|ib| ring_id(ib.ip_type, ib.ip_instance, ib.ring) != Some(id))
            {
                return Err(FsError::InvalidData);
            }
            if submission
                .ibs
                .iter()
                .any(|ib| ib.flags & (uapi::AMDGPU_IB_FLAGS_SECURE | uapi::AMDGPU_IB_FLAG_CE) != 0)
            {
                // No TMZ and no CE IBs on GC 10.3.
                return Err(FsError::InvalidData);
            }
            if vm.geometry() != crate::amdgpu_vm::Geometry::GMC11 {
                return Err(FsError::InvalidData);
            }
            let ibs: Vec<Ib> = submission
                .ibs
                .iter()
                .map(|ib| Ib {
                    va: ib.va_start,
                    dwords: ib.length_dw,
                })
                .collect();
            let page_table_base = vm.root_pde().ok_or(FsError::InvalidData)?;
            let pasid = vm.pasid().ok_or(FsError::NoSpace)?;
            let index = ring_index(self.epoch, id);
            let request = grab_request(vm, page_table_base, pasid, index);
            let context = entity(request.owner, submission.ctx_id);
            let deadline = narf_time::monotonic_ns().saturating_add(THROTTLE_NS);
            let mut admission = core::pin::pin!(self.admission[id].enter());
            let mut timeout = core::pin::pin!(narf_time::SleepUntil::new(
                narf_time::Deadline::after_ns(THROTTLE_NS).as_instant()
            ));
            let _permit = core::future::poll_fn(|cx| {
                if let core::task::Poll::Ready(permit) = admission.as_mut().poll(cx) {
                    return core::task::Poll::Ready(Ok(permit));
                }
                if timeout.as_mut().poll(cx).is_ready() {
                    return core::task::Poll::Ready(Err(FsError::Busy));
                }
                core::task::Poll::Pending
            })
            .await?;
            if (crate::amdgpu_vcn_navi22_cs::FIRST_ID..8).contains(&id) {
                // VCN/JPEG: MMHUB VMIDs of their own (amdgpu_vcn_navi22_cs).
                let progress = || self.progress();
                let seq = crate::amdgpu_vcn_navi22_cs::submit(
                    vm, submission, request, self.epoch, &progress,
                )
                .await?;
                let _ = self.progress();
                return Ok(u64::from(index) << 32 | u64::from(seq));
            }
            let ring = RINGS[id].ok_or(FsError::InvalidData)?;
            if !fence_slot(id).is_some_and(|slot| self.reader.present(slot)) {
                return Err(FsError::InvalidData);
            }
            let seq = loop {
                let observed = crate::amdgpu_fence_navi22::change_sequence();
                let throttle = {
                    let mut owner = crate::amdgpu_navi22_platform::owner().await;
                    let boot = owner.as_mut().ok_or(FsError::NoDevice)?;
                    let completed = self.progress().ok_or(FsError::NoDevice)?;
                    let vm_completed = self.vm_progress().ok_or(FsError::NoDevice)?;
                    let epoch = self.epoch;
                    let done = |t| {
                        if t & (1 << 63) != 0 {
                            job_done(epoch, vm_completed, t & !(1 << 63))
                        } else {
                            job_done(epoch, completed, t)
                        }
                    };
                    let grant = self.vmids.lock().grab(request, &done);
                    let Some(grant) = grant else {
                        // amdgpu_vmid_grab_idle: every client VMID still has
                        // an unfinished job; wait without the owner.
                        drop(owner);
                        if narf_time::monotonic_ns() >= deadline {
                            return Err(FsError::Busy);
                        }
                        crate::amdgpu_fence_navi22::wait_change(observed, deadline).await;
                        continue;
                    };
                    let result = {
                        let mut rings = self.rings.lock();
                        boot.submit(ring, &mut rings[id], vm_ref(&request, grant), context, &ibs)
                    };
                    match result {
                        Ok(seq) => {
                            let ticket = u64::from(index) << 32 | u64::from(seq);
                            self.vmids.lock().commit_with_flush(
                                request,
                                grant,
                                ticket,
                                ticket | (1 << 63),
                            );
                            break seq;
                        }
                        Err(crate::amdgpu_navi22_boot::Error::Queues(
                            crate::amdgpu_cp_navi22::Error::Busy,
                        )) => boot.fences(ring).map_err(|_| FsError::NoDevice)?.1,
                        Err(crate::amdgpu_navi22_boot::Error::Queues(
                            crate::amdgpu_cp_navi22::Error::Invalid,
                        )) => return Err(FsError::InvalidData),
                        Err(_) => return Err(FsError::NoDevice),
                    }
                };
                // Two jobs in flight: wait for the older without the owner.
                let oldest = u64::from(index) << 32 | u64::from(throttle);
                if !self.wait_for(oldest, deadline).await? {
                    return Err(FsError::Busy);
                }
            };
            let _ = self.progress();
            Ok(u64::from(index) << 32 | u64::from(seq))
        })
    }
    fn wait(
        &self,
        ticket: u64,
        deadline_ns: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        Box::pin(async move { self.wait_for(ticket, deadline_ns).await })
    }
}

/// The client VRAM chunk, retained across recoveries (it is published, so no
/// later owner recycles it), with the heap it backs.
static CLIENT_VRAM: IrqSafeSpinLock<
    Option<(crate::amdgpu_vram::Reservation, crate::amdgpu_gem::VramHeap)>,
> = IrqSafeSpinLock::new(None);
/// The client VMIDs lent by the memory owner, kept for its lifetime.
static CLIENT_VMIDS: IrqSafeSpinLock<Option<crate::amdgpu_gmc_navi22::ClientVmids>> =
    IrqSafeSpinLock::new(None);

/// The DRM card index of the bound Navi 22.
pub fn drm_card() -> Option<u32> {
    (0..crate::drm_registry::count() as u32).find(|&i| {
        crate::drm_registry::driver_name(i) == Some("amdgpu")
            && crate::drm_registry::pci_id(i)
                .is_some_and(|(vid, did)| crate::amdgpu_rdna2::for_pci_id(vid, did).is_some())
    })
}

/// Let the card's clients submit on `boot`'s verified queues and place
/// buffers in VRAM. Called with the platform owner held, after a cold boot or
/// recovery whose ring/IB tests passed. Failures are reported, never fatal.
pub async fn register(boot: &mut crate::amdgpu_navi22_boot::ColdBoot) {
    use core::fmt::Write;
    let Some(card) = drm_card() else {
        return;
    };
    let Some(reader) = boot.client_fence_reader() else {
        return;
    };
    let hidden_ready =
        boot.unmapped_pool().is_some() && crate::amdgpu_rdna2_vram::publish(card, boot).is_ok();
    let lent = match boot.reserve_client_vmids() {
        Ok(lent) => lent,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 no client VMIDs: {error:?}"
            );
            return;
        }
    };
    let vmids = vmid_manager(&lent);
    let (first, last) = lent.range();
    *CLIENT_VMIDS.lock() = Some(lent);
    {
        let mut client = CLIENT_VRAM.lock();
        if client.is_none() {
            match boot.reserve_client_vram() {
                Ok(heap) => *client = Some(heap),
                Err(error) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi22 no client VRAM heap: {error:?}"
                    );
                }
            }
        }
        if let Some((chunk, heap)) = client.as_mut() {
            if hidden_ready && heap.unmapped.is_none() {
                heap.unmapped = boot
                    .unmapped_pool()
                    .map(|pool| crate::amdgpu_gem::UnmappedHeap {
                        pool,
                        clear: crate::amdgpu_rdna2_vram::clearer(),
                        transfer: Some(crate::amdgpu_rdna2_vram::reader(card)),
                    });
            }
            crate::amdgpu_gem::register_vram_heap(card, heap.clone());
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 client VRAM heap {} MiB, VMIDs {first}-{last}",
                chunk.size() >> 20
            );
        }
    }
    crate::amdgpu_vcn_navi22_cs::register(boot, first, last);
    crate::amdgpu_cs::register_submitter(
        card,
        Arc::new(Submitter {
            card,
            // The fence generation advances during quiesce, before restart
            // registers this submitter. The recovery counter advances later.
            epoch: crate::amdgpu_fence_navi22::generation(),
            reader,
            vmids: IrqSafeSpinLock::new(vmids),
            rings: IrqSafeSpinLock::new([RingState::new(); RING_IDS]),
            admission: [const { crate::amdgpu_admission::Queue::new() }; RING_IDS],
        }),
    );
    // A recovery also replays the still-unsignalled front clear. The queue's
    // pulse closes the race with a drain noticing the old fence generation.
    crate::amdgpu_rdna2_vram::engine().kick();
}

/// Stop accepting client work (recovery is about to rebuild the owner). The
/// lent VMIDs belonged to the old memory owner and are dropped with it; the
/// next `register` starts a fresh manager (every VMID flushes again).
pub fn unregister() {
    crate::amdgpu_rdna2_vram::suspend();
    if let Some(card) = drm_card() {
        crate::amdgpu_cs::unregister_submitter(card);
        crate::amdgpu_gem::unregister_vram_heap(card);
    }
    crate::amdgpu_vcn_navi22_cs::unregister();
    // Its owner is being replaced; the handle must not reach the new one.
    let _ = CLIENT_VMIDS.lock().take();
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi22_cs_tickets_name_ring_and_recovery_epoch() -> TestResult {
        let entities = [
            (ring_id(uapi::AMDGPU_HW_IP_GFX, 0, 0), Some(0)),
            (ring_id(uapi::AMDGPU_HW_IP_GFX, 0, 1), None),
            (ring_id(uapi::AMDGPU_HW_IP_COMPUTE, 0, 3), Some(1)),
            (ring_id(uapi::AMDGPU_HW_IP_COMPUTE, 0, 4), None),
            (ring_id(uapi::AMDGPU_HW_IP_DMA, 0, 1), Some(3)),
            (ring_id(uapi::AMDGPU_HW_IP_DMA, 0, 2), Some(8)),
            (ring_id(uapi::AMDGPU_HW_IP_DMA, 0, 3), Some(9)),
            (ring_id(uapi::AMDGPU_HW_IP_DMA, 0, 4), None),
            (ring_id(uapi::AMDGPU_HW_IP_DMA, 1, 0), None),
            (ring_id(uapi::AMDGPU_HW_IP_VCN_DEC, 0, 0), None),
        ];
        if entities.iter().any(|(got, want)| got != want) {
            return TestResult::Fail("amdgpu_ctx_get_entity mapping");
        }
        let ticket = |epoch, id, seq: u32| u64::from(ring_index(epoch, id)) << 32 | u64::from(seq);
        let done = [10, 0, 7, u32::MAX, 0, 0, 0, 0];
        let cases = [
            (job_done(0, done, ticket(0, 0, 10)), true),
            (job_done(0, done, ticket(0, 0, 11)), false),
            (job_done(0, done, ticket(0, 2, 7)), true),
            // Wrap: 1 after u32::MAX is not yet done.
            (job_done(0, done, ticket(0, 3, 1)), false),
            // A ticket of an earlier epoch was abandoned by recovery.
            (job_done(1, done, ticket(0, 0, 11)), true),
            (job_done(256, done, ticket(0, 0, 11)), true),
        ];
        if cases.iter().any(|(got, want)| got != want) {
            return TestResult::Fail("ticket completion or epoch abandonment");
        }
        // The generic VmState's ring slot (`ticket >> 32 % 16`) is the ring id.
        if (ring_index(5, 3) % 16) != 3 || (ring_index(5, 7) % 16) != 7 {
            return TestResult::Fail("epoch tag leaked into the ring slot");
        }
        for epoch in [0, 1, 5, 255, 256, 65536] {
            let mut completed = [0; RING_IDS];
            completed[8] = 12;
            completed[9] = 3;
            if ring_index(epoch, 8) % 16 != 8
                || ring_index(epoch, 9) % 16 != 9
                || !job_done(epoch, completed, ticket(epoch, 8, 12))
                || job_done(epoch, completed, ticket(epoch, 9, 4))
                || job_done(epoch, completed, ticket(epoch, 0, 12))
                || !job_done(epoch + 1, completed, ticket(epoch, 9, 4))
            {
                return TestResult::Fail("SDMA2/3 ticket aliases another ring or epoch");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_cs_tickets_name_ring_and_recovery_epoch
    );
}
