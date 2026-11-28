//! CPU VA updates must preserve translations until every prior VM job retires,
//! as Linux's amdgpu_vm_clear_freed + amdgpu_vm_cpu_prepare do.
use super::*;
use alloc::boxed::Box;
use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

const VA: u64 = 0xffff_8001_0236_5000;
const CMD: u32 = 0xc028_6400 | (drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_VA);
const JOBS: [u64; 2] = [1, (1 << 32) | 1];

#[derive(Default)]
struct Engine {
    completed: AtomicU32,
    failed: AtomicBool,
    expired: AtomicBool,
}
impl crate::amdgpu_cs::Submitter for Engine {
    fn submit<'a>(
        &'a self,
        _: &'a VmState,
        _: &'a crate::amdgpu_cs::Submission,
        _: &'a Arc<crate::amdgpu_ctx::Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn signalled(&self, ticket: u64) -> bool {
        self.retired(ticket) || self.failed.load(Ordering::Acquire)
    }
    fn retired(&self, ticket: u64) -> bool {
        self.completed.load(Ordering::Acquire) & (1 << (ticket >> 32)) != 0
    }
    fn error(&self, _: u64) -> Option<FsError> {
        self.failed
            .load(Ordering::Acquire)
            .then_some(FsError::TimedOut)
    }
    fn ring_for(&self, _: u32, _: u32, ring: u32) -> Option<u32> {
        (ring < 2).then_some(ring)
    }
    fn wait(
        &self,
        ticket: u64,
        _: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        Box::pin(poll_fn(move |cx| {
            if self.retired(ticket) {
                Poll::Ready(Ok(true))
            } else if let Some(error) = self.error(ticket) {
                Poll::Ready(Err(error))
            } else if self.expired.load(Ordering::Acquire) {
                Poll::Ready(Ok(false))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }))
    }
}

struct Registered(u32);
impl Drop for Registered {
    fn drop(&mut self) {
        crate::amdgpu_cs::unregister_submitter(self.0);
        // No hardware exists in this fixture; all its synthetic jobs end here.
        crate::amdgpu_cs::retire(self.0, &|_| true);
    }
}

fn request(operation: u32, handle: u32, flags: u32, va: u64) -> [u8; 40] {
    let mut bytes = [0; 40];
    bytes[..4].copy_from_slice(&handle.to_le_bytes());
    bytes[8..12].copy_from_slice(&operation.to_le_bytes());
    bytes[12..16].copy_from_slice(&flags.to_le_bytes());
    bytes[16..24].copy_from_slice(&va.to_le_bytes());
    bytes[32..40].copy_from_slice(&4096u64.to_le_bytes());
    bytes
}

fn mapped(card: u32) -> (VmState, crate::amdgpu_gem::GemState, u32) {
    let vm = VmState::for_card(card);
    let gem = crate::amdgpu_gem::GemState::new();
    let mut create = [0u8; 32];
    create[..8].copy_from_slice(&4096u64.to_le_bytes());
    create[16..24].copy_from_slice(&u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT).to_le_bytes());
    crate::amdgpu_gem::dispatch(
        0xc020_6400 | (drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_CREATE),
        create.as_mut_ptr() as usize,
        &gem,
    )
    .unwrap();
    let handle = u32::from_le_bytes(create[..4].try_into().unwrap());
    let req = request(uapi::AMDGPU_VA_OP_MAP, handle, 0x0e, VA);
    dispatch(CMD, req.as_ptr() as usize, &vm, &gem, None).unwrap();
    for ticket in JOBS {
        vm.note_job(ticket);
    }
    (vm, gem, handle)
}

fn va_edits_wait_for_all_jobs_and_cancel_without_mutation() -> TestResult {
    const CARD: u32 = 0xfeed_0460;
    let _registered = Registered(CARD);
    for (operation, flags) in [
        (uapi::AMDGPU_VA_OP_UNMAP, 0),
        (uapi::AMDGPU_VA_OP_CLEAR, 0),
        (uapi::AMDGPU_VA_OP_REPLACE, uapi::AMDGPU_VM_PAGE_READABLE),
        (uapi::AMDGPU_VA_OP_REPLACE, uapi::AMDGPU_VM_PAGE_PRT),
    ] {
        let engine = Arc::new(Engine::default());
        crate::amdgpu_cs::register_submitter(CARD, engine.clone());
        let (vm, gem, handle) = mapped(CARD);
        let mut req = request(operation, handle, flags, VA);
        let address = req.as_ptr() as usize;
        let before = vm.leaf_entry(strip_hole(VA));
        assert!(before.is_some_and(|pte| pte & PTE_VALID != 0));
        let sequence = vm.tlb_seq.load(Ordering::Acquire);
        assert_eq!(dispatch(CMD, address, &vm, &gem, None), Err(FsError::Busy));
        let mut cx = Context::from_waker(Waker::noop());
        let mut future = Box::pin(dispatch_async(CMD, address, &vm, &gem, None));
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(vm.leaf_entry(strip_hole(VA)), before);
        assert!(vm.lookup(strip_hole(VA)).is_some());
        assert_eq!(vm.tlb_seq.load(Ordering::Acquire), sequence);
        assert!(crate::amdgpu_gem::try_placement(CARD).is_none());
        drop(future);
        assert!(crate::amdgpu_gem::try_placement(CARD).is_some());
        assert_eq!(vm.leaf_entry(strip_hole(VA)), before);

        let mut future = Box::pin(dispatch_async(CMD, address, &vm, &gem, None));
        assert!(future.as_mut().poll(&mut cx).is_pending());
        // An ioctl must keep the request it admitted, even if userspace
        // changes the original buffer while the thread is parked.
        req[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        core::hint::black_box(&req);
        engine.completed.store(1, Ordering::Release);
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(vm.leaf_entry(strip_hole(VA)), before);
        engine.completed.store(3, Ordering::Release);
        assert_eq!(future.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
        drop(future);
        if operation == uapi::AMDGPU_VA_OP_REPLACE {
            assert_eq!(vm.lookup(strip_hole(VA)).unwrap().vm_flags, flags);
            let pte = vm.leaf_entry(strip_hole(VA)).unwrap();
            if flags & uapi::AMDGPU_VM_PAGE_PRT != 0 {
                assert_eq!(pte & (PTE_PRT | PTE_VALID), PTE_PRT);
            } else {
                assert_eq!(pte & (PTE_VALID | PTE_WRITEABLE), PTE_VALID);
            }
        } else {
            assert!(vm.lookup(strip_hole(VA)).is_none());
            assert!(vm
                .leaf_entry(strip_hole(VA))
                .is_none_or(|pte| pte & PTE_VALID == 0));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/vm-retirement",
    va_edits_wait_for_all_jobs_and_cancel_without_mutation
);

fn va_edits_preserve_tables_on_error_timeout_and_missing_engine() -> TestResult {
    const CARD: u32 = 0xfeed_0461;
    let _registered = Registered(CARD);
    let engine = Arc::new(Engine::default());
    crate::amdgpu_cs::register_submitter(CARD, engine.clone());
    let (vm, gem, handle) = mapped(CARD);
    let req = request(uapi::AMDGPU_VA_OP_CLEAR, handle, 0, VA);
    let before = vm.leaf_entry(strip_hole(VA));
    for (failed, expected) in [(false, FsError::Busy), (true, FsError::TimedOut)] {
        engine.expired.store(true, Ordering::Release);
        engine.failed.store(failed, Ordering::Release);
        let mut future = Box::pin(dispatch_async(CMD, req.as_ptr() as usize, &vm, &gem, None));
        assert_eq!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(expected)))
        );
        assert_eq!(vm.leaf_entry(strip_hole(VA)), before);
        assert!(vm.lookup(strip_hole(VA)).is_some());
    }
    crate::amdgpu_cs::unregister_submitter(CARD);
    assert_eq!(
        dispatch(CMD, req.as_ptr() as usize, &vm, &gem, None),
        Err(FsError::NoDevice)
    );
    assert_eq!(vm.leaf_entry(strip_hole(VA)), before);
    // An error that has really retired (e.g. a completed queue reset) does
    // permit cleanup; signalling an error alone did not.
    engine.completed.store(3, Ordering::Release);
    crate::amdgpu_cs::register_submitter(CARD, engine);
    assert_eq!(dispatch(CMD, req.as_ptr() as usize, &vm, &gem, None), Ok(0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/vm-retirement",
    va_edits_preserve_tables_on_error_timeout_and_missing_engine
);

fn disjoint_map_keeps_running_jobs_and_snapshots_before_admission() -> TestResult {
    const CARD: u32 = 0xfeed_0462;
    let _registered = Registered(CARD);
    crate::amdgpu_cs::register_submitter(CARD, Arc::new(Engine::default()));
    let (vm, gem, handle) = mapped(CARD);
    let before = vm.leaf_entry(strip_hole(VA));
    let other_va = VA + 0x20_0000;
    let mut req = request(
        uapi::AMDGPU_VA_OP_MAP,
        handle,
        uapi::AMDGPU_VM_PAGE_READABLE,
        other_va,
    );
    let gate = crate::amdgpu_gem::try_placement(CARD).unwrap();
    let mut future = Box::pin(dispatch_async(CMD, req.as_ptr() as usize, &vm, &gem, None));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    req = request(uapi::AMDGPU_VA_OP_CLEAR, handle, 0, VA);
    core::hint::black_box(&req);
    drop(gate);
    assert_eq!(future.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
    assert_eq!(vm.leaf_entry(strip_hole(VA)), before);
    assert!(vm.lookup(strip_hole(other_va)).is_some());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/vm-retirement",
    disjoint_map_keeps_running_jobs_and_snapshots_before_admission
);
