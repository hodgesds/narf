// Real retained user VM/BO capture under the actual GuCGt reset owner.
use super::*;
use crate::{
    intel_gpu_error::{coredump, Reason},
    intel_gpu_exec::{ResidentBatch, VmMapping},
    intel_gpu_gem::GemState,
};

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn smoke_hardware_vm_dump_retains_closed_user_bo_through_capture_and_full_reset() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let gem = GemState::new();
    let handle = gem.create(8192, |_, _| Ok(())).unwrap();
    let object = gem.object(handle).unwrap();
    object.write(0, &[0xa5; 8192]).unwrap();
    object.write(0, &0x05000000u32.to_le_bytes()).unwrap();
    let weak = Arc::downgrade(&object);
    let context = UserContext::new();
    let batch = ResidentBatch::from_vm(
        platform,
        &[VmMapping {
            object: Some(object.clone()),
            va: 0x10000,
            offset: 0,
            length: 8192,
            writable: true,
            pat: 2,
            dumpable: true,
        }],
        Some(0x10000),
        false,
        None,
    )
    .unwrap();
    let root = batch.space().root_phys();
    let (id, completion) = gt
        .submit_user_batch(100, context.clone(), UserBatch(batch))
        .unwrap();
    // Normal CPU reads are blocked by this job's unfinished reservation.
    assert_eq!(object.read(0, &mut [0]), Err(FsError::WouldBlock));
    gem.close(handle).unwrap();
    drop(gem);
    drop(object);
    let mut registered = BTreeMap::new();
    for now in 101..130 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    // First expiry attempts isolated context recovery. Leave its disable
    // unanswered so the bounded second expiry requires a full GT reset.
    model_runtime(&w, registered[&u32::from(id)], 0, 15_000_000, true);
    ready(&mut gt, HANG_TIMEOUT + 130);
    let lost_at = 2 * HANG_TIMEOUT + 130;
    assert!(matches!(
        gt.poll(lost_at),
        Poll::Ready(Err(GtError::Scheduling(
            crate::intel_gpu_guc_sched::SchedulingError::Timeout
        )))
    ));
    assert_eq!(gt.state(), GtState::Lost);
    assert!(weak.upgrade().is_some() && context.busy());
    let report = gt.error_report(
        Reason::Timeout,
        gt.user_epoch().unwrap_or(0),
        lost_at + 1,
        || true,
        |reg| Some(w.read32(reg)),
    );
    let armed = coredump::Armed::reserve_for_test(59).unwrap();
    let allocations = arena.live_allocations();
    let writes = w.0.borrow().writes.len();
    gt.capture_coredump(armed, report, lost_at + 2, [0; 32], || true);
    assert_eq!(arena.live_allocations(), allocations);
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(completion.result(), None);
    assert!(weak.upgrade().is_some() && context.busy());
    let captured = coredump::snapshot_bytes_for_test(59).unwrap();
    assert_eq!((word(&captured, 8), word(&captured, 72)), (4, 31));
    assert_eq!(
        (
            word(&captured, 160),
            word(&captured, 164),
            word(&captured, 168)
        ),
        (0x1b4540, 0xc0e40, 0)
    );
    let section = &captured[0x1b4540..];
    assert_eq!(&section[..8], b"NARFVMEM");
    assert_eq!(
        (word(section, 24), word(section, 28), word(section, 32)),
        (1, 1, 1)
    );
    let record = &section[64..];
    assert_eq!(word(record, 0), u32::from(id));
    assert_eq!(u64::from_le_bytes(record[24..32].try_into().unwrap()), root);
    assert_eq!(
        (
            word(record, 32),
            word(record, 36),
            word(record, 40),
            word(record, 44)
        ),
        (4, 4, 1, 1)
    );
    let range = &record[0x10180..];
    assert_eq!((word(range, 32), word(range, 44)), (32, 8192));
    let data = word(range, 40) as usize;
    assert_eq!(word(&captured, data), 0x05000000);
    assert!(captured[data + 4..data + 8192].iter().all(|b| *b == 0xa5));
    hardware_stop(&mut gt, &w, 0xdfc);
    assert_eq!(completion.result(), Some(Err(JobError::Reset)));
    assert!(
        weak.upgrade().is_none(),
        "capture changed execution ownership"
    );
    assert_eq!(coredump::snapshot_bytes_for_test(59).unwrap(), captured);
    assert!(coredump::clear_for_test(59));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_vm_dump_retains_closed_user_bo_through_capture_and_full_reset
);
