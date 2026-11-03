// Real GuCGt timeout -> privileged immutable execution capture -> full reset.
// Retained LRC/ring snapshots follow pinned MIT Linux b90c984d
// xe_devcoredump.c and xe_guc_submit.c; NARF's fixed file format is native.
use crate::intel_gpu_engine::Engine;
use crate::intel_gpu_error::{coredump, Reason};

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn smoke_hardware_coredump_execution_timeout_snapshot_survives_full_reset() -> TestResult {
    for (platform, ack) in [
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Battlemage, 0xdfc),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
        ),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        hardware_discovery(&mut gt, &w, ack);
        hardware_scheduling(&mut gt, &w);
        let (id, completion) = gt.submit_kernel_probe(100).unwrap();
        let mut registered = BTreeMap::new();
        for now in 101..120 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        let base = registered[&u32::from(id)];
        let ring_base = w.0.borrow().memory[&base].borrow()[1024 + 9];
        w.0.borrow().memory[&base].borrow_mut()[0x3000 / 4] = 0x454c5243;
        w.0.borrow().memory[&ring_base].borrow_mut()[0x1ffc / 4] = 0x4552494e;
        assert!(gt.poll(6_000_000_000).is_ready());
        assert_eq!(gt.state(), GtState::Lost);
        assert_eq!(completion.result(), None);
        let report = gt.error_report(
            Reason::Timeout,
            0,
            6_000_000_001,
            || true,
            |reg| Some(w.read32(reg)),
        );
        let index = 59;
        let armed = coredump::Armed::reserve_for_test(index).unwrap();
        let allocations = arena.live_allocations();
        let writes = w.0.borrow().writes.len();
        gt.capture_coredump(armed, report, 6_000_000_002, [0xa5; 32], || true);
        assert_eq!(arena.live_allocations(), allocations);
        assert_eq!(
            w.0.borrow().writes.len(),
            writes,
            "passive capture wrote hardware"
        );
        assert_eq!(completion.result(), None);
        let captured = coredump::snapshot_bytes_for_test(index).unwrap();
        assert_eq!(word(&captured, 8), 4);
        assert_eq!(word(&captured, 72) & 8, 8);
        let offset = word(&captured, 144) as usize;
        let exec = &captured[offset..offset + word(&captured, 148) as usize];
        assert_eq!(&exec[..8], b"NARFEXEC");
        assert_eq!((word(exec, 24), word(exec, 28), word(exec, 32)), (1, 1, 1));
        let entry = &exec[64..];
        assert_eq!(
            (word(entry, 0), word(entry, 4), word(entry, 8)),
            (u32::from(id), u32::from(id), 0)
        );
        assert_eq!(word(entry, 40), 3);
        assert_eq!(word(entry, 48), Engine::Rcs0.lrc_pages(platform) * 4096);
        assert_eq!(
            word(&captured, word(entry, 44) as usize + 0x3000),
            0x454c5243
        );
        assert_eq!(
            word(&captured, word(entry, 52) as usize + 0x1ffc),
            0x4552494e
        );
        // Device mutation after capture cannot splice a retained description.
        w.0.borrow().memory[&base].borrow_mut()[0x3000 / 4] = 0;
        w.0.borrow().memory[&ring_base].borrow_mut()[0x1ffc / 4] = 0;
        hardware_stop(&mut gt, &w, ack);
        assert_eq!(
            completion.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        assert_eq!(coredump::snapshot_bytes_for_test(index).unwrap(), captured);
        assert!(coredump::clear_for_test(index));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_coredump_execution_timeout_snapshot_survives_full_reset
);

fn smoke_hardware_coredump_execution_denial_does_not_read_or_release_owned_dma() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    let (_, completion) = gt.submit_kernel_probe(100).unwrap();
    let report = gt.error_report(
        Reason::Unavailable,
        0,
        101,
        || true,
        |reg| Some(w.read32(reg)),
    );
    let index = 59;
    let armed = coredump::Armed::reserve_for_test(index).unwrap();
    let reads = w.0.borrow().mmio_reads.get();
    let writes = w.0.borrow().writes.len();
    let allocations = arena.live_allocations();
    gt.capture_coredump(armed, report, 102, [0; 32], || false);
    assert_eq!(w.0.borrow().mmio_reads.get(), reads);
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(arena.live_allocations(), allocations);
    assert_eq!(completion.result(), None);
    let captured = coredump::snapshot_bytes_for_test(index).unwrap();
    let offset = word(&captured, 144) as usize;
    let exec = &captured[offset..offset + word(&captured, 148) as usize];
    assert_eq!(
        (
            word(exec, 24),
            word(exec, 28),
            word(exec, 32),
            word(exec, 36)
        ),
        (1, 0, 0, 3)
    );
    assert!(exec[64..].iter().all(|byte| *byte == 0));
    let vm = &captured[0x1b4540..];
    assert_eq!(&vm[..8], b"NARFVMEM");
    assert_eq!(
        (word(vm, 24), word(vm, 28), word(vm, 32), word(vm, 36)),
        (0, 0, 0, 2)
    );
    assert!(vm[64..].iter().all(|byte| *byte == 0));
    assert!(coredump::clear_for_test(index));
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_coredump_execution_denial_does_not_read_or_release_owned_dma
);
