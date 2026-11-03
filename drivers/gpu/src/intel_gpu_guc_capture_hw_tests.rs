// Real GuCGt/ADS/CT error capture: list registration in the submission ADS,
// STATE_CAPTURE_NOTIFICATION extraction from the owned log BO and the
// coredump's engine snapshot. MIT Linux b90c984d xe_guc_capture.c,
// xe_guc_ads.c::guc_capture_prep_lists and xe_guc_submit.c.
use super::*;
use crate::intel_gpu_error::{capture, coredump, Reason};

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn logs(w: &Window) -> Words {
    w.0.borrow()
        .memory
        .values()
        .find(|b| b.borrow().len() == 0x115000 / 4)
        .unwrap()
        .clone()
}
fn xe_text(bytes: &[u8]) -> &str {
    let offset = word(bytes, 172) as usize;
    assert_eq!(&bytes[offset..offset + 8], b"NARFXETX");
    let len = word(bytes, offset + 20) as usize;
    assert!(bytes[offset + 64 + len..offset + 64 + 32768]
        .iter()
        .all(|byte| *byte == 0));
    core::str::from_utf8(&bytes[offset + 64..offset + 64 + len]).unwrap()
}
fn prime_capture(gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64) {
    hardware_discovery(gt, w, ack);
    gt.prepare_error_capture().unwrap();
    assert_eq!(gt.prepare_error_capture(), Err(FsError::Unsupported));
    hardware_scheduling(gt, w);
    let fence = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..95 {
        ready(gt, now);
        service_contexts(w, &mut registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(gt.user_epoch().is_some());
}
/// One render engine's GuC output group with a recognizable RING_HEAD.
fn guc_group(lrca: u32, guc_id: u32) -> Vec<u32> {
    let mut words = alloc::vec![0, 3];
    words.extend([0, 0, !0, !0, 1, 0xa188, 0x10001, 0, 0]);
    words.extend([0, 1, !0, !0, 1, 0x14800, 0x20002, 0, 0]);
    words.extend([0, 2, lrca, guc_id, capture::INSTANCE_REGS.len() as u32]);
    for descr in &capture::INSTANCE_REGS {
        let value = if descr.offset == 0x34 { 0xbeef } else { descr.offset };
        words.extend([descr.offset, value, 0, 0]);
    }
    words
}

fn smoke_hardware_guc_capture_ads_g2h_extraction_and_guc_engine_snapshot() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime_capture(&mut gt, &w, 0xdfc);
    {
        // xe_guc_ads.c::guc_capture_prep_lists in the reloaded ADS.
        let d = w.0.borrow();
        let ads = d.memory[&0x20001000].borrow();
        let null = ads[(0x111c + 4) / 4];
        assert_ne!(null, 0, "the main GT has no VCS: zero-descriptor list");
        let lists = d.memory[&null].borrow();
        assert!(lists[..4].iter().all(|word| *word == 0));
        let dss = gt.topology().unwrap().geometry_dss().count_ones();
        let rc_class = (4 + (1 + dss as usize * 6) * 16).next_multiple_of(4096) as u32;
        assert_eq!(ads[0x111c / 4], null + 0x1000);
        assert_eq!(lists[0x1000 / 4], 1 + dss * 6);
        assert_eq!(&lists[0x1004 / 4..0x1014 / 4], &[0x14800, 0xdeadf00d, 0, 0]);
        let instance = 0x1000 + rc_class;
        assert_eq!(ads[0x109c / 4], null + instance);
        assert_eq!(lists[instance as usize / 4], 27);
        assert_eq!(lists[instance as usize / 4 + 1], 0x98);
        // BCS0/BCS8: empty class list, one instance list.
        assert_eq!(ads[(0x111c + 12) / 4], null);
        assert_eq!(ads[(0x109c + 12) / 4], null + instance + 0x1000);
        assert_eq!(ads[0x119c / 4], null + instance + 0x2000);
        assert_eq!(
            &lists[(instance as usize + 0x2000) / 4..(instance as usize + 0x2000) / 4 + 3],
            &[1, 0xa188, 0xdeadf00d]
        );
        for class in 0..5 {
            assert_eq!(ads[(0x111c + 64 + class * 4) / 4], null, "VF lists");
        }
        assert_eq!(ads[(0x119c + 4) / 4], null);
    }
    let guilty = UserContext::new();
    let (batch, _result) = PpgttProbeResult::prepare(platform).unwrap();
    let (id, hung) = gt
        .submit_user_batch(100, guilty.clone(), UserBatch(batch))
        .unwrap();
    let mut registered = BTreeMap::new();
    for now in 101..130 {
        ready(&mut gt, now);
        service_contexts(&w, &mut registered, false);
    }
    let lrca = registered[&u32::from(id)];
    let stream = guc_group(lrca, u32::from(id));
    let bytes = stream.len() as u32 * 4;
    let log = logs(&w);
    {
        let mut words = log.borrow_mut();
        words[0x15000 / 4..0x15000 / 4 + stream.len()].copy_from_slice(&stream);
        words[18 + 2] = 0;
        words[18 + 5] = bytes;
        words[18 + 7] = 1;
    }
    // GuC: capture notification, then the reset under the context.
    event(&ct_memory(&w), 0x8002, &[0]);
    event(&ct_memory(&w), 0x1008, &[u32::from(id)]);
    ready(&mut gt, 131);
    assert!(service_contexts(&w, &mut registered, false).contains(&0x30));
    assert!(w.0.borrow().stream_controls.contains(&(0x30, 0, 2)));
    assert_eq!((log.borrow()[18 + 2], log.borrow()[18 + 7]), (bytes, 0));
    let report = gt.take_error_report().expect("reset report");
    let index = 58;
    let armed = coredump::Armed::reserve_for_test(index).unwrap();
    let writes = w.0.borrow().writes.len();
    gt.capture_coredump(armed, report, 132, [0; 32], || true);
    assert_eq!(w.0.borrow().writes.len(), writes, "text capture wrote hardware");
    let captured = coredump::snapshot_bytes_for_test(index).unwrap();
    assert_eq!(word(&captured, 8), 4);
    assert_eq!(word(&captured, 72) & 32, 32);
    assert_eq!(word(&captured, 180), coredump::XE_QUEUE | coredump::XE_GUC);
    let text = xe_text(&captured);
    assert!(text.contains(&alloc::format!(", guc_id={id}, flags=0x0\n")));
    assert!(text.contains(&alloc::format!("GuC ID: {id}\n\tName: rcs{id}\n\tClass: 0\n")));
    assert!(text.contains("\tTimeout: 5000 (ms)\n\tTimeslice: 1000 (us)\n"));
    assert!(text.contains("rcs0 (physical), logical instance=0\n\tCapture_source: GuC\n"));
    assert!(text.contains("\tFORCEWAKE_GT: 0x00010001\n\tRCU_MODE: 0x00020002\n"));
    assert!(text.contains("\tRING_HEAD: 0x0000beef\n"));
    assert!(text.contains("\tACTHD: 0x0000005c00000074\n"));
    assert!(coredump::clear_for_test(index));
    // The next notification releases the consumed node first; an empty
    // region still publishes read_ptr and acknowledges.
    event(&ct_memory(&w), 0x8002, &[1]);
    ready(&mut gt, 133);
    service_contexts(&w, &mut registered, false);
    let acks = w
        .0
        .borrow()
        .stream_controls
        .iter()
        .filter(|control| **control == (0x30, 0, 2))
        .count();
    assert_eq!(acks, 2);
    for now in 134..200 {
        ready(&mut gt, now);
        service_contexts(&w, &mut registered, false);
        if hung.result().is_some() {
            break;
        }
    }
    assert_eq!(hung.result(), Some(Err(JobError::Hang)));
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_guc_capture_ads_g2h_extraction_and_guc_engine_snapshot
);

/// guc_exec_queue_timedout_job without a GuC node: the manual capture is
/// read before the schedule disable and named in the coredump.
fn smoke_hardware_guc_capture_timeout_manual_fallback_snapshot() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime_capture(&mut gt, &w, 0xdfc);
    let guilty = UserContext::new();
    let (batch, _result) = PpgttProbeResult::prepare(platform).unwrap();
    let (id, hung) = gt
        .submit_user_batch(100, guilty.clone(), UserBatch(batch))
        .unwrap();
    let mut registered = BTreeMap::new();
    for now in 101..130 {
        ready(&mut gt, now);
        service_contexts(&w, &mut registered, false);
    }
    ready(&mut gt, HANG_TIMEOUT + 100);
    service_contexts(&w, &mut registered, false);
    w.0.borrow_mut().regs.extend([(0x2068, 0x7a00_0004), (0x20b0, 0x10)]);
    model_runtime(&w, registered[&u32::from(id)], 0, 15_000_000, true);
    ready(&mut gt, HANG_TIMEOUT + 130);
    let report = gt.take_error_report().expect("timeout capture before disable");
    let index = 58;
    let armed = coredump::Armed::reserve_for_test(index).unwrap();
    gt.capture_coredump(armed, report, HANG_TIMEOUT + 131, [0; 32], || true);
    let captured = coredump::snapshot_bytes_for_test(index).unwrap();
    assert_eq!(word(&captured, 180), coredump::XE_QUEUE | coredump::XE_MANUAL);
    let text = xe_text(&captured);
    assert!(text.contains("rcs0 (physical), logical instance=0\n\tCapture_source: Manual\n"));
    assert!(text.contains("\tIPEHR: 0x7a000004\n"));
    assert!(text.contains("\tRING_EIR: 0x00000010\n"));
    assert!(text.contains(&alloc::format!("GuC ID: {id}\n")));
    // The public first-error report keeps its redacted whitelist only.
    let public = crate::intel_gpu_error::Snapshot {
        report,
        suppressed: 0,
    }
    .text();
    assert!(!public.contains("IPEHR") && !public.contains("ACTHD"));
    assert!(coredump::clear_for_test(index));
    assert!(service_contexts(&w, &mut registered, false).contains(&0x1001));
    for now in HANG_TIMEOUT + 131..HANG_TIMEOUT + 200 {
        ready(&mut gt, now);
        service_contexts(&w, &mut registered, false);
        if hung.result().is_some() {
            break;
        }
    }
    assert_eq!(hung.result(), Some(Err(JobError::Hang)));
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_guc_capture_timeout_manual_fallback_snapshot
);

/// Without the opt-in: no ADS pointers, no text section, and a capture
/// notification stays the protocol loss it was.
fn smoke_hardware_guc_capture_option_off_unchanged() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    {
        let d = w.0.borrow();
        let ads = d.memory[&0x20001000].borrow();
        assert!(ads[0x109c / 4..0x11a4 / 4].iter().all(|word| *word == 0));
    }
    let (batch, _result) = PpgttProbeResult::prepare(platform).unwrap();
    let (_, hung) = gt
        .submit_user_batch(100, UserContext::new(), UserBatch(batch))
        .unwrap();
    let mut registered = BTreeMap::new();
    for now in 101..130 {
        ready(&mut gt, now);
        service_contexts(&w, &mut registered, false);
    }
    event(&ct_memory(&w), 0x8002, &[0]);
    assert!(matches!(
        gt.poll(131),
        Poll::Ready(Err(GtError::Scheduling(
            crate::intel_gpu_guc_sched::SchedulingError::Protocol
        )))
    ));
    assert_eq!(gt.state(), GtState::Lost);
    let report = gt.error_report(Reason::Protocol, 0, 132, || true, |reg| Some(w.read32(reg)));
    let index = 58;
    let armed = coredump::Armed::reserve_for_test(index).unwrap();
    gt.capture_coredump(armed, report, 133, [0; 32], || true);
    let captured = coredump::snapshot_bytes_for_test(index).unwrap();
    assert_eq!(word(&captured, 72) & 32, 0);
    assert_eq!(word(&captured, 180), 0);
    let offset = word(&captured, 172) as usize;
    assert!(captured[offset..].iter().all(|byte| *byte == 0));
    assert!(coredump::clear_for_test(index));
    assert_eq!(hung.result(), None);
    hardware_stop(&mut gt, &w, 0xdfc);
    assert_eq!(
        hung.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_guc_capture_option_off_unchanged
);
