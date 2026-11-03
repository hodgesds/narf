// Shared-GGTT GuC TLB invalidation through the production GuCGt, GuCBoot,
// GuCScheduler and CT owners on the GuC model. The model arena runs the
// production `intel_gpu_ggtt_tlb::Tracker` over its backings, so a cleared
// backing stays live until its covering invalidation completes. Wire values
// follow MIT Linux b90c984d xe_ggtt.c::xe_ggtt_invalidate,
// xe_guc_tlb_inval.c::send_tlb_inval_ggtt and xe_tlb_inval.c.
use crate::intel_gpu_ggtt_tlb::{GuCTlb, Mode, Tracker, TIMEOUT_NS};
use crate::intel_gpu_guc_sched::SchedulingError;

const GT0_MTL: GtPlatform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);

/// Opt the model arena into the tracker, with GT0's GuC an MMIO client from
/// the start as on every authorized production arena.
fn opt_in_gt0(w: &Window) {
    let mut tlb = Tracker::new();
    assert!(tlb.set_mode(GuCTlb::Primary, Mode::Mmio).is_empty());
    w.0.borrow_mut().ggtt_tlb = Some(tlb);
}

/// Every queued H2G as (control fence, request), without consuming it.
fn peek_h2g(w: &Window) -> Vec<(u16, Vec<u32>)> {
    let memory = ct_memory(w);
    let words = memory.borrow();
    let (mut head, tail) = (words[0], words[1]);
    let mut requests = Vec::new();
    while head != tail {
        let header = words[1024 + head as usize];
        let count = header & 0xff;
        let request = (1..=count)
            .map(|i| words[1024 + ((head + i) & 1023) as usize])
            .collect();
        requests.push(((header >> 16) as u16, request));
        head = (head + count + 1) & 1023;
    }
    requests
}

/// Consume every queued H2G, answering none of them.
fn drain_h2g(w: &Window) -> Vec<(u16, Vec<u32>)> {
    let requests = peek_h2g(w);
    let memory = ct_memory(w);
    let mut words = memory.borrow_mut();
    words[0] = words[1];
    requests
}

/// Seqnos of shared-GGTT invalidations: fast-request TLB_INVALIDATION with
/// MAKE_INVAL_OP(XE_GUC_TLB_INVAL_GUC) on control fence 0. Per-context
/// invalidations use their GuC context ID as fence.
fn ggtt_seqnos(requests: &[(u16, Vec<u32>)]) -> Vec<u32> {
    requests
        .iter()
        .filter(|(fence, request)| *fence == 0 && request[0] as u16 == 0x7000)
        .map(|(_, request)| {
            assert_eq!(request.len(), 3);
            assert_eq!(request[0], 0x2000_7000, "fast request, data0 0");
            assert_eq!(request[2], 0x8000_0003);
            request[1]
        })
        .collect()
}

fn tlb_events(w: &Window) -> Vec<(GuCTlb, TlbEvent)> {
    w.0.borrow().ggtt_tlb_events.clone()
}

fn resident(w: &Window, base: u32) -> bool {
    w.0.borrow().memory.contains_key(&base)
}

fn generation(w: &Window) -> u64 {
    w.0.borrow()
        .ggtt_tlb
        .as_ref()
        .expect("opted-in tracker")
        .generation()
}

/// GT0: MMIO invalidation before CT and submission, the CT action once
/// SchedulingReady, one request in flight, completion releasing exactly
/// what it covers, and MMIO plus reset proof on verified stop.
fn smoke_ggtt_tlb_gt0_mmio_before_ct_then_ct_done_releases() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GT0_MTL, 0xdfc);
    opt_in_gt0(&w);
    hardware_discovery(&mut gt, &w, 0xdfc);
    assert_eq!(gt.state(), GtState::Ready);
    let mut alloc = arena.clone();
    // Before CT/submission: MMIO, completing at once.
    let mmio = w.0.borrow().ggtt_tlb_mmio.len();
    let early = alloc.alloc(1).unwrap();
    let base = early.base;
    alloc.free(early);
    assert!(!resident(&w, base), "MMIO removal completes at once");
    assert_eq!(
        &w.0.borrow().ggtt_tlb_mmio[mmio..],
        &[GuCTlb::Primary, GuCTlb::Primary]
    );
    assert!(tlb_events(&w).is_empty(), "no transport switch before CT");
    hardware_scheduling(&mut gt, &w);
    // CT enabled with submission enabled: send_tlb_inval_ggtt's CT branch.
    assert_eq!(tlb_events(&w), [(GuCTlb::Primary, TlbEvent::Ct)]);
    let mmio = w.0.borrow().ggtt_tlb_mmio.len();
    let first = alloc.alloc(2).unwrap();
    let first_base = first.base;
    alloc.free(first);
    let first_gen = generation(&w);
    assert!(resident(&w, first_base), "retained until the CT DONE");
    assert_eq!(w.0.borrow().ggtt_tlb_mmio.len(), mmio, "no MMIO in CT mode");
    assert_eq!(gt.poll(26), Poll::Ready(Ok(GtState::SchedulingReady)));
    // xe_gt_tlb_inval_init_early: the first seqno is 1.
    assert_eq!(ggtt_seqnos(&drain_h2g(&w)), [1]);
    assert!(resident(&w, first_base));
    // One request in flight: no duplicate while it is pending.
    assert_eq!(gt.poll(27), Poll::Ready(Ok(GtState::SchedulingReady)));
    assert!(drain_h2g(&w).is_empty());
    // A removal after the request was sent is not covered by it.
    let second = alloc.alloc(1).unwrap();
    let second_base = second.base;
    alloc.free(second);
    let second_gen = generation(&w);
    event(&ct_memory(&w), 0x7001, &[1]);
    assert_eq!(gt.poll(28), Poll::Ready(Ok(GtState::SchedulingReady)));
    assert!(!resident(&w, first_base), "covered range released");
    assert!(resident(&w, second_base), "later removal still owed");
    // The same poll issued the next request for the newer generation.
    assert_eq!(ggtt_seqnos(&drain_h2g(&w)), [2]);
    event(&ct_memory(&w), 0x7001, &[2]);
    assert_eq!(gt.poll(29), Poll::Ready(Ok(GtState::SchedulingReady)));
    assert!(!resident(&w, second_base));
    assert!(drain_h2g(&w).is_empty());
    assert_eq!(
        tlb_events(&w),
        [
            (GuCTlb::Primary, TlbEvent::Ct),
            (GuCTlb::Primary, TlbEvent::Complete(first_gen)),
            (GuCTlb::Primary, TlbEvent::Complete(second_gen)),
        ]
    );
    // Verified stop: MMIO again at stop, then the GuC reset proof before
    // scheduler and CT memory is freed.
    hardware_stop(&mut gt, &w, 0xdfc);
    assert_eq!(
        &tlb_events(&w)[3..],
        &[
            (GuCTlb::Primary, TlbEvent::Mmio),
            (GuCTlb::Primary, TlbEvent::Reset),
        ]
    );
    {
        let d = w.0.borrow();
        let tlb = d.ggtt_tlb.as_ref().unwrap();
        assert_eq!(tlb.retained(), 0);
        // The stopped GuC left the client set: no MMIO without its wake.
        assert_eq!(tlb.mode(GuCTlb::Primary), Mode::Off);
    }
    let mmio = w.0.borrow().ggtt_tlb_mmio.len();
    drop(gt);
    assert_eq!(w.0.borrow().ggtt_tlb_mmio.len(), mmio);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_gt0_mmio_before_ct_then_ct_done_releases
);

/// Context stamps and GGTT seqnos share one 0x7001 cookie space: a new
/// context skips the in-flight GGTT seqno, the next GGTT seqno skips live
/// context stamps, and the GGTT request precedes the poll's other H2G. A
/// kernel job's retirement frees its LRC and ring inside the scheduler's
/// G2H handling while the CT is borrowed. The covering request then goes out
/// with no arena re-entry: the model's RefCell would panic on one.
fn smoke_ggtt_tlb_gt0_seqnos_and_context_stamps_never_share_a_cookie() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GT0_MTL, 0xdfc);
    opt_in_gt0(&w);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    let baseline = arena.live_allocations();
    let mut alloc = arena.clone();
    let page = alloc.alloc(1).unwrap();
    alloc.free(page);
    assert_eq!(gt.poll(26), Poll::Ready(Ok(GtState::SchedulingReady)));
    assert_eq!(ggtt_seqnos(&drain_h2g(&w)), [1]);
    // Stamp 1 is the in-flight GGTT seqno: the context takes 2.
    let (id, probe) = gt.submit_kernel_probe(27).unwrap();
    assert_eq!(gt.poll(28), Poll::Ready(Ok(GtState::SchedulingReady)));
    let requests = peek_h2g(&w);
    let stamps: Vec<u32> = requests
        .iter()
        .filter(|(fence, request)| *fence == id && request[0] as u16 == 0x7000)
        .map(|(_, request)| request[1])
        .collect();
    assert_eq!(stamps, [2]);
    assert!(
        ggtt_seqnos(&requests).is_empty(),
        "one GGTT request in flight"
    );
    let mut registered = BTreeMap::new();
    service_contexts(&w, &mut registered, true);
    assert_eq!(gt.poll(29), Poll::Ready(Ok(GtState::SchedulingReady)));
    service_contexts(&w, &mut registered, true);
    // GGTT DONE for seqno 1. The probe's LRC/ring publication is still owed,
    // and the next seqno skips the live context stamp 2.
    event(&ct_memory(&w), 0x7001, &[1]);
    assert_eq!(gt.poll(30), Poll::Ready(Ok(GtState::SchedulingReady)));
    let requests = peek_h2g(&w);
    assert_eq!(ggtt_seqnos(&requests), [3]);
    assert_eq!(requests[0].0, 0, "GGTT invalidation leads this poll's H2G");
    // Run the job to retirement; every request is answered by the model.
    for now in 31..80 {
        service_contexts(&w, &mut registered, true);
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if probe.result().is_some() && arena.live_allocations() == baseline {
            break;
        }
    }
    assert_eq!(probe.result(), Some(Ok(())));
    assert_eq!(
        arena.live_allocations(),
        baseline,
        "retired LRC/ring released"
    );
    assert!(registered.is_empty());
    let completions = tlb_events(&w)
        .iter()
        .filter(|(_, event)| matches!(event, TlbEvent::Complete(_)))
        .count();
    assert!(completions >= 3, "the retirement needed its own DONE");
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_gt0_seqnos_and_context_stamps_never_share_a_cookie
);

/// Fail closed: a request older than tlb_inval_timeout_delay, or a DONE
/// with no in-flight owner, loses the GT like other GuC protocol failures.
/// The covered ranges stay retained, as does any later removal. Only the
/// proven GuC reset of the following verified stop releases them.
fn smoke_ggtt_tlb_gt0_timeout_and_stale_done_retain_and_lose_gt() -> TestResult {
    for stale in [false, true] {
        let (w, arena, mut gt) = hardware_model(GT0_MTL, 0xdfc);
        opt_in_gt0(&w);
        hardware_discovery(&mut gt, &w, 0xdfc);
        hardware_scheduling(&mut gt, &w);
        let mut alloc = arena.clone();
        let page = alloc.alloc(1).unwrap();
        let base = page.base;
        alloc.free(page);
        assert_eq!(gt.poll(26), Poll::Ready(Ok(GtState::SchedulingReady)));
        assert_eq!(ggtt_seqnos(&drain_h2g(&w)), [1]);
        let (failure, expected) = if stale {
            event(&ct_memory(&w), 0x7001, &[1]);
            assert_eq!(gt.poll(27), Poll::Ready(Ok(GtState::SchedulingReady)));
            assert!(!resident(&w, base));
            // A second DONE for a completed seqno has no owner.
            event(&ct_memory(&w), 0x7001, &[1]);
            (gt.poll(28), SchedulingError::Protocol)
        } else {
            // Measured from issue at 26, inclusive at the bound.
            assert_eq!(
                gt.poll(26 + TIMEOUT_NS - 1),
                Poll::Ready(Ok(GtState::SchedulingReady))
            );
            assert!(resident(&w, base));
            (gt.poll(26 + TIMEOUT_NS), SchedulingError::Timeout)
        };
        assert_eq!(failure, Poll::Ready(Err(GtError::Scheduling(expected))));
        assert_eq!(gt.state(), GtState::Lost);
        assert_eq!(resident(&w, base), !stale, "timed-out range retained");
        // Still CT mode while lost: a further removal is retained as well.
        let late = alloc.alloc(1).unwrap();
        let late_base = late.base;
        alloc.free(late);
        assert!(resident(&w, late_base));
        assert!(!tlb_events(&w)
            .iter()
            .any(|(_, event)| *event == TlbEvent::Reset));
        let before = tlb_events(&w).len();
        hardware_stop(&mut gt, &w, 0xdfc);
        assert_eq!(
            &tlb_events(&w)[before..],
            &[
                (GuCTlb::Primary, TlbEvent::Mmio),
                (GuCTlb::Primary, TlbEvent::Reset),
            ]
        );
        assert!(!resident(&w, base) && !resident(&w, late_base));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_gt0_timeout_and_stale_done_retain_and_lose_gt
);

/// MTL/Arrow media GT (GT1) through MediaGuc on the `narf.intel.media_gt=1`
/// model. Registered before firmware DMA (MMIO), its own CT
/// TLB_INVALIDATION once its submission is enabled, retention until its
/// DONE, and an unacknowledged request released only by the proven stop.
fn smoke_ggtt_tlb_media_gt_ct_invalidation_and_proven_stop() -> TestResult {
    use super::media_gt_sched::{media_tick, media_until, start_media, Hw};
    use crate::intel_gpu_gt::media::MediaGucState;
    let (w, arena) = media_model();
    // GT1 alone: no GT0 GuC in this model, GT1 registers itself.
    w.0.borrow_mut().ggtt_tlb = Some(Tracker::new());
    let mut guc = start_media(&w, &arena);
    assert_eq!(
        w.0.borrow().ggtt_tlb.as_ref().unwrap().mode(GuCTlb::Media),
        Mode::Mmio
    );
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    {
        let d = w.0.borrow();
        assert_eq!(d.ggtt_tlb.as_ref().unwrap().mode(GuCTlb::Media), Mode::Ct);
        // Firmware, ADS and engine setup were invalidated by MMIO on GT1 only.
        assert!(!d.ggtt_tlb_mmio.is_empty());
        assert!(d.ggtt_tlb_mmio.iter().all(|gt| *gt == GuCTlb::Media));
        assert!(d.ggtt_tlb_events.iter().all(|(gt, _)| *gt == GuCTlb::Media));
        assert_eq!(d.ggtt_tlb_events[0], (GuCTlb::Media, TlbEvent::Ct));
        // Priming and probe retirement released their LRCs through DONEs.
        assert!(d
            .ggtt_tlb_events
            .iter()
            .any(|(_, event)| matches!(event, TlbEvent::Complete(_))));
    }
    // The last probe's LRC/ring are released by the DONE answered next.
    for tick in 1..4 {
        assert_eq!(
            media_tick(&mut guc, &w, &mut hw, now + tick),
            Poll::Ready(Ok(MediaGucState::Running))
        );
    }
    assert_eq!(w.0.borrow().ggtt_tlb.as_ref().unwrap().retained(), 0);
    let now = now + 10;
    let mmio = w.0.borrow().ggtt_tlb_mmio.len();
    let mut alloc = arena.clone();
    let page = alloc.alloc(1).unwrap();
    let base = page.base;
    alloc.free(page);
    let gen = generation(&w);
    assert!(resident(&w, base));
    assert_eq!(w.0.borrow().ggtt_tlb_mmio.len(), mmio, "no MMIO in CT mode");
    let mut seqno = None;
    for tick in 1..4 {
        assert!(guc.poll(now + tick, || true).is_ready());
        let sent = ggtt_seqnos(&drain_h2g(&w));
        if let [one] = sent[..] {
            seqno = Some(one);
            break;
        }
        assert!(sent.is_empty());
    }
    let Some(seqno) = seqno else {
        return TestResult::Fail("media scheduler sent no GGTT invalidation");
    };
    assert!(resident(&w, base));
    event(&ct_memory(&w), 0x7001, &[seqno]);
    assert!(guc.poll(now + 5, || true).is_ready());
    assert!(!resident(&w, base));
    assert_eq!(
        tlb_events(&w).last(),
        Some(&(GuCTlb::Media, TlbEvent::Complete(gen)))
    );
    // An unanswered request at stop: back to MMIO, still retained, then the
    // proven GuC reset and unregistration release it.
    let page = alloc.alloc(1).unwrap();
    let base = page.base;
    alloc.free(page);
    assert!(guc.poll(now + 6, || true).is_ready());
    assert_eq!(ggtt_seqnos(&drain_h2g(&w)).len(), 1);
    guc.begin_stop(now + 7);
    assert_eq!(
        w.0.borrow().ggtt_tlb.as_ref().unwrap().mode(GuCTlb::Media),
        Mode::Mmio
    );
    assert!(resident(&w, base), "unproven stop keeps the range");
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 8, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(!resident(&w, base));
    assert!(tlb_events(&w)
        .iter()
        .any(|event| *event == (GuCTlb::Media, TlbEvent::Reset)));
    assert_eq!(
        w.0.borrow().ggtt_tlb.as_ref().unwrap().mode(GuCTlb::Media),
        Mode::Off
    );
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_ggtt_tlb_media_gt_ct_invalidation_and_proven_stop
);
