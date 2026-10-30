use super::*;
fn ready() -> Engine<Fake> {
    let mut e = idle_dpm_engine();
    run(e.notify_wm_ranges(0x8_0040_1000)).unwrap();
    let r = Request {
        deep_sleep_dcfclk_khz: 10_673,
        ..request()
    };
    run(e.prepare(r)).unwrap();
    e.io.commands.clear();
    e
}
fn dcn401_runtime_admission_checks_each_die_and_releases_legacy_fabric_floor() -> TestResult {
    for chip in [
        crate::amdgpu_rdna4::Rdna4Chip::Navi48,
        crate::amdgpu_rdna4::Rdna4Chip::Navi44,
    ] {
        for legacy in [false, true] {
            let mut e = ready();
            e.layout.chip = Some(chip);
            e.status.levels.as_mut().unwrap().firmware =
                chip.idle_dpm_min_smu() - u32::from(legacy);
            run(e.admit_dynamic_power(&|_| false)).unwrap();
            run(e.update_bandwidth(pstate_bw(), true, &|_| false)).unwrap();
            assert_eq!(e.status.bandwidth.fclk_pstate, !legacy);
            assert_eq!(
                e.status.bandwidth.fclk_khz,
                if legacy { 2_500_000 } else { 300_000 }
            );
            if legacy {
                assert!(e.io.commands.contains(&(9, 3 << 16 | 2500)));
            }
            let none = run(e.release()).unwrap();
            assert_eq!(none.request.displays, 0);
            assert_eq!(none.memory_floor_khz, 96_000);
            assert_eq!(e.status.bandwidth.fclk_khz, 300_000);
            if legacy {
                assert!(e.io.commands.contains(&(9, 3 << 16 | 300)));
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    dcn401_runtime_admission_checks_each_die_and_releases_legacy_fabric_floor
);
fn dcn401_dynamic_admission_replays_pinned_floors_then_allows_dml_lowering() -> TestResult {
    let mut e = ready();
    assert!(!e.status.dynamic_power);
    let applied = run(e.admit_dynamic_power(&|_| false)).unwrap();
    assert!(e.status.dynamic_power && e.status.watermarks_ready);
    assert!(!applied.uclk_pstate);
    assert_eq!(applied.memory_floor_khz, 1_258_000);
    assert!(e.io.commands.contains(&(0xd, 11)));
    assert!(e.io.commands.contains(&(0x18, 2500 << 16 | 1258)));
    assert!(e.io.commands.contains(&(0x19, 2500 << 16 | 1258)));
    assert!(e.io.commands.contains(&(0x1a, 0)));
    let lowered = run(e.update_bandwidth(pstate_bw(), true, &|_| false)).unwrap();
    assert!(lowered.uclk_pstate);
    assert_eq!(lowered.memory_floor_khz, 96_000);
    assert!(e.io.commands.contains(&(0x18, 300 << 16 | 96)));
    assert!(e.io.commands.contains(&(0x19, 300 << 16 | 96)));
    assert_eq!(e.status.ignored.count, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    dcn401_dynamic_admission_replays_pinned_floors_then_allows_dml_lowering
);

fn dcn401_watermark_refusal_never_becomes_dynamic_power_admission() -> TestResult {
    for message in 0..3 {
        let mut e = idle_dpm_engine();
        // Even a saturated diagnostic counter cannot hide a refused message.
        e.status.ignored.count = u32::MAX;
        e.io.refuse = Some(e.io.commands.len() + 1 + message);
        run(e.notify_wm_ranges(0x8_0040_1000)).unwrap();
        assert!(!e.status.watermarks_ready);
        run(e.prepare(request())).unwrap();
        let count = e.io.commands.len();
        assert_eq!(run(e.admit_dynamic_power(&|_| false)), Err(Error::Busy));
        assert_eq!(e.io.commands.len(), count);
        assert!(!e.status.dynamic_power);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    dcn401_watermark_refusal_never_becomes_dynamic_power_admission
);

fn dcn401_rejected_runtime_floors_are_terminal_and_not_recorded_as_applied() -> TestResult {
    let mut probe = ready();
    run(probe.admit_dynamic_power(&|_| false)).unwrap();
    probe.io.commands.clear();
    run(probe.update_bandwidth(pstate_bw(), true, &|_| false)).unwrap();
    let sequence = probe.io.commands.clone();
    for step in 0..sequence.len() {
        let mut e = ready();
        run(e.admit_dynamic_power(&|_| false)).unwrap();
        let old = e.status.applied;
        e.io.refuse = Some(e.io.commands.len() + step + 1);
        assert!(run(e.update_bandwidth(pstate_bw(), true, &|_| false)).is_err());
        assert_eq!(e.status.applied, old);
        assert!(matches!(e.status.state, State::Failed(_)));
        let count = e.io.commands.len();
        assert_eq!(
            run(e.update_bandwidth(pstate_bw(), true, &|_| false)),
            Err(Error::Busy)
        );
        assert_eq!(e.io.commands.len(), count);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    dcn401_rejected_runtime_floors_are_terminal_and_not_recorded_as_applied
);

fn dcn401_dynamic_admission_cancellation_and_missing_floor_ack_keep_owner_closed() -> TestResult {
    let mut e = ready();
    e.unanswered_ignored = true;
    let count = e.io.commands.len();
    assert_eq!(run(e.admit_dynamic_power(&|_| false)), Err(Error::Timeout));
    assert_eq!(e.io.commands.len(), count);
    assert_eq!(e.status.state, State::Failed(Error::Timeout));
    let mut e = ready();
    e.io.wrong_ack = true;
    assert!(matches!(
        run(e.admit_dynamic_power(&|_| false)),
        Err(Error::HardMinTimeout(_))
    ));
    assert!(matches!(e.status.state, State::Failed(_)));
    let mut e = ready();
    e.io.stall = Some(e.io.commands.len() + 1);
    {
        let held = |_: u64| false;
        let mut future = core::pin::pin!(e.admit_dynamic_power(&held));
        assert!(core::future::Future::poll(
            future.as_mut(),
            &mut Context::from_waker(Waker::noop())
        )
        .is_pending());
    }
    assert_eq!(e.status.state, State::Applying);
    let count = e.io.commands.len();
    assert_eq!(run(e.admit_dynamic_power(&|_| false)), Err(Error::Busy));
    assert_eq!(e.io.commands.len(), count);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    dcn401_dynamic_admission_cancellation_and_missing_floor_ack_keep_owner_closed
);
