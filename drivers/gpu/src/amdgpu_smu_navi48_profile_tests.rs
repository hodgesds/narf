use super::super::profile::{DS_DCFCLK, GFX_ULV, SLEEP};
fn smu14_resume_replays_factory_workload_before_low_power_readmission() -> TestResult {
    let (_pool, mut old) = powered();
    run(old.set_power_profile(PowerProfile::Compute)).unwrap();
    let retained = old.profile;
    // A fresh PMFW owner has bootstrap masks again. The retained profile is
    // replayed before queue/media/display proof paths admit their sleep bits.
    let (_pool, mut resumed) = powered();
    assert_eq!(resumed.profile, PowerProfile::BootupDefault);
    run(resumed.set_power_profile(retained)).unwrap();
    resumed.features |= GFX_ULV | DS_DCFCLK;
    run(resumed.admit_sleep(GFX_ULV)).unwrap();
    run(resumed.enable_display_power()).unwrap();
    run(resumed.deep_sleep_control()).unwrap();
    run(resumed.admit_sleep(DS_DCFCLK)).unwrap();
    assert_eq!(resumed.profile, PowerProfile::Compute);
    assert_eq!(resumed.power.unwrap().enabled & SLEEP, 0);
    assert_eq!(
        resumed.io.commands.iter().find(|&&(m, _)| m == 0x24),
        Some(&(0x24, 32))
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    smu14_resume_replays_factory_workload_before_low_power_readmission
);
use super::*;
fn smu14_factory_workloads_use_linux_masks_and_preserve_limits() -> TestResult {
    for (profile, mask) in [
        (PowerProfile::BootupDefault, 1),
        (PowerProfile::Fullscreen3d, 2),
        (PowerProfile::PowerSaving, 4),
        (PowerProfile::Video, 8),
        (PowerProfile::Vr, 16),
        (PowerProfile::Compute, 32),
        (PowerProfile::Window3d, 128),
    ] {
        let (_pool, mut e) = powered();
        let power = e.power;
        let limits = e.limits;
        run(e.set_power_profile(profile)).unwrap();
        assert_eq!(e.profile, profile);
        assert_eq!(e.power, power);
        assert_eq!(e.limits, limits);
        assert_eq!(
            e.io.commands
                .iter()
                .filter(|&&(m, _)| m == 0x24)
                .copied()
                .collect::<Vec<_>>(),
            vec![(0x24, mask)]
        );
        assert!(e
            .io
            .commands
            .iter()
            .all(|&(m, _)| matches!(m, 0xc | 0xd | 0x24)));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    smu14_factory_workloads_use_linux_masks_and_preserve_limits
);

fn smu14_compute_sleep_policy_survives_later_display_and_media_admission() -> TestResult {
    let (_pool, mut e) = powered();
    e.features |= SLEEP | (1 << 20);
    run(e.set_power_profile(PowerProfile::Compute)).unwrap();
    run(e.admit_sleep(GFX_ULV)).unwrap();
    run(e.enable_display_power()).unwrap();
    assert_eq!(e.power.unwrap().enabled & SLEEP, 0);
    run(e.deep_sleep_control()).unwrap();
    assert_eq!(e.power.unwrap().enabled & SLEEP, 0);
    run(e.admit_sleep(DS_DCFCLK)).unwrap();
    run(e.configure_media_power(true)).unwrap();
    assert_eq!(e.power.unwrap().enabled & SLEEP, 0);
    assert_ne!(e.power.unwrap().enabled & (1 << 20), 0);
    let allowed = e.power.unwrap().allowed;
    run(e.set_power_profile(PowerProfile::Video)).unwrap();
    assert_eq!(e.power.unwrap().enabled & SLEEP, allowed & SLEEP);
    run(e.set_power_profile(PowerProfile::Compute)).unwrap();
    assert_eq!(e.power.unwrap().enabled & SLEEP, 0);
    // A static media recovery must withdraw DS_VCN admission too.
    run(e.configure_media_power(false)).unwrap();
    run(e.set_power_profile(PowerProfile::BootupDefault)).unwrap();
    assert_eq!(e.power.unwrap().enabled & (1 << 44), 0);
    assert!(e.protected(e.power.unwrap().enabled));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    smu14_compute_sleep_policy_survives_later_display_and_media_admission
);

fn smu14_extra_sleep_requires_board_support_and_display_admission() -> TestResult {
    let (_pool, mut e) = powered();
    assert_eq!(run(e.admit_sleep(DS_DCFCLK)), Err(Error::Busy));
    assert!(e.io.commands.is_empty());
    e.features &= !GFX_ULV;
    let before = e.power;
    run(e.admit_sleep(GFX_ULV)).unwrap();
    assert_eq!(e.power, before);
    assert!(!e
        .io
        .commands
        .iter()
        .any(|&(m, _)| matches!(m, 4 | 5 | 8 | 9)));
    let (_pool, mut e) = displayed();
    e.features |= DS_DCFCLK | GFX_ULV;
    let old = e.power.unwrap();
    let new = run(e.admit_sleep(DS_DCFCLK | GFX_ULV)).unwrap();
    assert_eq!(new.allowed, old.allowed | DS_DCFCLK | GFX_ULV);
    assert_eq!(new.enabled, old.enabled | DS_DCFCLK | GFX_ULV);
    assert!(e.io.commands.contains(&(8, (DS_DCFCLK | GFX_ULV) as u32)));
    assert_eq!(run(e.admit_sleep(1 << 17)), Err(Error::Invalid));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    smu14_extra_sleep_requires_board_support_and_display_admission
);

fn smu14_profile_rejection_and_partial_failure_publish_only_accepted_profiles() -> TestResult {
    let (_pool, mut e) = powered();
    e.io.reject = Some(0x24);
    assert_eq!(
        run(e.set_power_profile(PowerProfile::Video)),
        Err(Error::Rejected(0xfd))
    );
    assert_eq!(e.state, State::PowerReady);
    assert_eq!(e.profile, PowerProfile::BootupDefault);
    e.io.reject = None;
    run(e.set_power_profile(PowerProfile::Video)).unwrap();
    e.features |= GFX_ULV;
    run(e.admit_sleep(GFX_ULV)).unwrap();
    e.io.reject = Some(0x24);
    assert_eq!(
        run(e.set_power_profile(PowerProfile::Compute)),
        Err(Error::Rejected(0xfd))
    );
    assert_eq!(e.state, State::Failed);
    assert_eq!(e.profile, PowerProfile::Video);
    let count = e.io.commands.len();
    assert_eq!(
        run(e.set_power_profile(PowerProfile::BootupDefault)),
        Err(Error::Busy)
    );
    assert_eq!(e.io.commands.len(), count);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    smu14_profile_rejection_and_partial_failure_publish_only_accepted_profiles
);

fn smu14_profile_cancellation_revocation_and_lost_protection_close_the_owner() -> TestResult {
    for mode in 0..3 {
        let (_pool, mut e) = powered();
        if mode == 0 {
            e.io.stall = Some(0x24);
            let mut future = core::pin::pin!(e.set_power_profile(PowerProfile::Compute));
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            if mode == 1 {
                e.io.revoke = Some((0x24, e.authority));
            } else {
                e.io.reported = Some(e.io.enabled & !(1 << 28));
            }
            assert!(run(e.set_power_profile(PowerProfile::Compute)).is_err());
        }
        assert!(matches!(e.state, State::Runtime | State::Failed));
        assert_eq!(e.profile, PowerProfile::BootupDefault);
        let count = e.io.commands.len();
        assert_eq!(
            run(e.set_power_profile(PowerProfile::Video)),
            Err(Error::Busy)
        );
        assert_eq!(e.io.commands.len(), count);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    smu14_profile_cancellation_revocation_and_lost_protection_close_the_owner
);
