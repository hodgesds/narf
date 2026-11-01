//! The production Device/Guard color owner, including console/PM/reset paths.
use super::*;
use crate::intel_gpu_color::MODE;
fn identity() -> [u64; 9] {
    [1 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32]
}
fn smoke_kms_ctm_only_owns_color_and_preserves_it_across_surface_restore() -> TestResult {
    let platform = MockPlatform::new();
    platform.set(0x49010, 0x12345678);
    let device = platform.meteor();
    let mut session = complete(device.session()).unwrap();
    let mut update = Box::pin(session.set_ctm(Some(identity())));
    assert!(once(update.as_mut()).is_pending());
    assert_eq!(platform.read32(MODE), 1 << 31);
    assert!(device.legacy().is_err());
    let stamp = complete(update).unwrap();
    session.confirm_ctm();
    assert_eq!(stamp.sequence, 41);
    complete(session.restore_surface()).unwrap();
    assert_eq!(platform.read32(MODE), 1 << 31);
    complete(session.restore_console()).unwrap();
    assert_eq!(platform.read32(MODE), 0);
    assert_eq!(platform.read32(0x49010), 0x12345678);
    drop(session);
    assert!(device.legacy().is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_ctm_only_owns_color_and_preserves_it_across_surface_restore
);
fn smoke_kms_ctm_cancel_restores_original_before_console_resume() -> TestResult {
    for pause_blocked in [false, true] {
        let platform = MockPlatform::new();
        platform.0.lock().pause_blocked = pause_blocked;
        let device = platform.meteor();
        {
            let mut session = complete(device.session()).unwrap();
            let mut update = Box::pin(session.set_ctm(Some(identity())));
            assert!(once(update.as_mut()).is_pending());
            drop(update);
        }
        assert!(device.legacy().is_err());
        assert!(!platform.actions().contains(&Action::Resume));
        platform.0.lock().pause_blocked = false;
        let mut session = complete(device.session()).unwrap();
        if !pause_blocked {
            assert_eq!(complete(session.restore_surface()), Err(FsError::Busy));
        }
        complete(session.restore_console()).unwrap();
        assert_eq!(platform.read32(MODE), 0);
        // Cancellation before takeover must not make later CSC writes assume
        // PSR ownership; restoration obtains that missing ownership first.
        assert_eq!(
            platform
                .actions()
                .iter()
                .filter(|&&a| a == Action::Takeover)
                .count(),
            1
        );
        assert_eq!(platform.actions().last(), Some(&Action::Resume));
        drop(session);
        assert!(device.legacy().is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_ctm_cancel_restores_original_before_console_resume
);
fn smoke_kms_ctm_suspend_and_gt_reset_restore_original_color_before_reopen() -> TestResult {
    for reset in [false, true] {
        let platform = MockPlatform::new();
        platform.set(0x49010, 0x24681357);
        let device = platform.meteor();
        let mut session = complete(device.session()).unwrap();
        complete(session.set_ctm(Some(identity()))).unwrap();
        session.confirm_ctm();
        drop(session);
        if reset {
            quarantine_reset_state(&device.state, &platform.1);
            assert!(device.reset_lost());
            assert!(complete(device.session()).is_err());
            complete(device.recover()).unwrap();
            assert!(!device.reset_lost());
        } else {
            complete(device.quiesce()).unwrap();
            assert!(complete(device.session()).is_err());
            let mut legacy = device.legacy().unwrap();
            legacy.console_replaced(&console());
        }
        assert_eq!(platform.read32(MODE), 0);
        assert_eq!(platform.read32(0x49010), 0x24681357);
        assert!(device.legacy().is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_ctm_suspend_and_gt_reset_restore_original_color_before_reopen
);
fn smoke_kms_ctm_failed_latch_retains_color_until_fresh_reset_restore() -> TestResult {
    let platform = MockPlatform::new();
    let device = platform.meteor();
    {
        let mut session = complete(device.session()).unwrap();
        let mut update = Box::pin(session.set_ctm(Some(identity())));
        assert!(once(update.as_mut()).is_pending());
        platform.set(MODE, 0); // shadow ownership lost before the witness
        assert_eq!(once(update.as_mut()), Poll::Ready(Err(FsError::NoDevice)));
    }
    assert!(device.legacy().is_err());
    assert!(device.state.try_lock().unwrap().color.is_some());
    quarantine_reset_state(&device.state, &platform.1);
    complete(device.recover()).unwrap();
    assert_eq!(platform.read32(MODE), 0);
    assert!(device.state.try_lock().unwrap().color.is_none());
    assert!(device.legacy().is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_ctm_failed_latch_retains_color_until_fresh_reset_restore
);
