use super::super::tssi::tests::{self as source, complete};
use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
fn measurements(results: &[Path; 2]) -> [[u16; 8]; 2] {
    core::array::from_fn(|i| {
        let r = results[i];
        [
            u16::from(r.thermal),
            u16::from(r.txagc),
            r.pwsf,
            u16::from(r.gain),
            u16::from(r.correlation_index),
            u16::from(r.correlation),
            r.dc[0],
            r.dc[1],
        ]
    })
}
fn smoke_rtw89_b_dpk_both_paths_after_tssi_match_frozen_references() -> TestResult {
    for &(seed, cut, gain, count, hash, result) in CASES {
        let (tssi, mut model) = source::fixture_with_seed(seed);
        model.reset_trace();
        let mut owner = Dpk::default();
        // SAFETY: same actual source model retained through full preceding
        // TSSI, explicit factory cut and completed basic DPD-gain input.
        if complete(unsafe { owner.prepare(&mut model, cut, gain, &tssi) }) != Some(Ok(()))
            || owner.results().is_none_or(|r| measurements(r) != result)
            || model.count != count
            || model.hash != hash
            || model.kind.is_some()
        {
            return TestResult::Fail(
                "two-path DPK NCTL/AGC/IDL/restoration differs from the frozen post-TSSI reference",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_dpk_both_paths_after_tssi_match_frozen_references
);

fn smoke_rtw89_b_dpk_digital_gain_complete_domain_matches_frozen_references() -> TestResult {
    let mut hash = 14695981039346656037u64;
    for value in 0..4096 {
        for byte in u32::from(dgain_offset(value) as u8).to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1099511628211);
        }
    }
    if hash != DGAIN_HASH {
        return TestResult::Fail(
            "complete12-bit signed DPK gain mapping differs from the frozen reference",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_dpk_digital_gain_complete_domain_matches_frozen_references
);

fn smoke_rtw89_b_dpk_failed_sync_nctl_ignored_controls_and_current_epoch_no_result() -> TestResult {
    for fault in 0..7 {
        let (tssi, mut model) = source::fixture();
        model.reset_trace();
        match fault {
            0 => model.correlation = 169,
            1 => model.dc = [201, 20],
            2 => model.nctl_first_timeout = true,
            3 => model.nctl_second_timeout = true,
            4 => model.ignore = Some((0x18000, u32::MAX)),
            5 => model.ignore = Some((0x10000 + R_DPD_CH0A, 0xff000000)),
            6 => model.authority.revoke(),
            _ => unreachable!(),
        }
        let mut owner = Dpk::default();
        // SAFETY: exact retained inert source profile; rejected hardware
        // measurements/controls/current authority cannot create a result.
        if complete(unsafe { owner.prepare(&mut model, 0, 0x5b, &tssi) }).is_none_or(|r| r.is_ok())
            || owner.results().is_some()
            || fault != 6 && owner.state() != State::Calibrating
        {
            return TestResult::Fail(
                "failed/stale DPK measurements or ignored controls earned completion",
            );
        }
        if fault == 6 && (model.count != 0 || model.operations != 0) {
            return TestResult::Fail("revoked exact DPK epoch touched source registers");
        }
        if fault == 2 && model.now < 20_000 || fault == 3 && model.now < 2000 {
            return TestResult::Fail("NCTL bounded source poll returned before its deadline");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_dpk_failed_sync_nctl_ignored_controls_and_current_epoch_no_result
);

fn smoke_rtw89_b_dpk_stale_ready_ignored_trigger_and_uncleared_completion_are_terminal(
) -> TestResult {
    for fault in 0..4 {
        let (tssi, mut model) = source::fixture();
        model.reset_trace();
        if matches!(fault, 0 | 3) {
            model.words[(0x10000 + R_NCTL_N1) as usize / 4] = 0x55;
        }
        if matches!(fault, 1 | 3) {
            model.ignore = Some((0x10000 + R_NCTL_CFG, u32::MAX));
        }
        if fault == 2 {
            model.ignore = Some((0x10000 + R_NCTL_N1, 255));
        }
        let mut owner = Dpk::default();
        // SAFETY: same retained inert TSSI/DPK owner and actual register-causal
        // status/ignored-write fixture. No status shortcut can create a result.
        let result = complete(unsafe { owner.prepare(&mut model, 0, 0x5b, &tssi) });
        let expected = if fault == 1 {
            Error::Register(power::Error::Timeout)
        } else {
            Error::Terminal
        };
        if result != Some(Err(expected))
            || owner.results().is_some()
            || owner.state() != State::Calibrating
            || model.nctl_commands != usize::from(fault == 2)
            || fault == 2 && model.selector(R_NCTL_N1, 255) != 0x55
        {
            return TestResult::Fail(
                "stale/uncleared NCTL status or ignored trigger earned DPK completion",
            );
        }
        let before = model.count;
        // SAFETY: retained terminal one-shot must reject before additional I/O.
        let replay = complete(unsafe { owner.prepare(&mut model, 0, 0x5b, &tssi) });
        if replay != Some(Err(Error::Terminal)) || model.count != before {
            return TestResult::Fail("failed NCTL freshness reconstructed a DPK owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_dpk_stale_ready_ignored_trigger_and_uncleared_completion_are_terminal
);

fn smoke_rtw89_b_dpk_cancel_and_access_failures_retain_one_shot_owner() -> TestResult {
    let (tssi, mut baseline) = source::fixture();
    baseline.reset_trace();
    let mut owner = Dpk::default();
    // SAFETY: same inert model, native measurements and completed TSSI owner.
    let result = complete(unsafe { owner.prepare(&mut baseline, 0, 0x5b, &tssi) });
    assert_eq!(result, Some(Ok(())));
    for index in [
        0,
        1,
        20,
        100,
        baseline.operations / 2,
        baseline.operations - 5,
        baseline.operations - 1,
    ] {
        let (tssi, mut model) = source::fixture();
        model.reset_trace();
        model.fail = Some(index);
        let mut owner = Dpk::default();
        // SAFETY: one actual source operation fails in the same retained owner.
        if complete(unsafe { owner.prepare(&mut model, 0, 0x5b, &tssi) }).is_none_or(|r| r.is_ok())
            || owner.results().is_some()
            || owner.state() != State::Calibrating
        {
            return TestResult::Fail(
                "actual DPK operation failure exposed completed/reusable result",
            );
        }
    }
    let (tssi, mut model) = source::fixture();
    model.reset_trace();
    model.pending_delay = true;
    let mut owner = Dpk::default();
    {
        // SAFETY: same retained inert source owner, suspended at its real wait.
        let future = unsafe { owner.prepare(&mut model, 0, 0x5b, &tssi) };
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        if !future.as_mut().poll(&mut cx).is_pending() {
            return TestResult::Fail("DPK cancellable NCTL wait fixture");
        }
    }
    let before = model.count;
    // SAFETY: cancelled one-shot must reject before all further device access.
    let replay = complete(unsafe { owner.prepare(&mut model, 0, 0x5b, &tssi) });
    if owner.results().is_some() || replay != Some(Err(Error::Terminal)) || model.count != before {
        return TestResult::Fail("cancelled DPK restarted or earned calibration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_dpk_cancel_and_access_failures_retain_one_shot_owner
);
