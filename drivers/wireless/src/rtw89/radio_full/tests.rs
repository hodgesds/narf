use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
#[path = "model.rs"]
mod model;
use crate::rtw89::tssi::tests::{calibration, complete, tracking};
use model::Model;
fn gain() -> radio_gain::Gain {
    let selected =
        super::super::radio_table::program(super::super::radio_tables_b::GAIN, 1, 0).unwrap();
    radio_gain::Gain::decode(&selected, 1).unwrap()
}
fn input<'a>(
    gain: &'a radio_gain::Gain,
    calibration: &'a factory_b::Calibration,
    power: &'a radio_power::Plan,
    tracking: &'a tssi::Tracking,
) -> Inputs<'a> {
    Inputs {
        gain,
        calibration,
        gain_bases: [-30, 46],
        cut: 0,
        dpd_gain: 0x5b,
        power,
        tracking,
    }
}
fn smoke_rtw89_b_full_radio_runs_actual_components_on_same_current_register_owner() -> TestResult {
    let gain = gain();
    let mut calibration = calibration(false);
    let power = radio_power::Plan::fixture_defaults().unwrap();
    let tracking = tracking(false);
    calibration.thermal_programmed = true;
    calibration.thermal_trim = [0x11, 0x1d];
    calibration.pa_programmed = true;
    calibration.pa_bias = [0x42, 0x37];
    let mut io = Model::new();
    let original = io.backings();
    let mut radio = Radio::default();
    // SAFETY: one inert exact initial-profile port, actual selected static gain
    // table/parsed source power inputs and explicit physical/CW/NCTL fixtures.
    if complete(unsafe { radio.prepare(&mut io, input(&gain, &calibration, &power, &tracking)) })
        != Some(Ok(()))
        || radio.state() != State::Ready
        || io.backings() != original
        || radio.transition.state() != channel_transition::State::Finished
        || radio.trim.state() != radio_trim::State::Applied
        || radio.bb.state() != channel_bb::State::Configured
        || radio.rf.state() != channel_rf::State::SynthConfigured
        || radio.iqk.results().is_none_or(|r| r.failures != 0)
        || radio.tssi.results().is_none()
        || radio.dpk.results().is_none()
        || io.pauses != 6
        || io.resumes != 6
        || io.paused
        || io.base.kind.is_some()
        || io.base.now < 60_000
    {
        return TestResult::Fail("full radio skipped an actual component, changed register owner or lost scheduler restoration");
    }
    if io.starts
        != vec![
            rfk::Kind::Rxdck,
            rfk::Kind::Iqk,
            rfk::Kind::IqkPath,
            rfk::Kind::IqkPath,
            rfk::Kind::Tssi,
            rfk::Kind::Dpk,
        ]
        || io.ends
            != vec![
                rfk::Kind::Rxdck,
                rfk::Kind::IqkPath,
                rfk::Kind::IqkPath,
                rfk::Kind::Iqk,
                rfk::Kind::Tssi,
                rfk::Kind::Dpk,
            ]
        || io.base.words[0xc000 / 4] & (1 << 29) != 0
        || io.base.words[0x1010 / 4] & (1 << 8 | 1 << 16 | 1 << 19) != 1 << 8 | 1 << 16 | 1 << 19
    {
        return TestResult::Fail(
            "actual radio pipeline reordered RFK or enabled ordinary CMAC/DMA",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_radio_runs_actual_components_on_same_current_register_owner
);

fn smoke_rtw89_b_full_radio_access_policy_epoch_and_stage_failures_never_ready() -> TestResult {
    let gain = gain();
    let calibration = calibration(false);
    let power = radio_power::Plan::fixture_defaults().unwrap();
    let tracking = tracking(false);
    let mut base = Model::new();
    let mut radio = Radio::default();
    // SAFETY: same explicit inert source inputs used only to obtain coverage
    // boundaries; every following case executes the actual full pipeline anew.
    let result = complete(unsafe {
        radio.prepare(&mut base, input(&gain, &calibration, &power, &tracking))
    });
    assert_eq!(result, Some(Ok(())));
    for fault in 0..10 {
        let mut io = Model::new();
        let mut radio = Radio::default();
        match fault {
            0 => io.fail = Some(0),
            1 => io.fail = Some(100),
            2 => io.fail = Some(base.operations / 2),
            3 => io.fail = Some(base.operations - 2),
            4 => io.deny = Some(0),
            5 => io.deny = Some(base.admissions / 2),
            6 => io.authority().revoke(),
            7 => io.lock_stuck = true,
            8 => io.base.cw_timeout = true,
            9 => io.base.correlation = 169,
            _ => unreachable!(),
        }
        // SAFETY: fault/epoch/status injection acts on the same exclusive port;
        // component receipts are produced only by their real source protocols.
        if complete(unsafe {
            radio.prepare(&mut io, input(&gain, &calibration, &power, &tracking))
        })
        .is_none_or(|r| r.is_ok())
            || radio.state() != State::Preparing
        {
            return TestResult::Fail("actual full radio component/policy failure earned Ready");
        }
        let before = io.operations;
        // SAFETY: a failed one-shot must reject before all additional access.
        if complete(unsafe {
            radio.prepare(&mut io, input(&gain, &calibration, &power, &tracking))
        }) != Some(Err(power::Error::Terminal))
            || io.operations != before
        {
            return TestResult::Fail("failed full radio reconstructed/replayed lower owners");
        }
        if matches!(fault, 4 | 6) && io.operations != 0 {
            return TestResult::Fail(
                "pre-transition policy/revoked epoch touched native registers",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_radio_access_policy_epoch_and_stage_failures_never_ready
);

fn smoke_rtw89_b_full_radio_cancelled_real_pmac_wait_retains_incomplete_owner() -> TestResult {
    let gain = gain();
    let calibration = calibration(false);
    let power = radio_power::Plan::fixture_defaults().unwrap();
    let tracking = tracking(false);
    let mut io = Model::new();
    io.base.cw_timeout = true;
    io.hold_delay = Some(30);
    let mut radio = Radio::default();
    {
        // SAFETY: exact retained source pipeline, suspended only after real
        // PMAC register publication and an actual not-ready CW observation.
        let future =
            unsafe { radio.prepare(&mut io, input(&gain, &calibration, &power, &tracking)) };
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        if !future.as_mut().poll(&mut cx).is_pending() {
            return TestResult::Fail("full-radio PMAC cancellation fixture did not wait");
        }
    }
    let before = io.operations;
    if radio.state() != State::Preparing
        || radio.tssi.state() != tssi::State::Calibrating
        || radio.tssi.results().is_some()
        || radio.dpk.results().is_some()
        || io.base.kind != Some(rfk::Kind::Tssi)
    {
        return TestResult::Fail("cancelled real PMAC wait exposed completed radio/TSSI/DPK");
    }
    // SAFETY: one-shot owner remains retained and refuses every replay.
    if complete(unsafe { radio.prepare(&mut io, input(&gain, &calibration, &power, &tracking)) })
        != Some(Err(power::Error::Terminal))
        || io.operations != before
    {
        return TestResult::Fail("cancelled full radio replayed hardware preparation");
    }
    io.hold_delay = None;
    if tssi::stop_pmac(&mut io).is_err() {
        return TestResult::Fail("terminal retained PMAC model cannot close source engines");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_radio_cancelled_real_pmac_wait_retains_incomplete_owner
);
