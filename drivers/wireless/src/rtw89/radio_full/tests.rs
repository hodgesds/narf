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
/// Linux core.c `__rtw89_set_channel` then rtw8852b.c `rtw8852b_rfk_channel`
/// on a Ready owner: every step reruns on the actual primary, DE uses that
/// primary's TSSI groups, R_IQKCH records it and the retained epoch advances.
fn smoke_rtw89_b_full_radio_retunes_ready_owner_to_actual_primary_and_advances_epoch() -> TestResult
{
    use crate::rtw89::operating_channel::Profile;
    use narf_wireless::association::channel::Band;
    let gain = gain();
    let mut calibration = calibration(false);
    calibration.thermal_programmed = true;
    calibration.thermal_trim = [0x11, 0x1d];
    calibration.pa_programmed = true;
    calibration.pa_bias = [0x42, 0x37];
    for path in 0..2 {
        calibration.tssi_cck[path][2] = [7, -6][path];
        calibration.tssi_mcs[path][2] = [-13, 12][path];
        calibration.tssi_cck[path][3] = [9, -8][path];
        calibration.tssi_mcs[path][3] = [-15, 14][path];
        calibration.tssi_trim[path][1] = [3, -1][path];
    }
    let initial = radio_power::Plan::fixture_defaults().unwrap();
    let tracking = tracking(false);
    let mut io = Model::new();
    let mut radio = Radio::default();
    let plan = |primary| {
        Profile::new(Band::Ghz2, primary)
            .and_then(|profile| radio_power::Plan::fixture_defaults_for_channel(profile).ok())
    };
    let (Some(six), Some(eleven)) = (plan(6), plan(11)) else {
        return TestResult::Fail("typed noninitial power fixtures");
    };
    // SAFETY: a New owner can never be retuned; nothing touches the model.
    if complete(unsafe { radio.retune(&mut io, input(&gain, &calibration, &six, &tracking)) })
        != Some(Err(power::Error::Terminal))
        || radio.state() != State::New
        || io.operations != 0
    {
        return TestResult::Fail("retune admitted a radio that never completed bring-up");
    }
    // SAFETY: one inert exact initial-profile port with explicit fixtures.
    if complete(unsafe { radio.prepare(&mut io, input(&gain, &calibration, &initial, &tracking)) })
        != Some(Ok(()))
        || radio.channel() != Some(Profile::INITIAL)
        || radio.epoch() != 1
    {
        return TestResult::Fail("initial bring-up did not retain channel1 epoch1");
    }
    let iqkch = (0x10000 + 0x9fe4) / 4;
    let de =
        |io: &Model, address: u32| (io.base.words[(0x10000 + address) as usize / 4] >> 12) & 0x3ff;
    for (epoch, primary, power, group, trim) in [(2, 6u8, &six, 2, 0), (3, 11, &eleven, 3, 1)] {
        let starts = io.starts.len();
        // SAFETY: same inert retained owner; caller-closed TX is modelled by the
        // unchanged CMAC/DMA words checked below.
        if complete(unsafe { radio.retune(&mut io, input(&gain, &calibration, power, &tracking)) })
            != Some(Ok(()))
            || radio.state() != State::Ready
            || radio.channel() != Profile::new(Band::Ghz2, primary)
            || radio.epoch() != epoch
            || radio.bb.state() != channel_bb::State::Configured
            || radio.rf.state() != channel_rf::State::SynthConfigured
            || radio.iqk.results().is_none()
            || radio.dpk.results().is_none()
            || io.paused
            || io.base.kind.is_some()
        {
            return TestResult::Fail("retune did not complete every source step on the owner");
        }
        if io.starts[starts..]
            != [
                rfk::Kind::Rxdck,
                rfk::Kind::Iqk,
                rfk::Kind::IqkPath,
                rfk::Kind::IqkPath,
                rfk::Kind::Tssi,
                rfk::Kind::Dpk,
            ]
            || io.base.words[0xc000 / 4] & (1 << 29) != 0
            || io.base.words[0x1010 / 4] & (1 << 8 | 1 << 16 | 1 << 19)
                != 1 << 8 | 1 << 16 | 1 << 19
        {
            return TestResult::Fail("retune reordered channel RFK or opened CMAC/DMA");
        }
        let word = io.base.words[iqkch];
        if (word >> 8) & 0xff != u32::from(primary) || (word >> 24) & 0xff != u32::from(primary) {
            return TestResult::Fail("IQK did not record the actual primary");
        }
        let Some(results) = radio.tssi.results() else {
            return TestResult::Fail("retune TSSI results");
        };
        for path in 0..2usize {
            let t = i16::from(calibration.tssi_trim[path][trim]);
            let expected = [
                i16::from(calibration.tssi_cck[path][group]) + t,
                i16::from(calibration.tssi_mcs[path][group]) + t,
            ];
            let offset = (path as u32) << 13;
            if results.de[path] != expected
                || de(&io, 0x5858 + offset) != expected[0] as u32 & 0x3ff
                || de(&io, 0x5838 + offset) != expected[1] as u32 & 0x3ff
            {
                return TestResult::Fail("TSSI DE did not use the primary's Linux groups");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_radio_retunes_ready_owner_to_actual_primary_and_advances_epoch
);
