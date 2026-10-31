//! Genuine MLME/RSNA plus the retained native suspend
//! implementation, with an explicitly admitted test-only platform route.
use super::*;
use alloc::boxed::Box;
use narf_power::system_pm::SystemSleepState;
use narf_wireless::{WowlanConfig, WowlanPattern};

#[path = "wowlan_nlo_runtime_tests.rs"]
mod nlo;

#[inline(never)]
fn joined(secure: bool) -> Result<NativeSession, &'static str> {
    let (mut session, bss) = super::ht20_tests::prepared(6, secure);
    run(Box::pin(session.associate_station(
        &bss,
        b"narf",
        if secure {
            crate::mt7921::association::Security::Wpa2Psk { psk: [0x55; 32] }
        } else {
            crate::mt7921::association::Security::Open
        },
        test_permission(),
        &[],
    )))
    .map_err(|_| "WoW genuine station fixture")?;
    session.backend.pm.dma_enabled = true;
    Ok(session)
}

fn config() -> WowlanConfig {
    WowlanConfig {
        disconnect: true,
        magic_packet: true,
        patterns: vec![WowlanPattern {
            mask: vec![0xff, 1],
            pattern: b"real-wake".to_vec(),
            offset: 0,
        }],
        ..WowlanConfig::default()
    }
}

fn uni(frame: &[u8], id: u16) -> Option<&[u8]> {
    (frame.len() > 48 && frame[43] == 7 && frame[34..36] == id.to_le_bytes()).then(|| &frame[48..])
}

fn handoff() -> Result<(), &'static str> {
    use super::wowlan_model::Power;
    for secure in [false, true] {
        for target in [SystemSleepState::S0Idle, SystemSleepState::S3] {
            let mut session = joined(secure)?;
            let info = match session.state {
                State::Associated { info, .. } => info,
                _ => return Err("WoW fixture not associated"),
            };
            // Normal models cannot grant a route. This fixture admission is
            // absent from Hardware and follows a separate native PciWake
            // composite test over actual ECAM/AML/GPE primitives.
            let before = session.backend.frames.len();
            if run(Box::pin(session.suspend_wowlan(&config(), target)))
                != Err(Error::UnsupportedFirmware)
                || session.backend.frames.len() != before
                || !matches!(session.state, State::Associated { .. })
            {
                return Err("missing platform authority did not precede radio commands");
            }
            session.backend.pm.wow.route_available = true;
            let epoch = session.receive_epoch;
            let gtk = session
                .security
                .as_ref()
                .map(|security| security.wow_gtk_update())
                .transpose()
                .map_err(|_| "genuine current RSNA not exportable")?;
            run(Box::pin(session.suspend_wowlan(&config(), target)))
                .map_err(|_| "native associated WoW handoff failed")?;
            let frames = &session.backend.frames[before..];
            let offload: Vec<&[u8]> = frames.iter().filter_map(|(_, f)| uni(f, 6)).collect();
            let suspend: Vec<&[u8]> = frames.iter().filter_map(|(_, f)| uni(f, 5)).collect();
            let rekey = offload
                .iter()
                .find(|body| body.len() == 76 && body[48] == 2);
            if gtk
                .as_ref()
                .is_some_and(|expected| rekey.is_none_or(|actual| actual != &&expected[..]))
                || gtk.is_none() && rekey.is_some()
                || !offload
                    .iter()
                    .any(|body| body.len() == 76 && body[48] == u8::from(!secure))
                || !offload.iter().any(|body| body.len() == 12 && body[8] == 1)
                || !suspend.iter().any(|body| {
                    body.len() == 16 && body[4..8] == [0, 0, 12, 0] && body[8..11] == [1, 1, 1]
                })
                || !suspend.iter().any(|body| {
                    body.len() == 160
                        && body[4..8] == [4, 0, 156, 0]
                        && body[8..12] == [0, 1, 9, 0]
                        && body[12..14] == [0xff, 1]
                        && &body[28..37] == b"real-wake"
                })
                || !suspend.iter().any(|body| {
                    body.len() == 32
                        && body[8..12] == [1, 0x55, 2, 0]
                        && body[16..21] == [2, 0, 16, 0, 0xff]
                })
                || frames.iter().any(|(_, frame)| frame.first() == Some(&0xc0))
                || frames
                    .iter()
                    .any(|(_, frame)| uni(frame, 2).is_some_and(|body| body.get(8) == Some(&0)))
                || !matches!(session.state, State::WowSuspended { .. })
                || session.backend.pm.trace
                    != ["route-probe", "dma-off", "fw-own", "pme-arm", "d3hot"]
                || session.backend.pm.wow.target != Some(target)
                || session.backend.pm.wow.power != Power::D3Hot
                || !session.backend.pm.wow.armed
                || session.backend.receive_open
                || session.receive_current(epoch) != Ok(false)
                || session.start_ethernet(&[0; 14]) != Err(Error::Busy)
            {
                return Err(
                    "WoW skipped native TLVs, retained association, actual target or closed RX",
                );
            }
            run(Box::pin(session.resume_wowlan(info.capabilities.mac)))
                .map_err(|_| "native WoW resume reset failed")?;
            let d0 = session
                .backend
                .pm
                .trace
                .iter()
                .position(|step| *step == "d0");
            let disarm = session
                .backend
                .pm
                .trace
                .iter()
                .position(|step| *step == "pme-disarm");
            if !matches!((d0, disarm), (Some(a), Some(b)) if a < b)
                || session.backend.pm.wow.power != Power::D0
                || session.backend.pm.wow.armed
                || session.state != State::RadioReady(info)
                || session.security.is_some()
                || session.station_permission.is_some()
                || session.backend.receive_open
                || !session
                    .backend
                    .recovery_trace
                    .iter()
                    .any(|(step, _)| *step == "assert")
            {
                return Err(
                    "WoW resumed stale firmware keys/replay or skipped D0/route/reset retirement",
                );
            }
        }
    }
    Ok(())
}

fn mt76_wow_native_associated_handoff_and_reset_resume() -> TestResult {
    handoff().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/wowlan",
    mt76_wow_native_associated_handoff_and_reset_resume
);

fn cancellation() -> Result<(), &'static str> {
    use super::wowlan_model::Power;
    let mut session = joined(true)?;
    let State::Associated { info, .. } = session.state else {
        return Err("WoW cancellation not associated");
    };
    session.backend.pm.wow.route_available = true;
    session.backend.tick_step_ns = 0;
    {
        let config = config();
        let mut future = Box::pin(session.suspend_wowlan(&config, SystemSleepState::S0Idle));
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("physical D3 interval did not remain pending");
        }
    }
    let at = session
        .backend
        .pm
        .wow
        .written_at
        .ok_or("D3 timestamp lost at cancellation")?;
    if session.backend.pm.wow.power != Power::EnteringD3
        || !matches!(session.state, State::Running(Stage::WowSuspend))
        || session.backend.wow_begin_d0() != Err(Error::Busy)
        || session.backend.receive_open
        || session.start_ethernet(&[0; 14]) != Err(Error::Busy)
    {
        return Err("cancelled D3 entry admitted config/RX or lost retained power ownership");
    }
    session.backend.tick_step_ns = 1_000_000;
    run(Box::pin(session.recover(info.capabilities.mac)))
        .map_err(|_| "cancelled D3 entry could not normalize and recover")?;
    if session.backend.ticks.get().saturating_sub(at) < 20_000_000
        || session.backend.pm.wow.power != Power::D0
        || session.backend.pm.wow.armed
        || session.state != State::RadioReady(info)
        || session.security.is_some()
    {
        return Err("recovery shortened entry/exit delays or reopened the old RSNA");
    }
    Ok(())
}

fn mt76_wow_cancelled_power_entry_retains_delay_and_fences_old_rsna() -> TestResult {
    cancellation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/wowlan",
    mt76_wow_cancelled_power_entry_retains_delay_and_fences_old_rsna
);
