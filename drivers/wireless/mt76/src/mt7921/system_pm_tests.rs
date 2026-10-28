//! System suspend/resume of the retained owner (Linux mt7921_pci_suspend /
//! mt7921_pci_resume, mt792x_wpdma_reinit_cond, mt792x_reset fallback).
use super::*;

fn ce_body(frame: &[u8], id: u8) -> Option<&[u8]> {
    (frame.len() > 64 && frame[36] == id && frame[43] != 7).then(|| &frame[64..])
}
fn uni_body(frame: &[u8], id: u16) -> Option<&[u8]> {
    (frame.len() > 48 && frame[43] == 7 && frame[34..36] == id.to_le_bytes()).then(|| &frame[48..])
}

fn radio_model() -> (Session<Model>, RadioInfo) {
    let mut session = Session::new(Model::new(), firmware(32));
    run(session.run()).unwrap();
    let info = run(session.initialize_radio()).unwrap();
    (session, info)
}

fn mt76_system_suspend_leaves_station_stops_vif_and_hands_off_ownership() -> TestResult {
    let mut session = secure_model();
    let State::Associated { info, .. } = session.state else {
        unreachable!()
    };
    session.backend.pm.dma_enabled = true;
    let start = session.backend.frames.len();
    if run(session.suspend()).is_err() || session.state != State::Suspended(info) {
        return TestResult::Fail("associated MT76 radio did not reach the suspended handoff");
    }
    let frames: Vec<&[u8]> = session.backend.frames[start..]
        .iter()
        .map(|(_, frame)| frame.as_slice())
        .collect();
    let deauth = frames.iter().position(|frame| frame.first() == Some(&0xc0));
    let bss_off = frames
        .iter()
        .rposition(|frame| uni_body(frame, 2).is_some_and(|body| body[8] == 0));
    let dev_off = frames.iter().rposition(|frame| {
        uni_body(frame, 1).is_some_and(|body| body[8] == 0 && body[10..16] == info.capabilities.mac)
    });
    let mac_off = frames.iter().rposition(|frame| {
        frame.len() >= 68 && frame[36] == 0xed && frame[41] == 0x46 && frame[64..68] == [0; 4]
    });
    let deep = frames.iter().rposition(|frame| {
        ce_body(frame, 0xca)
            .is_some_and(|body| body.len() == 328 && &body[8..22] == b"KeepFullPwr 0\0")
    });
    let hif = frames.iter().rposition(|frame| {
        uni_body(frame, 7)
            .is_some_and(|body| body == [2, 0, 0, 0, 0, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0])
    });
    let ordered = matches!(
        (deauth, bss_off, dev_off, mac_off, deep, hif),
        (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) if a < b && b < c && c < d && d < e && e < f
    );
    if !ordered
        || session.backend.pm.trace != ["dma-off", "fw-own"]
        || session.backend.pm.dma_enabled
        || !session.backend.pm.firmware_owned
        || session.security.is_some()
        || session.station_permission.is_some()
        || session.start_ethernet(&[0; 14]) != Err(Error::Busy)
        || !session.backend.owner.published
    {
        return TestResult::Fail(
            "MT76 suspend skipped leave/VIF stop/deep sleep/HIF suspend or ownership handoff",
        );
    }
    // A repeated platform prepare is idempotent and touches no hardware.
    let frames_now = session.backend.frames.len();
    if run(session.suspend()).is_err() || session.backend.frames.len() != frames_now {
        return TestResult::Fail("repeated MT76 suspend reissued firmware commands");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/power",
    mt76_system_suspend_leaves_station_stops_vif_and_hands_off_ownership
);

fn mt76_system_resume_reenables_retained_dma_and_requires_fresh_station() -> TestResult {
    let (mut session, info) = radio_model();
    session.backend.pm.dma_enabled = true;
    if run(session.resume(info.capabilities.mac)) != Err(Error::Busy) {
        return TestResult::Fail("resume accepted a radio that was never suspended");
    }
    run(session.suspend()).unwrap();
    // RadioReady has no firmware VIF to remove.
    if session
        .backend
        .frames
        .iter()
        .any(|(_, frame)| uni_body(frame, 1).is_some())
    {
        return TestResult::Fail("suspend removed a VIF that was never created");
    }
    let mut other = info.capabilities.mac;
    other[5] ^= 1;
    if run(session.resume(other)) != Err(Error::InvalidIdentity)
        || session.state != State::Suspended(info)
        || run(session.resume([1, 0, 0, 0, 0, 0])) != Err(Error::Bounds)
    {
        return TestResult::Fail("resume accepted a different or invalid radio identity");
    }
    session.events.push_back(vec![0x44; 36]);
    let start = session.backend.frames.len();
    session.backend.pm.trace.clear();
    if run(session.resume(info.capabilities.mac)) != Ok(info)
        || session.state != State::RadioReady(info)
    {
        return TestResult::Fail("retained MT76 resume did not return the idle radio");
    }
    let frames: Vec<&[u8]> = session.backend.frames[start..]
        .iter()
        .map(|(_, frame)| frame.as_slice())
        .collect();
    let deep = frames.iter().position(|frame| {
        ce_body(frame, 0xca).is_some_and(|body| &body[8..22] == b"KeepFullPwr 1\0")
    });
    let hif = frames
        .iter()
        .position(|frame| uni_body(frame, 7).is_some_and(|body| body[0] == 2 && body[8] == 0));
    if session.backend.pm.trace != ["bus", "dma-on"]
        || !matches!((deep, hif), (Some(a), Some(b)) if a < b)
        || session.backend.pm.firmware_owned
        || !session.events.is_empty()
        || session
            .backend
            .recovery_trace
            .iter()
            .any(|(label, _)| *label == "assert")
    {
        return TestResult::Fail("retained resume reset, reinitialized or skipped HIF resume");
    }
    // Stopped VIF/MAC: the next scan repeats the full setup.
    let before = session.backend.frames.len();
    if run(session.scan_passive(&[6])).is_err()
        || !session.backend.frames[before..]
            .iter()
            .any(|(_, frame)| uni_body(frame, 1).is_some_and(|body| body[8] == 1))
    {
        return TestResult::Fail("resumed radio did not recreate its firmware VIF on scan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/power",
    mt76_system_resume_reenables_retained_dma_and_requires_fresh_station
);

fn mt76_system_resume_reinitializes_lost_wfdma_or_resets_lost_firmware() -> TestResult {
    // WFDMA lost its DUMMY_CR marker: rings are retired only after disable
    // and idle proof, and the firmware is kept.
    let (mut session, info) = radio_model();
    session.backend.pm.dma_enabled = true;
    run(session.suspend()).unwrap();
    session.backend.pm.lose_dma = true;
    session.backend.pm.trace.clear();
    session.backend.packets.push_back(vec![0x55; 36]);
    if run(session.resume(info.capabilities.mac)) != Ok(info)
        || session.backend.pm.trace != ["bus", "reinit"]
        || !session.backend.packets.is_empty()
        || session
            .backend
            .recovery_trace
            .iter()
            .any(|(label, _)| *label == "assert")
    {
        return TestResult::Fail("lost WFDMA was not reinitialized on the retained firmware");
    }
    // Firmware lost across D3cold: the mt792x_reset fallback reboots it and
    // requires the same identity.
    let (mut session, info) = radio_model();
    run(session.suspend()).unwrap();
    session.backend.pm.lose_firmware = true;
    let start = session.backend.recovery_trace.len();
    if run(session.resume(info.capabilities.mac)).map(|radio| radio.capabilities.mac)
        != Ok(info.capabilities.mac)
        || !matches!(session.state, State::RadioReady(_))
        || !session.backend.recovery_trace[start..]
            .iter()
            .any(|(label, _)| *label == "assert")
    {
        return TestResult::Fail("lost firmware did not fall back to verified reset recovery");
    }
    // A revoked device is never reset blindly.
    let (mut session, info) = radio_model();
    run(session.suspend()).unwrap();
    session.backend.live = false;
    if run(session.resume(info.capabilities.mac)) != Err(Error::Authority)
        || !matches!(
            session.state,
            State::Failed {
                stage: Stage::Resume,
                error: Error::Authority
            }
        )
        || !session.backend.owner.published
    {
        return TestResult::Fail("revoked device resume released DMA or attempted reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/power",
    mt76_system_resume_reinitializes_lost_wfdma_or_resets_lost_firmware
);

fn mt76_system_suspend_failure_restores_usable_radio() -> TestResult {
    let (mut session, info) = radio_model();
    session.backend.pm.dma_enabled = true;
    session.backend.pm.firmware_own_stall = true;
    if run(session.suspend()) != Err(Error::Timeout)
        || session.state != State::RadioReady(info)
        || !session.backend.pm.dma_enabled
        || session
            .backend
            .pm
            .trace
            .iter()
            .filter(|step| **step == "fw-own")
            .count()
            != 10
    {
        return TestResult::Fail("failed firmware-own handoff left DMA off or radio unusable");
    }
    if run(session.scan_passive(&[6])).is_err() {
        return TestResult::Fail("radio restored after failed suspend cannot scan");
    }
    // The undo itself failing leaves a terminal owner for verified reset.
    let (mut session, _) = radio_model();
    session.backend.pm.firmware_own_stall = true;
    session.backend.pm.driver_own_stall = true;
    session.backend.pm.firmware_owned = true;
    if run(session.suspend()) != Err(Error::Timeout)
        || !matches!(
            session.state,
            State::Failed {
                stage: Stage::Suspend,
                ..
            }
        )
        || !session.backend.owner.published
    {
        return TestResult::Fail("failed suspend undo reported a usable radio");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/power",
    mt76_system_suspend_failure_restores_usable_radio
);

fn mt76_owned_suspend_survives_cancelled_waiter() -> TestResult {
    let session = secure_model();
    let mut work = KeyWork {
        future: Some(alloc::boxed::Box::pin(async move {
            let mut session = session;
            let result = session.suspend().await;
            (session, result)
        })),
        completed: None,
    };
    let mut cx = Context::from_waker(Waker::noop());
    {
        // Poll once through a waiter that is then dropped.
        let mut waiter = pin!(poll_fn(|cx| work.poll(cx)));
        let _ = waiter.as_mut().poll(&mut cx);
    }
    for _ in 0..10_000 {
        if work.poll(&mut cx).is_ready() {
            break;
        }
    }
    let Some((session, result)) = work.completed.take() else {
        return TestResult::Fail("owned suspend stopped when its waiter was cancelled");
    };
    if result.is_err()
        || !matches!(session.state, State::Suspended(_))
        || !session.backend.pm.firmware_owned
    {
        return TestResult::Fail("cancelled suspend waiter left a partial handoff");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/power",
    mt76_owned_suspend_survives_cancelled_waiter
);

fn mt76_pci_removal_retires_proven_dma_and_keeps_uncertain_rings() -> TestResult {
    // Associated owner: removal fences keys/ports, stops DMA, proves idle and
    // unpublishes before the ring memory may be returned.
    let mut session = secure_model();
    let resources = session.backend.resources.clone();
    if !session.retire_removed()
        || session.state != State::Stopped
        || session.backend.owner.published
        || session.security.is_some()
        || session.station_permission.is_some()
        || session.backend.receive_open
        || session.start_ethernet(&[0; 14]) != Err(Error::Busy)
    {
        return TestResult::Fail("MT76 removal left a published ring or live station grant");
    }
    drop(session);
    if resources.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("proven MT76 removal did not return ring memory");
    }
    // DMA never proved idle (or the device is gone): rings stay retained.
    for revoked in [false, true] {
        let mut session = secure_model();
        let resources = session.backend.resources.clone();
        session.backend.idle_stall = !revoked;
        session.backend.live = !revoked;
        if session.retire_removed()
            || !matches!(
                session.state,
                State::Failed {
                    stage: Stage::Shutdown,
                    ..
                }
            )
            || !session.backend.owner.published
        {
            return TestResult::Fail("unproven MT76 removal reported retired DMA");
        }
        drop(session);
        if resources.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("unproven MT76 removal freed device-visible rings");
        }
    }
    // A transport that never published rings retires trivially.
    let mut session = Session::new(Model::new(), firmware(32));
    if !session.retire_removed() || session.state != State::Stopped {
        return TestResult::Fail("unstarted MT76 transport did not retire on removal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/lifecycle",
    mt76_pci_removal_retires_proven_dma_and_keeps_uncertain_rings
);

fn mt76_reprobe_generation_never_republishes_or_unclaims_stale_owner() -> TestResult {
    // Completed retained work of a removed generation is retired, never
    // installed as the new binding's owner.
    let retired = Cell::new(false);
    let session = secure_model();
    match admit_completed(session, 1, 2, |mut stale: Session<Model>| {
        retired.set(stale.retire_removed() && stale.state == State::Stopped);
    }) {
        Err(Error::DeviceGone) if retired.get() => {}
        _ => return TestResult::Fail("stale-generation MT76 owner was republished"),
    }
    let session = secure_model();
    if admit_completed(session, 3, 3, |_| retired.set(false)).is_err() || !retired.get() {
        return TestResult::Fail("current-generation MT76 owner was retired");
    }
    // Claim isolation uses the real binding statics; skip on real hardware.
    if crate::mt7921::pci::is_probed() {
        return TestResult::Pass;
    }
    let saved = crate::mt7921::pci::__swap_claim_for_test((true, 1, 2));
    crate::mt7921::pci::release_transport_claim(3);
    let newer_kept = crate::mt7921::pci::__claimed_for_test();
    crate::mt7921::pci::release_transport_claim(1);
    let stale_released = !crate::mt7921::pci::__claimed_for_test();
    // No binding: claiming never fabricates a transport.
    let unbound = matches!(crate::mt7921::pci::claim_firmware_transport(), Ok(None));
    crate::mt7921::pci::__swap_claim_for_test(saved);
    if !newer_kept || !stale_released || !unbound {
        return TestResult::Fail("MT76 claim generation isolation failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/lifecycle",
    mt76_reprobe_generation_never_republishes_or_unclaims_stale_owner
);
