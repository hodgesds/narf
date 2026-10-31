//! Actual registered DOWN wdev authority and native MCU/reset ownership.
//! The model implements hardware receipts; it cannot grant a radio role.
use super::*;
use narf_wireless::ap_control::RadioControlAuthority;
#[path = "p2p_roc_tests.rs"]
mod roc;

fn radio(fixture: &Fixture) -> Result<RadioControlAuthority, WirelessError> {
    RadioControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        fixture.source.clone(),
    )
}
fn device(cnm: bool, mode: u32) -> Result<(NativeSession, Fixture), &'static str> {
    let base = firmware(32);
    let firmware = if cnm {
        Firmware::prepare(&base.patch, &super::super::p2p::wm_features(0x80))
            .map_err(|_| "actual CNM release artifact")?
    } else {
        base
    };
    let mut session = Box::new(Session::new(Model::new(), firmware));
    run(session.run()).map_err(|_| "P2P actual firmware boot")?;
    let info = run(session.initialize_radio()).map_err(|_| "P2P actual radio initialization")?;
    let fixture = fixture_for(info.capabilities.mac, mode, false)?;
    Ok((session, fixture))
}
fn reserved(fixture: &Fixture) -> Result<Arc<RadioControlAuthority>, &'static str> {
    radio(fixture)
        .and_then(RadioControlAuthority::reserve)
        .map(Arc::new)
        .map_err(|_| "actual delegated P2P reservation")
}
fn start() -> Result<(), &'static str> {
    let (mut session, fixture) = device(true, 10)?;
    let authority = reserved(&fixture)?;
    let first = session.backend.frames.len();
    run(Box::pin(session.start_p2p_device(authority.clone())))
        .map_err(|_| "P2P native DEV/BSS start")?;
    let frames = &session.backend.frames[first..];
    let dev = frames
        .iter()
        .filter_map(|(_, f)| uni(f, 1))
        .find(|body| body.len() == 16 && body[8] == 1)
        .ok_or("P2P native DEV active receipt")?;
    let bss = frames
        .iter()
        .filter_map(|(_, f)| uni(f, 2))
        .find(|body| body.len() == 36 && body[12..16] == [2, 0, 2, 0])
        .ok_or("P2P native device connection receipt")?;
    let mut expected_dev = [0u8; 16];
    expected_dev[6] = 12;
    expected_dev[8] = 1;
    expected_dev[10..16].copy_from_slice(&fixture.radio.mac());
    let mut expected_bss = [0u8; 36];
    expected_bss[6] = 32;
    expected_bss[8] = 1;
    expected_bss[12..16].copy_from_slice(&[2, 0, 2, 0]);
    expected_bss[16] = 1;
    if dev != expected_dev
        || bss != expected_bss
        || frames
            .iter()
            .filter_map(|(_, f)| uni(f, 2))
            .any(|b| b.get(4..6) == Some(&[7, 0]))
        || !matches!(session.state, State::P2pDevice(_))
        || session.backend.receive_open
        || session.security.is_some()
        || !session.data_pending.is_empty()
        || narf_net::iface::lookup(fixture.radio.name())
            .is_none_or(|link| link.link_up || link.carrier)
    {
        return Err("P2P device invented UP/AP beacon/peer/key/packet authority");
    }
    let foreign = fixture_for(fixture.radio.mac(), 10, false)?;
    let foreign_authority = reserved(&foreign)?;
    let before = session.backend.frames.len();
    if session.commit_p2p_device(&foreign_authority).err() != Some(Error::Authority)
        || run(Box::pin(session.stop_p2p_device(&foreign_authority))) != Err(Error::Authority)
        || session.backend.frames.len() != before
    {
        return Err("current same-MAC foreign wdev changed native P2P owner");
    }
    let identity = session
        .commit_p2p_device(&authority)
        .map_err(|_| "actual P2P start publication")?;
    if !session
        .p2p_owner
        .as_ref()
        .is_some_and(|owner| owner.activated && owner.pending.is_none())
    {
        return Err("P2P device did not publish only after native completion");
    }
    drop(authority);
    let stop = reserved(&fixture)?;
    let first = session.backend.frames.len();
    run(Box::pin(session.stop_p2p_device(&stop))).map_err(|_| "P2P native stop/reset")?;
    let disabled: Vec<_> = session.backend.frames[first..]
        .iter()
        .filter_map(|(_, f)| uni(f, 2))
        .filter(|body| body.len() == 36 && body[8] == 0)
        .collect();
    if disabled.len() != 1
        || disabled[0][24..26] != [19, 0]
        || disabled[0][30..32] != [19, 0]
        || session.p2p_owner.is_some()
        || !matches!(session.state, State::RadioReady(_))
        || identity.current().is_err()
    {
        return Err("P2P stop failed native assigned-WCID/reset retirement");
    }
    Ok(())
}
fn mt76_p2p_device_actual_down_wdev_bss_receipts_and_identity_bound_stop() -> TestResult {
    start().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_device_actual_down_wdev_bss_receipts_and_identity_bound_stop
);

fn preflight() -> Result<(), &'static str> {
    // Linux exposes P2P-device independently of the optional CNM/ROC bit.
    // Actual add-dev does not acquire a channel or depend on that ABI.
    let (mut legacy, fixture) = device(false, 10)?;
    let authority = reserved(&fixture)?;
    run(Box::pin(legacy.start_p2p_device(authority.clone())))
        .map_err(|_| "legacy WM P2P-device refused without optional ROC feature")?;
    legacy
        .commit_p2p_device(&authority)
        .map_err(|_| "legacy WM device publication")?;
    run(Box::pin(legacy.stop_p2p_device(&authority)))
        .map_err(|_| "legacy WM P2P-device retirement")?;
    for mode in [2, 3, 8, 9] {
        let (mut session, fixture) = device(true, mode)?;
        let authority = reserved(&fixture)?;
        let before = session.backend.frames.len();
        if run(Box::pin(session.start_p2p_device(authority))) != Err(Error::Authority)
            || session.backend.frames.len() != before
            || session.p2p_owner.is_some()
        {
            return Err("P2P wrong actual role reached native writes");
        }
    }
    let (mut session, fixture) = device(true, 10)?;
    let authority = reserved(&fixture)?;
    fixture.source.0.store(false, Ordering::Release);
    let before = session.backend.frames.len();
    if run(Box::pin(session.start_p2p_device(authority))) != Err(Error::Authority)
        || session.backend.frames.len() != before
    {
        return Err("P2P device ignored exact closed command source");
    }
    Ok(())
}
fn mt76_p2p_device_legacy_firmware_role_and_current_source_precede_native_start() -> TestResult {
    preflight().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_device_legacy_firmware_role_and_current_source_precede_native_start
);

fn pending() -> Result<(), &'static str> {
    for failure in 0..3 {
        let (mut session, fixture) = device(true, 10)?;
        let authority = reserved(&fixture)?;
        let hold = Arc::new(Hold::default());
        session.backend.p2p_hold = Some(hold.clone());
        let mut operation = Box::pin(session.start_p2p_device(authority));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..8192 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("P2P device completed before actual BSS ACK");
            }
            if hold.seen.load(Ordering::Acquire) {
                break;
            }
        }
        if !hold.seen.load(Ordering::Acquire) {
            return Err("P2P native BSS ACK seam not reached");
        }
        if failure == 0 {
            drop(operation);
            if radio(&fixture)
                .and_then(RadioControlAuthority::reserve)
                .err()
                != Some(WirelessError::Busy)
                || session.state != State::Running(Stage::P2pDeviceStart)
                || session
                    .p2p_owner
                    .as_ref()
                    .is_none_or(|owner| owner.activated)
            {
                return Err("cancelled P2P waiter released a published native owner");
            }
            hold.release.store(true, Ordering::Release);
            run(Box::pin(session.shutdown())).map_err(|_| "abandoned P2P shutdown")?;
            if session.p2p_owner.is_some()
                || session.state != State::Stopped
                || radio(&fixture)
                    .and_then(RadioControlAuthority::reserve)
                    .is_err()
            {
                return Err("P2P shutdown failed terminal cleanup/release");
            }
        } else {
            if failure == 1 {
                fixture.source.0.store(false, Ordering::Release);
            } else {
                fixture.daemon.revoke();
            }
            if run(operation) != Err(Error::Authority)
                || session.p2p_owner.is_some()
                || !matches!(session.state, State::RadioReady(_))
                || session.backend.receive_open
            {
                return Err("P2P revoked pending start bypassed verified native cleanup");
            }
        }
    }
    Ok(())
}
fn mt76_p2p_device_cancel_close_and_revoke_retain_native_owner_until_reset() -> TestResult {
    pending().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_device_cancel_close_and_revoke_retain_native_owner_until_reset
);

fn suspend() -> Result<(), &'static str> {
    let (mut session, fixture) = device(true, 10)?;
    let authority = reserved(&fixture)?;
    run(Box::pin(session.start_p2p_device(authority.clone())))
        .map_err(|_| "P2P device start before suspend")?;
    session
        .commit_p2p_device(&authority)
        .map_err(|_| "P2P device publish before suspend")?;
    drop(authority);
    fixture.source.0.store(false, Ordering::Release);
    run(Box::pin(session.suspend())).map_err(|_| "P2P actual device suspend cleanup")?;
    if session.p2p_owner.is_some()
        || !matches!(session.state, State::Suspended(_))
        || session.backend.receive_open
    {
        return Err("P2P autonomous owner survived system PM handoff");
    }
    run(Box::pin(session.resume(fixture.radio.mac()))).map_err(|_| "P2P idle resume")?;
    if session.p2p_owner.is_some() || !matches!(session.state, State::RadioReady(_)) {
        return Err("resume invented a started P2P device without source/start receipt");
    }
    Ok(())
}
fn mt76_p2p_device_system_pm_retires_completed_wdev_without_request_socket() -> TestResult {
    suspend().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_device_system_pm_retires_completed_wdev_without_request_socket
);
