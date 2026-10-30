//! Native partial beacon receipt and host-only port update ownership.
use super::*;
fn beacon() -> Result<(), &'static str> {
    let (mut session, fixture, mac) = secure_peer()?;
    let mut tail = session
        .ap_owner
        .as_ref()
        .unwrap()
        .plan
        .config
        .beacon_tail
        .clone();
    tail.extend_from_slice(&[221, 4, 0, 0x11, 0x22, 0x33]);
    let authority = bound(&fixture)?;
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(mac), 0, 31),
    )))
    .map_err(|_| "beacon update current PTK")?;
    run(Box::pin(session.ap_update_beacon(
        authority.clone(),
        None,
        Some(tail.clone()),
        None,
    )))
    .map_err(|_| "actual partial beacon update ACK")?;
    let owner = session.ap_owner.as_ref().unwrap();
    let body = session
        .backend
        .frames
        .iter()
        .rev()
        .find_map(|(_, frame)| uni(frame, 2))
        .ok_or("actual beacon update UNI")?;
    if owner.plan.config.beacon_tail != tail
        || owner.pending_plan.is_some()
        || body.len() != 530
        || body[50..50 + owner.plan.beacon.len()] != owner.plan.beacon
        || !session.ap_keys.has_pair(mac)
    {
        return Err("beacon replacement lost native receipt/template/current peer key");
    }
    let mut invalid_head = owner.plan.config.beacon_head.clone();
    invalid_head[35] ^= 4;
    let before = session.backend.frames.len();
    if run(Box::pin(session.ap_update_beacon(
        authority.clone(),
        Some(invalid_head),
        None,
        None,
    ))) != Err(Error::Bounds)
        || session.backend.frames.len() != before
        || !matches!(session.state, State::AccessPoint { .. })
    {
        return Err("beacon replacement changed MAC timing without a native timing receipt");
    }
    let hold = Arc::new(Hold::default());
    session.backend.ap_hold = Some(hold.clone());
    let old = session.ap_owner.as_ref().unwrap().plan.beacon.clone();
    tail.extend_from_slice(&[221, 1, 0x77]);
    let mut update = Box::pin(session.ap_update_beacon(authority, None, Some(tail.clone()), None));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..8192 {
        if update.as_mut().poll(&mut cx).is_ready() {
            return Err("beacon replacement completed before actual native ACK");
        }
        if hold.seen.load(Ordering::Acquire) {
            break;
        }
    }
    if !hold.seen.load(Ordering::Acquire) {
        return Err("beacon replacement did not reach its native ACK");
    }
    drop(update);
    let owner = session.ap_owner.as_ref().unwrap();
    if session.state != State::Running(Stage::ApPeer)
        || session.backend.receive_open
        || owner.plan.beacon != old
        || owner
            .pending_plan
            .as_ref()
            .is_none_or(|p| p.config.beacon_tail != tail)
        || bound(&fixture).is_ok()
    {
        return Err("cancelled beacon replacement discarded uncertain template/control ownership");
    }
    hold.release.store(true, Ordering::Release);
    run(Box::pin(session.shutdown())).map_err(|_| "uncertain beacon native reset")?;
    if session.ap_owner.is_some() || session.ap_keys.has_pair(mac) || bound(&fixture).is_err() {
        return Err("beacon cleanup failed to retire old/new BSS ownership");
    }
    Ok(())
}
fn mt76_ap_partial_beacon_update_keeps_uncertain_template_until_real_receipt() -> TestResult {
    beacon().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_partial_beacon_update_keeps_uncertain_template_until_real_receipt
);

fn port_update() -> Result<(), &'static str> {
    let (mut session, fixture, mac) = secure_peer()?;
    let authority = bound(&fixture)?;
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(mac), 0, 37),
    )))
    .map_err(|_| "port transition current PTK")?;
    session
        .ap_authorize_station(&authority, mac, true)
        .map_err(|_| "port transition original authorization")?;
    let own = fixture.radio.mac();
    let mut ether = mac.to_vec();
    ether.extend_from_slice(&own);
    ether.extend_from_slice(&[8, 0, 0x45, 0]);
    if !session
        .step_ap_network(Some(&ether))
        .map_err(|_| "port transition actual packet")?
        .transmitted
    {
        return Err("port transition lacked real native packet ownership");
    }
    if session.ap_authorize_station(&authority, mac, false) != Err(Error::Busy) {
        return Err("synchronous port transition ignored old native packet ownership");
    }
    let mut config = peer_config(1);
    config.aid = 0;
    config.listen_interval = 0;
    config.supported_rates.clear();
    config.capability = None;
    config.authorized = Some(false);
    session.backend.completion_budget = Some(0);
    let mut operation = Box::pin(session.ap_update_station(authority, config));
    let mut cx = Context::from_waker(Waker::noop());
    if operation.as_mut().poll(&mut cx).is_ready() {
        return Err("SET_STATION completed without old packet terminal receipt");
    }
    drop(operation);
    if session.state != State::Running(Stage::ApPeer)
        || session.backend.receive_open
        || session.data_pending.len() != 1
        || !session
            .ap_owner
            .as_ref()
            .unwrap()
            .peers
            .get(mac)
            .unwrap()
            .authorized
        || bound(&fixture).is_ok()
    {
        return Err("dropped SET_STATION released an unretired old data/port/control owner");
    }
    session.backend.completion_budget = None;
    run(Box::pin(session.shutdown())).map_err(|_| "retained port transition verified cleanup")?;
    Ok(())
}
fn mt76_ap_set_station_port_change_waits_for_native_packet_retirement() -> TestResult {
    port_update().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_set_station_port_change_waits_for_native_packet_retirement
);
