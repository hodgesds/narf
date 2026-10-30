//! Typed RX authority retains its actual source/grant, not a control lease.
use super::*;
fn event_authority() -> Result<(), &'static str> {
    for boundary in 0..4 {
        let fixture = fixture()?;
        let authority = ApControlAuthority::bind(
            fixture.admin.clone(),
            &fixture.iface,
            0,
            fixture.ifindex,
            fixture.source.clone(),
        )
        .and_then(ApControlAuthority::reserve)
        .map_err(|_| "actual AP registration request")?;
        let event = authority
            .event_authority()
            .map_err(|_| "actual AP typed receive grant")?;
        drop(authority);
        let next = ApControlAuthority::bind(
            fixture.admin.clone(),
            &fixture.iface,
            0,
            fixture.ifindex,
            fixture.source.clone(),
        )
        .and_then(ApControlAuthority::reserve)
        .map_err(|_| "completed RX registration retained native control serialization")?;
        drop(next);
        let own = fixture.radio.mac();
        let peer = [2, 0, 0, 0, 0x77, 1];
        let mut frame = alloc::vec![0;30];
        frame[0] = 0xb0;
        frame[4..10].copy_from_slice(&own);
        frame[10..16].copy_from_slice(&peer);
        frame[16..22].copy_from_slice(&own);
        event
            .management_received(2412, None, &frame)
            .map_err(|_| "current native management delivery")?;
        event
            .control_received(peer, 0x888e, &[2, 0, 0, 0], true)
            .map_err(|_| "current native control-port delivery")?;
        let messages = fixture.source.1.lock();
        if messages.len() != 2
            || messages[0][16] != 59
            || messages[1][16] != 129
            || messages.iter().any(|m| m[8..16] != [0; 8])
        {
            return Err("typed receive source lost command or notification framing");
        }
        drop(messages);
        match boundary {
            0 => fixture.daemon.revoke(),
            1 => fixture.source.0.store(false, Ordering::Release),
            2 => {
                fixture.radio.mode.store(2, Ordering::Release);
                fixture.radio.generation.store(2, Ordering::Release);
                fixture.radio.mode.store(3, Ordering::Release);
                fixture.radio.generation.store(3, Ordering::Release);
            }
            _ => {
                narf_net::iface::set_link_state(fixture.radio.name(), false);
                narf_net::iface::set_link_state(fixture.radio.name(), true);
            }
        }
        let replacement = Source::new();
        if event.current() != Err(WirelessError::Denied)
            || event.management_received(2412, Some(-42), &frame) != Err(WirelessError::Denied)
            || event.control_received(peer, 0x888e, &[2, 0, 0, 0], true)
                != Err(WirelessError::Denied)
            || fixture.source.1.lock().len() != 2
            || !replacement.1.lock().is_empty()
        {
            return Err("typed AP RX survived revoked source/capability/mode/UP ownership");
        }
    }
    let fixture = fixture()?;
    narf_net::iface::set_link_state(fixture.radio.name(), false);
    let request = ApControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        fixture.source.clone(),
    )
    .and_then(ApControlAuthority::reserve)
    .map_err(|_| "actual pre-UP registration request")?;
    let event = request
        .event_authority()
        .map_err(|_| "REGISTER_FRAME incorrectly required administrative UP")?;
    if event.current() != Err(WirelessError::Denied) {
        return Err("pre-UP registration opened typed receive authority");
    }
    narf_net::iface::set_link_state(fixture.radio.name(), true);
    if event.current() != Ok(()) {
        return Err("same registered UP generation did not enable actual receive checks");
    }
    Ok(())
}
fn native_ap_typed_receive_authority_rechecks_actual_grant_socket_and_mode_without_holding_control(
) -> TestResult {
    event_authority().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    native_ap_typed_receive_authority_rechecks_actual_grant_socket_and_mode_without_holding_control
);
