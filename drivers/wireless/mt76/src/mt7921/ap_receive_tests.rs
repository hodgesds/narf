//! Native raw management/EAPOL copies composed with actual source authority.
use super::*;
pub(super) fn packet(frame: &[u8], wcid: u16, signal: bool) -> Vec<u8> {
    let offset = if signal { 32 } else { 24 };
    let mut p = vec![0; offset];
    p[..4].copy_from_slice(&((2u32 << 27) | (offset + frame.len()) as u32).to_le_bytes());
    p[4..8].copy_from_slice(&(u32::from(wcid) | if signal { 1 << 13 } else { 0 }).to_le_bytes());
    p[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    if signal {
        p[28..32].copy_from_slice(&120u32.to_le_bytes());
    }
    p.extend_from_slice(frame);
    p
}
fn received() -> Result<(), &'static str> {
    let (mut session, fixture, peer) = secure_peer()?;
    let own = fixture.radio.mac();
    let unknown = [2, 0, 0, 0, 0x55, 1];
    let registration = bound(&fixture)?;
    let events = registration
        .event_authority()
        .map_err(|_| "native actual registration RX grant")?;
    drop(registration);
    let mut auth = vec![0; 30];
    auth[0] = 0xb0;
    auth[4..10].copy_from_slice(&own);
    auth[10..16].copy_from_slice(&unknown);
    auth[16..22].copy_from_slice(&own);
    auth[26] = 1;
    let mut eapol = vec![0; 24];
    eapol[0] = 8;
    eapol[1] = 1;
    eapol[4..10].copy_from_slice(&own);
    eapol[10..16].copy_from_slice(&peer);
    eapol[16..22].copy_from_slice(&own);
    eapol.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 2, 3, 0, 4, 1, 2, 3, 4]);
    session
        .backend
        .packets
        .extend([packet(&auth, 1023, true), packet(&eapol, 1, false)]);
    let step = session
        .step_ap_network(None)
        .map_err(|_| "native AP closed-port RX")?;
    if !step.received.is_empty() {
        return Err("AP management/EAPOL bypassed ordinary controlled port");
    }
    let event = session
        .pop_ap_event()
        .map_err(|_| "native AP management copy")?
        .ok_or("native management notification missing")?;
    if !session
        .ap_receive_current(event.epoch)
        .map_err(|_| "management current native capture")?
    {
        return Err("native management event lost its current copy owner");
    }
    match event.event {
        super::super::ApEvent::Management {
            frequency_mhz,
            signal_dbm,
            frame,
        } if frequency_mhz == 2437 && signal_dbm == Some(-50) && frame == auth => {
            // This fixture's explicit registration filter selects Open Auth.
            // No management packet itself grants association or a data port.
            if frame[0] != 0xb0 || frame[24..26] != [0, 0] {
                return Err("native registration filter");
            }
            events
                .management_received(frequency_mhz, signal_dbm, &frame)
                .map_err(|_| "native management exact-source delivery")?;
        }
        _ => return Err("native management invented RSSI/frequency or peer admission"),
    }
    let event = session
        .pop_ap_event()
        .map_err(|_| "native AP control copy")?
        .ok_or("native control notification missing")?;
    if !session
        .ap_receive_current(event.epoch)
        .map_err(|_| "EAPOL current native capture")?
    {
        return Err("native EAPOL event lost its copy owner");
    }
    match event.event {
        super::super::ApEvent::Control {
            peer: mac,
            ethertype,
            pdu,
            unencrypted,
        } if mac == peer
            && ethertype == 0x888e
            && pdu == [2, 3, 0, 4, 1, 2, 3, 4]
            && unencrypted =>
        {
            events
                .control_received(mac, ethertype, &pdu, unencrypted)
                .map_err(|_| "native EAPOL exact-source delivery")?
        }
        _ => return Err("native control-port RX invented authentication/port proof"),
    }
    if fixture.source.1.lock().len() != 2
        || session
            .ap_owner
            .as_ref()
            .unwrap()
            .peers
            .get(peer)
            .unwrap()
            .authorized
        || session.ap_keys.has_pair(peer)
    {
        return Err("native RX delivery fabricated PTK or peer authorization");
    }
    let mut malformed = packet(&auth, 1023, false);
    malformed[5] |= 0x80; // GROUP5 without GROUP3.
    let mut other_band = packet(&auth, 1023, false);
    other_band[12..16].copy_from_slice(&(181u32 << 8).to_le_bytes());
    let mut translated = packet(&eapol, 1, false);
    translated[10] |= 0x80;
    let foreign = packet(&eapol, 2, false);
    session
        .backend
        .packets
        .extend([malformed, other_band, translated, foreign]);
    if !session
        .step_ap_network(None)
        .map_err(|_| "native malformed RX progress")?
        .received
        .is_empty()
        || session
            .pop_ap_event()
            .map_err(|_| "native malformed event check")?
            .is_some()
    {
        return Err("malformed metadata/foreign WCID acquired native event authority");
    }
    session
        .backend
        .packets
        .push_back(packet(&auth, 1023, false));
    session
        .step_ap_network(None)
        .map_err(|_| "old native management event")?;
    let authority = bound(&fixture)?;
    run(Box::pin(
        session.ap_install_key(authority, temporal_key(Some(peer), 0, 41)),
    ))
    .map_err(|_| "new native key/capture owner")?;
    if session
        .pop_ap_event()
        .map_err(|_| "retired native management copy")?
        .is_some()
    {
        return Err("queued old event inherited later capture/key ownership");
    }
    fixture.source.0.store(false, Ordering::Release);
    if events.management_received(2437, None, &auth) != Err(WirelessError::Denied)
        || fixture.source.1.lock().len() != 2
    {
        return Err("native AP RX retargeted a closed original socket");
    }
    Ok(())
}
fn mt76_ap_native_management_and_closed_port_eapol_keep_actual_copy_and_source_owners() -> TestResult
{
    received().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_native_management_and_closed_port_eapol_keep_actual_copy_and_source_owners
);
