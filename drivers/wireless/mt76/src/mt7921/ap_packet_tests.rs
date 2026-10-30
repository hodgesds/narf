//! Native Session data ownership with actual AES-CCM, not a cipher model.
use super::*;
use narf_wireless::ccmp::{self, ReplayWindow};

fn authorized() -> Result<(NativeSession, Fixture, [u8; 6]), &'static str> {
    let (mut session, fixture, mac) = secure_peer()?;
    let authority = bound(&fixture)?;
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(mac), 0, 17),
    )))
    .map_err(|_| "AP data current PTK")?;
    session
        .ap_authorize_station(&authority, mac, true)
        .map_err(|_| "AP data current peer port")?;
    Ok((session, fixture, mac))
}
fn ethernet(own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
    let mut frame = peer.to_vec();
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&[8, 0, 0x45, 0, 0, 20]);
    frame
}
fn receive_packet(own: [u8; 6], peer: [u8; 6], key: u8, pn: u64, wcid: u16) -> Vec<u8> {
    let mut header = vec![0; 24];
    header[0] = 8;
    header[1] = 0x41;
    header[4..10].copy_from_slice(&own);
    header[10..16].copy_from_slice(&peer);
    header[16..22].copy_from_slice(&own);
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 0x45, 0, 0, 20];
    let cipher = ccmp::protect(
        &super::super::ap_crypto::Ccm,
        &header,
        &[key; 16],
        pn,
        0,
        0,
        false,
        &mut body,
    )
    .unwrap();
    header.extend_from_slice(&cipher);
    let mut packet = vec![0; 24];
    packet[..4].copy_from_slice(&((2u32 << 27) | (24 + header.len()) as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&u32::from(wcid).to_le_bytes());
    packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    packet.extend_from_slice(&header);
    packet
}
fn packets() -> Result<(), &'static str> {
    let (mut session, fixture, mac) = authorized()?;
    let own = fixture.radio.mac();
    let ethernet = ethernet(own, mac);
    let step = session
        .step_ap_network(Some(&ethernet))
        .map_err(|_| "native AP encrypted packet publication")?;
    if !step.transmitted || session.data_pending.len() != 1 {
        return Err("AP did not retain its actual native packet owner");
    }
    let header = session.backend.data_headers.last().ok_or("AP native TXD")?;
    let wire = &session.backend.frames.last().unwrap().1;
    if header[4..8] != 0x80026001u32.to_le_bytes()
        || header[13] & 2 != 0
        || header[15] & 0x80 != 0
        || wire[1] != 0x42
        || wire[4..10] != mac
        || wire[10..16] != own
    {
        return Err("software AP packet used wrong WCID/direction or hardware crypto/manual SN");
    }
    let mut replay = ReplayWindow::default();
    let mut cipher = wire[24..].to_vec();
    let clear = ccmp::unprotect(
        &super::super::ap_crypto::Ccm,
        &wire[..24],
        &[17; 16],
        0,
        false,
        &mut replay,
        &mut cipher,
    )
    .map_err(|_| "native AP TX real CCMP proof")?;
    if clear[..8] != [0xaa, 0xaa, 3, 0, 0, 0, 8, 0] || clear[8..] != ethernet[14..] {
        return Err("AP native software ciphertext did not carry the real Ethernet MSDU");
    }
    let valid = receive_packet(own, mac, 17, 1, 1);
    let mut forged = valid.clone();
    *forged.last_mut().unwrap() ^= 1;
    let mut old_plaintext = valid.clone();
    old_plaintext[4..8].copy_from_slice(&(1u32 | (4 << 16)).to_le_bytes());
    let wrong_peer = receive_packet(own, mac, 17, 1, 2);
    session
        .backend
        .packets
        .extend([forged, old_plaintext, wrong_peer, valid.clone()]);
    let step = session
        .step_ap_network(None)
        .map_err(|_| "native AP RX real ciphertext")?;
    let mut expected = own.to_vec();
    expected.extend_from_slice(&mac);
    expected.extend_from_slice(&ethernet[12..]);
    if step.received != vec![expected] || !session.data_pending.is_empty() {
        return Err("AP forged/old hardware plaintext/foreign WCID reached its data port");
    }
    session.backend.packets.push_back(valid);
    if !session
        .step_ap_network(None)
        .map_err(|_| "native AP replay progress")?
        .received
        .is_empty()
    {
        return Err("AP accepted a replayed CCMP packet");
    }
    // Copy under the old capture epoch, then install the exact new key that
    // could authenticate these bytes. Copy-time authority must still deny it.
    session
        .backend
        .packets
        .push_back(receive_packet(own, mac, 18, 2, 1));
    let old = session
        .backend
        .receive_data_captured()
        .map_err(|_| "native old-epoch copy")?
        .ok_or("old capture")?;
    let authority = bound(&fixture)?;
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(mac), 0, 18),
    )))
    .map_err(|_| "AP current key transition")?;
    session.backend.captured_packets.push_back(old);
    if !session
        .step_ap_network(None)
        .map_err(|_| "native stale AP copy")?
        .received
        .is_empty()
    {
        return Err("earlier AP capture acquired later key authority");
    }
    session
        .backend
        .packets
        .push_back(receive_packet(own, mac, 18, 2, 1));
    if session
        .step_ap_network(None)
        .map_err(|_| "fresh AP current-key copy")?
        .received
        .len()
        != 1
    {
        return Err("old capture consumed current-key replay state");
    }
    session
        .ap_authorize_station(&authority, mac, false)
        .map_err(|_| "AP port close")?;
    session
        .backend
        .packets
        .push_back(receive_packet(own, mac, 18, 3, 1));
    if !session
        .step_ap_network(None)
        .map_err(|_| "closed AP peer RX")?
        .received
        .is_empty()
        || session
            .step_ap_network(Some(&ethernet))
            .map_err(|_| "closed AP peer TX")?
            .transmitted
    {
        return Err("closed AP peer retained ordinary data admission");
    }
    fixture.source.0.store(false, Ordering::Release);
    if session.ap_receive_current(session.receive_epoch) != Ok(true) {
        return Err("completed AP BSS incorrectly depended on an old request socket");
    }
    fixture.daemon.revoke(); // The completed identity carries no admin grant.
    if session.ap_receive_current(session.receive_epoch) != Ok(true) {
        return Err("data port invented a per-packet administrative capability");
    }
    Ok(())
}
fn mt76_ap_native_data_real_ccmp_peer_port_and_capture_ownership() -> TestResult {
    packets().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_native_data_real_ccmp_peer_port_and_capture_ownership
);

fn pending_key() -> Result<(), &'static str> {
    for revoke in [false, true] {
        let (mut session, fixture, mac) = authorized()?;
        let ethernet = ethernet(fixture.radio.mac(), mac);
        if !session
            .step_ap_network(Some(&ethernet))
            .map_err(|_| "key-wait real packet publication")?
            .transmitted
        {
            return Err("key wait lacked a real native packet owner");
        }
        session.backend.completion_budget = Some(0);
        let authority = bound(&fixture)?;
        let mut operation =
            Box::pin(session.ap_install_key(authority, temporal_key(Some(mac), 0, 29)));
        let mut cx = Context::from_waker(Waker::noop());
        if operation.as_mut().poll(&mut cx).is_ready() {
            return Err("AP key changed before native packet dual retirement");
        }
        if revoke {
            fixture.daemon.revoke();
            if run(operation) != Err(Error::Authority)
                || session.ap_owner.is_some()
                || session.ap_keys.has_pair(mac)
            {
                return Err("revoked AP key waiter bypassed current admin or verified cleanup");
            }
        } else {
            drop(operation);
            if session.state != State::Running(Stage::ApPeer)
                || session.backend.receive_open
                || session.data_pending.len() != 1
                || !session.ap_keys.has_pair(mac)
                || bound(&fixture).is_ok()
            {
                return Err("dropped AP key waiter released old packet/key/control ownership");
            }
            session.backend.completion_budget = None;
            run(Box::pin(session.shutdown())).map_err(|_| "abandoned AP key native reset")?;
            if session.ap_owner.is_some()
                || session.ap_keys.has_pair(mac)
                || bound(&fixture).is_err()
            {
                return Err("verified AP key cleanup retained abandoned owners");
            }
        }
    }
    Ok(())
}
fn mt76_ap_key_change_waits_for_real_packet_retirement_and_retains_cancelled_owner() -> TestResult {
    pending_key().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_key_change_waits_for_real_packet_retirement_and_retains_cancelled_owner
);
