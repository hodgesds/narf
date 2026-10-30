//! Real START metadata, current peer software CCMP and native TXS control ACK.
use super::*;
use narf_wireless::{ApStartSettings, ControlPort, ControlPortTxRequest};
fn settings() -> ApStartSettings {
    ApStartSettings {
        auth_type: Some(0),
        wpa_versions: Some(2),
        pairwise_ciphers: Some(vec![0x000fac04]),
        group_cipher: Some(0x000fac04),
        akms: Some(vec![0x000fac02]),
        control_port: ControlPort {
            enabled: true,
            over_nl80211: true,
            ..ControlPort::default()
        },
    }
}
fn report(pid: u8, ack: bool) -> Vec<u8> {
    [
        1u32 << 27 | 40,
        0,
        if ack { 0 } else { 1 << 16 },
        0,
        1 << 16,
        u32::from(pid) << 24,
        0,
        0,
        0,
        0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect()
}
fn control() -> Result<(), &'static str> {
    let (mut session, fixture, authority) = idle()?;
    let own = fixture.radio.mac();
    let before = session.backend.frames.len();
    let mut invalid = settings();
    invalid.wpa_versions = Some(1);
    if run(Box::pin(session.start_ap_with_settings(
        authority.clone(),
        secure_config(own),
        invalid,
    ))) != Err(Error::UnsupportedFirmware)
        || session.backend.frames.len() != before
        || session.ap_owner.is_some()
    {
        return Err("native AP ignored requested crypto metadata before RF publication");
    }
    run(Box::pin(session.start_ap_with_settings(
        authority.clone(),
        secure_config(own),
        settings(),
    )))
    .map_err(|_| "native START_AP explicit WPA2/control-port settings")?;
    if session.ap_owner.as_ref().unwrap().start_settings != Some(settings())
        || session.ap_keys.has_group(1)
    {
        return Err("START_AP settings fabricated a GTK/native key receipt");
    }
    session
        .commit_ap_start(&authority)
        .map_err(|_| "native explicit AP capture commit")?;
    drop(authority);
    let authority = bound(&fixture)?;
    let cfg = peer_config(1);
    let peer = cfg.mac;
    run(Box::pin(session.ap_add_station(authority.clone(), cfg)))
        .map_err(|_| "native control peer")?;
    let pdu = vec![2, 3, 0, 4, 1, 2, 3, 4];
    session.backend.tx_status.push_back(report(3, true));
    if run(Box::pin(session.ap_send_control(
        authority.clone(),
        ControlPortTxRequest::new(peer, 0x888e, pdu.clone(), false, true),
    ))) != Ok(true)
    {
        return Err("initial keyless EAPOL lost native ACK receipt");
    }
    let frame = &session.backend.frames.last().unwrap().1;
    if frame[1] != 2
        || frame[24..32] != [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]
        || frame[32..] != pdu
        || session
            .ap_owner
            .as_ref()
            .unwrap()
            .peers
            .get(peer)
            .unwrap()
            .authorized
    {
        return Err("EAPOL fabricated protection or an ordinary peer data port");
    }
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(peer), 0, 43),
    )))
    .map_err(|_| "native protected-control current PTK")?;
    session.backend.tx_status.push_back(report(4, false));
    if run(Box::pin(session.ap_send_control(
        authority.clone(),
        ControlPortTxRequest::new(peer, 0x888e, pdu.clone(), false, true),
    ))) != Ok(false)
    {
        return Err("native control failure became positive ACK or lost terminal receipt");
    }
    let frame = &session.backend.frames.last().unwrap().1;
    let mut wire = frame[24..].to_vec();
    let mut replay = narf_wireless::ccmp::ReplayWindow::default();
    let clear = narf_wireless::ccmp::unprotect(
        &super::super::ap_crypto::Ccm,
        &frame[..24],
        &[43; 16],
        0,
        false,
        &mut replay,
        &mut wire,
    )
    .map_err(|_| "native AP control real AES-CCM")?;
    if frame[1] != 0x42
        || frame[24] != 1
        || clear[8..] != pdu
        || session.backend.data_headers.last().unwrap()[13] & 2 != 0
    {
        return Err("protected control used hardware key/old nonce or wrong PDU");
    }
    if run(Box::pin(session.ap_send_control(
        authority.clone(),
        ControlPortTxRequest::new(peer, 0x888e, pdu.clone(), true, false),
    ))) != Ok(false)
    {
        return Err("DONT_WAIT control required an unrequested TXS");
    }
    let frame = &session.backend.frames.last().unwrap().1;
    if frame[1] != 2 || session.backend.data_headers.last().unwrap()[20..24] != [0; 4] {
        return Err("explicit unencrypted/no-status control selected a key or HOST PID");
    }
    let before = session.backend.frames.len();
    if run(Box::pin(session.ap_send_control(
        authority.clone(),
        ControlPortTxRequest::new(peer, 0x0800, pdu.clone(), true, false),
    ))) != Err(Error::Bounds)
        || session.backend.frames.len() != before
    {
        return Err("ordinary IPv4 entered explicit AP control injection");
    }
    let mut operation = Box::pin(session.ap_send_control(
        authority,
        ControlPortTxRequest::new(peer, 0x888e, pdu, false, true),
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if operation.as_mut().poll(&mut cx).is_ready() {
        return Err("protected control ACK guessed from packet release without TXS");
    }
    drop(operation);
    if session.state != State::Running(Stage::ApPeer)
        || !session.ap_keys.has_pair(peer)
        || bound(&fixture).is_ok()
    {
        return Err("dropped control ACK wait released active key/request ownership");
    }
    run(Box::pin(session.shutdown())).map_err(|_| "abandoned native control reset")?;
    if session.ap_keys.has_pair(peer)
        || session.ap_keys.check_install(
            super::super::ap_crypto::Target::Pairwise(peer),
            &[43; 16],
            0,
        ) != Err(super::super::ap_crypto::Error::Key)
    {
        return Err("reset reused abandoned control key material with a fresh nonce");
    }
    Ok(())
}
fn mt76_ap_explicit_crypto_control_settings_real_ccmp_and_native_ack_ownership() -> TestResult {
    control().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_explicit_crypto_control_settings_real_ccmp_and_native_ack_ownership
);

fn no_preauth() -> Result<(), &'static str> {
    let (mut session, fixture, authority) = idle()?;
    let own = fixture.radio.mac();
    let mut config = settings();
    config.control_port.no_preauth = true;
    run(Box::pin(session.start_ap_with_settings(
        authority.clone(),
        secure_config(own),
        config,
    )))
    .map_err(|_| "native explicit no-preauth START")?;
    session
        .commit_ap_start(&authority)
        .map_err(|_| "native no-preauth capture")?;
    drop(authority);
    let authority = bound(&fixture)?;
    let cfg = peer_config(1);
    let peer = cfg.mac;
    run(Box::pin(session.ap_add_station(authority.clone(), cfg)))
        .map_err(|_| "native no-preauth peer")?;
    let pdu = [2, 3, 0, 4, 1, 2, 3, 4];
    let mut ether = peer.to_vec();
    ether.extend_from_slice(&own);
    ether.extend_from_slice(&[0x88, 0xc7]);
    ether.extend_from_slice(&pdu);
    if session
        .step_ap_network(Some(&ether))
        .map_err(|_| "closed preauth data path")?
        .transmitted
    {
        return Err("no-preauth bypassed a closed peer data port");
    }
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(peer), 0, 47),
    )))
    .map_err(|_| "native no-preauth current PTK")?;
    session
        .ap_authorize_station(&authority, peer, true)
        .map_err(|_| "native no-preauth authorized port")?;
    if !session
        .step_ap_network(Some(&ether))
        .map_err(|_| "native no-preauth netdev TX")?
        .transmitted
    {
        return Err("explicit no-preauth did not preserve actual netdev TX");
    }
    let mut header = vec![0; 24];
    header[0] = 8;
    header[1] = 0x41;
    header[4..10].copy_from_slice(&own);
    header[10..16].copy_from_slice(&peer);
    header[16..22].copy_from_slice(&own);
    for (pn, proto) in [(1u64, 0x88c7u16), (2, 0x888e)] {
        let mut clear = vec![0xaa, 0xaa, 3, 0, 0, 0];
        clear.extend_from_slice(&proto.to_be_bytes());
        clear.extend_from_slice(&pdu);
        let cipher = narf_wireless::ccmp::protect(
            &super::super::ap_crypto::Ccm,
            &header,
            &[47; 16],
            pn,
            0,
            0,
            false,
            &mut clear,
        )
        .map_err(|_| "native no-preauth actual peer CCMP")?;
        let mut packet = vec![0; 24];
        packet[..4]
            .copy_from_slice(&((2u32 << 27) | (24 + 24 + cipher.len()) as u32).to_le_bytes());
        packet[4..8].copy_from_slice(&1u32.to_le_bytes());
        packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&cipher);
        session.backend.packets.push_back(packet);
        let step = session
            .step_ap_network(None)
            .map_err(|_| "native no-preauth current RX")?;
        if proto == 0x88c7 {
            let mut expected = own.to_vec();
            expected.extend_from_slice(&peer);
            expected.extend_from_slice(&proto.to_be_bytes());
            expected.extend_from_slice(&pdu);
            if step.received != vec![expected]
                || session
                    .pop_ap_event()
                    .map_err(|_| "native preauth event exclusion")?
                    .is_some()
            {
                return Err("no-preauth redirected a configured netdev PDU into nl80211");
            }
        } else if !step.received.is_empty()
            || !matches!(
                session
                    .pop_ap_event()
                    .map_err(|_| "native EAPOL route")?
                    .map(|e| e.event),
                Some(super::super::ApEvent::Control {
                    ethertype: 0x888e,
                    unencrypted: false,
                    ..
                })
            )
        {
            return Err("no-preauth accidentally redirected EAPOL into ordinary data");
        }
    }
    Ok(())
}
fn mt76_ap_no_preauth_preserves_controlled_netdev_path_and_separates_eapol() -> TestResult {
    no_preauth().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_no_preauth_preserves_controlled_netdev_path_and_separates_eapol
);
