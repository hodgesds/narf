//! Scan while linked through the production station/scan/control owners.
use super::*;
use crate::mt7921::association::Security;
use alloc::boxed::Box;

fn policy() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2472,
                max_bandwidth_mhz: 40,
                max_power_dbm: 17,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5170,
                freq_end_mhz: 5895,
                max_bandwidth_mhz: 40,
                max_power_dbm: 17,
                flags: RegFlags::empty(),
            },
        ],
    }
}
fn joined(secure: bool, wide: bool) -> Result<Session<Model>, &'static str> {
    let (mut session, bss) = super::ht20_tests::prepared(6, secure);
    let permission = if wide {
        super::ht40_tests::permission40(6, 10)
    } else {
        test_permission()
    };
    let mode = if secure {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    };
    run(session.associate_station(&bss, b"narf", mode, permission, &[]))
        .map_err(|_| "associated scan actual MLME/RSNA fixture")?;
    Ok(session)
}
fn downlink(secure: bool, value: u8) -> Vec<u8> {
    let mut packet = super::rx_ba_tests::data_on(6, 0, 1, secure.then_some(7), value);
    let r2 = u32::from_le_bytes(packet[8..12].try_into().unwrap()) | 1 << 30;
    packet[8..12].copy_from_slice(&r2.to_le_bytes());
    packet
}
fn ordinary(value: u8) -> Vec<u8> {
    super::amsdu_rx_tests::ethernet(value, 3)
}
fn request() -> Vec<Vec<u8>> {
    vec![b"other-ap".to_vec()]
}

fn coexist() -> Result<(), &'static str> {
    for secure in [false, true] {
        let mut session = joined(secure, true)?;
        let associated = session.state;
        let epoch = session.receive_epoch;
        let permission = session.station_permission.ok_or("station power grant")?;
        session
            .backend
            .packets
            .push_back(scan_beacon(36, b"other-ap"));
        session.backend.packets.push_back(downlink(secure, 0x51));
        session
            .backend
            .packets
            .push_back(super::rx_ba_tests::request_packet(1, 10, 32, 0, 6));
        let before = session.backend.frames.len();
        let report = run(session.scan_active_with_policy(&[36], &request(), || Ok(policy())))
            .map_err(|_| "associated/off-channel active scan")?;
        if report.bss.len() != 1
            || report.bss[0].channel != 36
            || report.bss[0].ssid != b"other-ap"
            || session.state != associated
            || session.receive_epoch != epoch
            || !session.rx_ba.active(1)
            || session.receive_current(epoch) != Ok(true)
            || session.receive_ethernet() != Ok(Some(ordinary(0x51)))
        {
            return Err("scan lost operating RX/control/association or rebound its epoch");
        }
        let frames = &session.backend.frames[before..];
        let limits = frames
            .iter()
            .filter(|(_, f)| f.len() > 64 && f[36] == 0x5d)
            .next_back()
            .ok_or("restored rate limits")?;
        let State::Associated { info, .. } = associated else {
            return Err("associated fixture state");
        };
        if limits.1.get(64..)
            != permission
                .rate_limits_for_paths(info.capabilities.phy.spatial_streams)
                .as_deref()
        {
            return Err("scan did not replay the exact occupied-channel rate rows");
        }
        let domain = frames
            .iter()
            .filter(|(_, f)| f.len() > 64 && f[36] == 0x0f)
            .next_back()
            .ok_or("restored channel domain")?;
        let body = &domain.1[64..];
        if body[..2] != *b"US" || body[4] != permission.domain_width() {
            return Err("scan restored passive or wrong-width operating domain");
        }
        for entry in body[12..].chunks_exact(8).take(11) {
            let channel = u16::from_le_bytes([entry[0], entry[1]]);
            let flags = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            if flags != if [6, 10].contains(&channel) { 0 } else { 2 } {
                return Err("scan domain failed to preserve only the operating40MHz grant");
            }
        }
    }
    Ok(())
}
fn mt76_associated_offchannel_scan_preserves_data_ba_epoch_and_occupied_power() -> TestResult {
    coexist().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mt76_associated_offchannel_scan_preserves_data_ba_epoch_and_occupied_power
);

fn terminal() -> Result<(), &'static str> {
    let mut session = joined(true, false)?;
    let old = session.receive_epoch;
    session.backend.packets.push_back(downlink(true, 0x52));
    let mut deauth = vec![0; 26];
    deauth[0] = 0xc0;
    deauth[4..10].copy_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    deauth[10..16].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    deauth[16..22].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    deauth[24] = 3;
    session.backend.packets.push_back(descriptor(&deauth));
    let result = run(session.scan_active_with_policy(&[36], &request(), || Ok(policy())));
    if result.is_ok()
        || !matches!(session.state, State::Failed { .. })
        || session.security.is_some()
        || session.station_permission.is_some()
        || session.receive_current(old) != Ok(false)
        || !session.received_msdu.is_empty()
    {
        return Err("peer close during scan published data or restored associated authority");
    }

    let mut session = joined(false, false)?;
    let before = session.backend.frames.len();
    let random = narf_wireless::ScanRandomMac {
        addr: [2, 0, 0, 0, 0, 0],
        mask: [1, 0, 0, 0, 0, 0],
    };
    if !matches!(
        run(session.scan_with_options_and_policy(
            &[36],
            &request(),
            ScanOptions {
                extra_ies: &[],
                random_mac: Some(random),
            },
            || Ok(policy()),
        )),
        Err(Error::Busy)
    ) || session.backend.frames.len() != before
        || !matches!(session.state, State::Associated { .. })
    {
        return Err("associated random scan was not refused before hardware mutation");
    }
    session.backend.scan_stall = true;
    let epoch = session.receive_epoch;
    let ssids = request();
    let mut future = Box::pin(session.scan_active_with_policy(&[36], &ssids, || Ok(policy())));
    let mut cx = Context::from_waker(Waker::noop());
    if future.as_mut().poll(&mut cx).is_ready() {
        return Err("cancelled scan fixture unexpectedly completed");
    }
    drop(future);
    if !matches!(session.state, State::Running(_))
        || session.receive_current(epoch) != Ok(false)
        || !session.backend.owner.published
    {
        return Err("cancelled associated scan reopened the station or released uncertain DMA");
    }
    Ok(())
}
fn mt76_associated_scan_peer_close_and_random_scan_cannot_restore_authority() -> TestResult {
    terminal().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mt76_associated_scan_peer_close_and_random_scan_cannot_restore_authority
);

fn rekey_and_pending_tx() -> Result<(), &'static str> {
    let mut session = joined(true, false)?;
    let old_epoch = session.receive_epoch;
    let mut uplink = vec![0; 60];
    let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ap = [2, 1, 2, 3, 4, 5];
    uplink[..6].copy_from_slice(&ap);
    uplink[6..12].copy_from_slice(&own);
    uplink[12..14].copy_from_slice(&[8, 0]);
    session
        .start_ethernet(&uplink)
        .map_err(|_| "pre-scan native TX")?;
    session.backend.packets.push_back(downlink(true, 0x53));
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    session
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(own, ap, &m1.into_eapol())));
    // The existing native key fixture authenticates the new exchange; the
    // first joined AP fixture has completed its one initial handshake.
    session.backend.access_point = None;
    session.backend.psk = [0x55; 32];
    session.backend.own_mac = own;
    session.backend.ap_mac = ap;
    session.backend.anonce = [0x55; 32];
    run(session.scan_active_with_policy(&[36], &request(), || Ok(policy())))
        .map_err(|_| "scan did not service old TX plus real rekey exchange")?;
    if !session.data_pending.is_empty()
        || session.receive_epoch == old_epoch
        || session.receive_current(session.receive_epoch) != Ok(true)
        || session.receive_current(old_epoch) != Ok(false)
        || session.receive_ethernet() != Ok(None)
    {
        return Err("scan starved native TX/EAPOL or delivered data from the previous key epoch");
    }
    Ok(())
}
fn mt76_associated_scan_drains_pending_tx_and_services_rekey_before_publication() -> TestResult {
    rekey_and_pending_tx().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mt76_associated_scan_drains_pending_tx_and_services_rekey_before_publication
);

fn nested_cancel() -> Result<(), &'static str> {
    for key_wait in [false, true] {
        let mut session = joined(key_wait, false)?;
        let epoch = session.receive_epoch;
        let before = session.backend.frames.len();
        let stage = if key_wait {
            let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
            let ap = [2, 1, 2, 3, 4, 5];
            let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
            m1.key_information = 2 | (1 << 3) | (1 << 7);
            m1.key_length = 16;
            m1.replay_counter = 7;
            m1.key_nonce = [0x55; 32];
            session
                .backend
                .packets
                .push_back(descriptor(&ap_eapol_frame(own, ap, &m1.into_eapol())));
            session.backend.access_point = None;
            session.backend.management_stall_after = Some(before + 7);
            Stage::EapolHandshake
        } else {
            session
                .backend
                .packets
                .push_back(super::rx_ba_tests::request_packet(1, 10, 32, 0, 6));
            // Six scan preflight/START commands, then the nested WTBL BA.
            session.backend.tx_stall_after = Some(before + 7);
            Stage::StaRecord
        };
        let ssids = request();
        let mut scan = Box::pin(session.scan_active_with_policy(&[36], &ssids, || Ok(policy())));
        for _ in 0..20 {
            if scan
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return Err("nested cancellation native wait was not held");
            }
        }
        drop(scan);
        if session.state != State::Running(stage)
            || session.receive_current(epoch) != Ok(false)
            || session.receive_ethernet() != Err(Error::Busy)
            || !session.backend.owner.published
        {
            return Err("cancelled nested scan/key/BA wait exposed associated state or DMA");
        }
    }
    Ok(())
}
fn mt76_associated_scan_cancellation_inside_key_and_ba_waits_keeps_running_owner() -> TestResult {
    nested_cancel().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mt76_associated_scan_cancellation_inside_key_and_ba_waits_keeps_running_owner
);
