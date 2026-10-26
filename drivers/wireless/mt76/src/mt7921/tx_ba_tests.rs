//! Actual retained originator protocol/control/data, with native firmware replies.
use super::*;
use crate::mt7921::association::Security;
const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
fn frame(n: u8) -> Vec<u8> {
    let mut f = vec![n; 60];
    f[..6].copy_from_slice(&AP);
    f[6..12].copy_from_slice(&OWN);
    f[12..14].copy_from_slice(&[8, 0]);
    f
}
fn joined(channel: u8, wide: bool, secure: bool) -> Result<Session<Model>, &'static str> {
    let (mut session, bss) = super::ht20_tests::prepared(channel, secure);
    let permission = if wide {
        super::ht40_tests::permission40(channel, channel + 4)
    } else {
        test_permission_for(channel)
    };
    let security = if secure {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    };
    run(session.associate_station(&bss, b"narf", security, permission, &[]))
        .map_err(|_| "genuine originator HT station")?;
    session.backend.tx_ba_offer = Some((64, 0));
    Ok(session)
}
fn establish(session: &mut Session<Model>) -> Result<(), &'static str> {
    if run(session.negotiate_transmit_ba()) != Ok(true)
        || !session.tx_ba.active()
        || !session.tx_ba.published()
        || !session.backend.tx_ba_native
    {
        return Err("actual ADDBA/native receipts did not activate originator");
    }
    Ok(())
}
fn delba() -> Vec<u8> {
    let mut f = vec![0; 30];
    f[0] = 0xd0;
    f[4..10].copy_from_slice(&OWN);
    f[10..16].copy_from_slice(&AP);
    f[16..22].copy_from_slice(&AP);
    f[24..26].copy_from_slice(&[3, 2]);
    f[28..30].copy_from_slice(&39u16.to_le_bytes());
    let mut packet = descriptor(&f);
    packet[4] = 1;
    packet
}
fn native() -> Result<(), &'static str> {
    for channel in [6, 36] {
        for wide in [false, true] {
            for secure in [false, true] {
                let mut session = joined(channel, wide, secure)?;
                let before = session.backend.frames.len();
                establish(&mut session)?;
                let frames = &session.backend.frames[before..];
                let wtbl = [
                    0, 1, 1, 0, 1, 0, 0, 0, 13, 0, 40, 0, 1, 2, 1, 0, 0, 0, 0, 0, 8, 0, 28, 0, 0,
                    1, 0, 0, 0, 0, 1, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ];
                let sta = [0, 1, 1, 0, 1, 0, 0, 0, 6, 0, 12, 0, 0, 1, 0, 1, 0, 0, 64, 0];
                if frames.len() != 3
                    || frames[0].1.get(24..) != Some(&[3, 0, 1, 2, 16, 0, 0, 0, 0][..])
                    || frames[1].1.get(48..) != Some(&wtbl[..])
                    || frames[2].1.get(48..) != Some(&sta[..])
                {
                    return Err(
                        "literal ADDBA fresh SSN/window -> originator WTBL -> STA native order",
                    );
                }
                session.backend.tx_stall = true;
                for n in 0..8 {
                    session
                        .start_ethernet(&frame(n))
                        .map_err(|_| "active originator eight native MPDUs")?;
                }
                if session.start_ethernet(&frame(9)) != Err(Error::Busy)
                    || session.backend.data_aggregation != [true; 8]
                    || session.backend.data_protection.iter().any(|p| *p != secure)
                {
                    return Err("originator/data token capacity or key profile mismatch");
                }
                session.backend.tx_stall = false;
                session
                    .poll_data_tx()
                    .map_err(|_| "native aggregate packet statuses")?;
                let count = session.backend.frames.len();
                if run(session.negotiate_transmit_ba()) != Err(Error::Busy)
                    || session.backend.frames.len() != count
                    || !session.tx_ba.active()
                {
                    return Err("second entry reset active QoS sequence or native window");
                }
            }
        }
    }
    Ok(())
}
fn mt76_tx_ba_actual_dialog_native_records_and_ht20_ht40_open_wpa2_data() -> TestResult {
    native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_actual_dialog_native_records_and_ht20_ht40_open_wpa2_data
);

fn fallback() -> Result<(), &'static str> {
    for case in 0..11 {
        let mut session = joined(6, false, true)?;
        match case {
            0 => session.backend.tx_ba_offer = None,
            1 => session.backend.tx_ba_status = 37,
            2 => session.backend.tx_ba_offer = Some((0, 0)),
            3 => session.backend.tx_ba_offer = Some((65, 0)),
            n => session.backend.tx_ba_fault = (n - 3) as u8,
        }
        let before = session.backend.frames.len();
        if run(session.negotiate_transmit_ba()) != Ok(false)
            || session.tx_ba.active()
            || session.tx_ba.published()
            || session.tx_ba.remote()
            || !matches!(session.state, State::Associated { .. })
        {
            return Err(
                "decline/foreign/unsupported/no-response did not earn clean native fallback",
            );
        }
        let messages = &session.backend.frames[before..];
        if messages.iter().any(|(_, f)| {
            f.len() >= 60 && f[34..36] == [3, 0] && matches!(&f[56..58], [13, 0] | [6, 0])
        }) {
            return Err("unaccepted ADDBA response programmed a native originator record");
        }
        let stops = messages
            .iter()
            .filter(|(_, f)| f.len() == 30 && f[24..30] == [3, 2, 0, 8, 39, 0])
            .count();
        if stops != usize::from(case != 1) {
            return Err("uncertain remote dialog was abandoned without terminal DELBA");
        }
        run(session.send_ethernet(&frame(7))).map_err(|_| "nonaggregated fallback data")?;
        if session.backend.data_aggregation != [false] {
            return Err("fallback cleared BA_DISABLE");
        }
    }
    Ok(())
}
fn mt76_tx_ba_refusal_no_response_and_invalid_bound_replies_preserve_fallback() -> TestResult {
    fallback().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_refusal_no_response_and_invalid_bound_replies_preserve_fallback
);

fn cancelled() -> Result<(), &'static str> {
    for stage in 0..3 {
        let mut session = joined(6, false, true)?;
        let before = session.backend.frames.len();
        if stage == 0 {
            session.backend.management_stall_after = Some(before + 1);
        } else {
            session.backend.tx_stall_after = Some(before + stage + 1);
        }
        {
            let mut future = pin!(session.negotiate_transmit_ba());
            let mut cx = Context::from_waker(Waker::noop());
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("originator setup skipped native request/WTBL/STA wait");
            }
        }
        if !matches!(session.state, State::Running(Stage::StaRecord))
            || session.tx_ba.active()
            || !session.tx_ba.remote()
            || session.tx_ba.published() != (stage != 0)
            || !session.backend.owner.published
        {
            return Err("cancelled originator released dialog/native uncertainty");
        }
        session.backend.management_stall_after = None;
        session.backend.tx_stall_after = None;
        let before = session.backend.frames.len();
        if session.start_ethernet(&frame(9)) != Err(Error::Busy)
            || run(session.service_keys()).is_err()
            || session.backend.frames.len() != before
            || !matches!(session.state, State::Running(_))
        {
            return Err("late native reply revived cancelled originator");
        }
        run(session.recover(OWN)).map_err(|_| "verified originator cancellation reset")?;
        if session.tx_ba.active() || session.tx_ba.published() || session.tx_ba.remote() {
            return Err("verified reset retained uncertain originator record");
        }
    }
    Ok(())
}
fn mt76_tx_ba_cancel_request_or_each_native_receipt_retains_exact_owner() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_cancel_request_or_each_native_receipt_retains_exact_owner
);

fn rejected() -> Result<(), &'static str> {
    for tag in [13, 6] {
        let mut session = joined(6, false, true)?;
        session.backend.ba_error_tag = Some(tag);
        if run(session.negotiate_transmit_ba()).is_ok()
            || !matches!(session.state, State::Failed { .. })
            || session.tx_ba.active()
            || !session.tx_ba.published()
            || session.security.is_some()
            || !session.backend.owner.published
            || session.start_ethernet(&frame(1)) != Err(Error::Busy)
        {
            return Err("rejected originator native record granted BA or lost uncertain owner");
        }
    }
    for stage in 0..4 {
        let mut session = joined(6, false, true)?;
        let before = session.backend.frames.len();
        session.backend.deny_tx_after = Some(before + stage);
        if run(session.negotiate_transmit_ba()) != Err(Error::Authority)
            || session.backend.frames.len() != before + stage
            || !matches!(session.state, State::Failed { .. })
            || session.tx_ba.active()
            || session.station_permission.is_some()
        {
            return Err("originator publication crossed a revoked source/policy boundary");
        }
    }
    Ok(())
}
fn mt76_tx_ba_native_rejection_and_every_publication_recheck_are_terminal() -> TestResult {
    rejected().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_native_rejection_and_every_publication_recheck_are_terminal
);

fn peer_stop() -> Result<(), &'static str> {
    let mut session = joined(6, false, true)?;
    session.backend.tx_ba_offer = Some((4, 0));
    establish(&mut session)?;
    session.backend.tx_stall = true;
    for n in 0..4 {
        session
            .start_ethernet(&frame(n))
            .map_err(|_| "negotiated four-packet window")?;
    }
    if session.start_ethernet(&frame(5)) != Err(Error::Busy) {
        return Err("host queue exceeded actual response window");
    }
    session.backend.packets.push_back(delba());
    if session.receive_ethernet() != Ok(None) || session.tx_ba.active() || session.keys_pending() {
        return Err("peer DELBA did not pause replenishment before old packet drain");
    }
    session.backend.tx_stall = false;
    session
        .poll_data_tx()
        .map_err(|_| "old originator terminal packets")?;
    if !session.keys_pending() {
        return Err("drained DELBA did not reach native retirement");
    }
    let before = session.backend.frames.len();
    run(session.service_keys()).map_err(|_| "peer originator retirement")?;
    let f = &session.backend.frames[before..];
    if f.len() != 2
        || f[0].1.get(68..82) != Some(&[8, 0, 28, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0][..])
        || f[1].1.get(56..68) != Some(&[6, 0, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0][..])
        || session.tx_ba.published()
        || session.tx_ba.remote()
    {
        return Err("peer DELBA native disable/zero window records or exact receipts missing");
    }
    run(session.send_ethernet(&frame(10))).map_err(|_| "single-frame traffic after peer DELBA")?;
    if session.backend.data_aggregation.last() != Some(&false) {
        return Err("peer DELBA fallback retained aggregate eligibility");
    }
    Ok(())
}
fn mt76_tx_ba_peer_delba_and_small_window_drain_before_native_fallback() -> TestResult {
    peer_stop().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_peer_delba_and_small_window_drain_before_native_fallback
);

fn local_stop() -> Result<(), &'static str> {
    for cancel in [false, true] {
        let mut session = joined(6, false, true)?;
        session.backend.tx_ba_offer = Some((16, 100));
        establish(&mut session)?;
        session
            .backend
            .ticks
            .set(session.backend.ticks.get() + 103_000_000);
        if !session.keys_pending() {
            return Err("native response timeout did not retain inactivity owner");
        }
        let before = session.backend.frames.len();
        if cancel {
            session.backend.tx_stall_after = Some(before + 1);
            {
                let mut f = pin!(session.service_keys());
                let mut cx = Context::from_waker(Waker::noop());
                if f.as_mut().poll(&mut cx).is_ready() {
                    return Err("local originator stop skipped native receipt");
                }
            }
            if !matches!(session.state, State::Running(_))
                || session.tx_ba.active()
                || !session.tx_ba.published()
                || session.start_ethernet(&frame(0)) != Err(Error::Busy)
            {
                return Err("cancelled originator stop freed its native record");
            }
        } else {
            run(session.service_keys()).map_err(|_| "local originator inactivity retirement")?;
            let f = &session.backend.frames[before..];
            if f.len() != 3
                || f[2].1.get(24..) != Some(&[3, 2, 0, 8, 39, 0][..])
                || session.tx_ba.active()
                || session.tx_ba.published()
                || session.tx_ba.remote()
            {
                return Err("native disable receipts did not precede positive local DELBA");
            }
        }
    }
    Ok(())
}
fn mt76_tx_ba_inactivity_and_cancelled_retirement_close_before_native_waits() -> TestResult {
    local_stop().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_inactivity_and_cancelled_retirement_close_before_native_waits
);

fn rekey() -> Result<(), &'static str> {
    let mut session = joined(6, true, true)?;
    session
        .backend
        .packets
        .push_back(super::rx_ba_tests::request_packet(0, 0, 64, 0, 6));
    if session.receive_ethernet() != Ok(None) {
        return Err("coexisting recipient request");
    }
    run(session.service_keys()).map_err(|_| "coexisting recipient BA")?;
    establish(&mut session)?;
    session.backend.tx_stall = true;
    for n in 0..8 {
        session
            .start_ethernet(&frame(n))
            .map_err(|_| "old-key aggregate pipeline")?;
    }
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    session
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol())));
    if session.receive_ethernet() != Ok(None) || session.keys_pending() {
        return Err("old-key packets did not postpone rekey");
    }
    session.backend.tx_stall = false;
    session
        .poll_data_tx()
        .map_err(|_| "all old-key token receipts")?;
    session.backend.access_point = None;
    session.backend.psk = [0x55; 32];
    session.backend.own_mac = OWN;
    session.backend.ap_mac = AP;
    session.backend.anonce = [0x55; 32];
    let before = session.backend.frames.len();
    run(session.service_keys()).map_err(|_| "both BA roles before M2")?;
    let f = &session.backend.frames[before..];
    if f.len() != 6
        || f[2].1.get(24..) != Some(&[3, 2, 0, 8, 39, 0][..])
        || extract_eapol(&f[5].1).is_none()
        || session.tx_ba.active()
        || session.tx_ba.published()
        || !session.rx_ba.records().is_empty()
    {
        return Err("rekey M2 preceded terminal originator/recipient retirement");
    }
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return Err("genuine authenticated new-key M3 missing");
    }
    run(session.service_keys()).map_err(|_| "new native PTK after both role fences")?;
    run(session.send_ethernet(&frame(12))).map_err(|_| "post-rekey nonaggregated fallback")?;
    if session.backend.data_aggregation.last() != Some(&false) || session.security.is_none() {
        return Err("old originator window crossed native key epoch");
    }
    Ok(())
}
fn mt76_tx_ba_rekey_retires_both_roles_and_all_old_packets_before_key_epoch() -> TestResult {
    rekey().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_rekey_retires_both_roles_and_all_old_packets_before_key_epoch
);

fn close() -> Result<(), &'static str> {
    let mut session = joined(6, false, true)?;
    establish(&mut session)?;
    let before = session.backend.frames.len();
    run(session.disassociate_station()).map_err(|_| "originator native close")?;
    let f = &session.backend.frames[before..];
    if f.len() < 5
        || f[0].1.get(68..74) != Some(&[8, 0, 28, 0, 0, 1][..])
        || f[1].1.get(56..64) != Some(&[6, 0, 12, 0, 0, 1, 0, 0][..])
        || f[2].1.first() != Some(&0xc0)
        || f[3].1.get(56..64) != Some(&[17, 0, 8, 0, 1, 0, 0, 0][..])
        || session.tx_ba.published()
        || session.tx_ba.remote()
        || !matches!(session.state, State::ScanReady(_))
    {
        return Err("originator/key/WCID close did not preserve native retirement order");
    }
    let mut used = joined(6, false, false)?;
    run(used.send_ethernet(&frame(0))).map_err(|_| "existing QoS sequence fixture")?;
    let before = used.backend.frames.len();
    if run(used.negotiate_transmit_ba()) != Err(Error::Busy) || used.backend.frames.len() != before
    {
        return Err("midstream hardware sequence was guessed or reset");
    }
    let mut exhausted = joined(6, false, false)?;
    for _ in 0..255 {
        if !exhausted.tx_ba.begin_connection() || exhausted.tx_ba.start(OWN, AP, 6) != Ok(true) {
            return Err("bounded native dialog inventory fixture");
        }
        exhausted.tx_ba.fallback();
    }
    if !exhausted.tx_ba.begin_connection() {
        return Err("clean exhausted-dialog peer fixture");
    }
    let before = exhausted.backend.frames.len();
    if run(exhausted.negotiate_transmit_ba()) != Ok(false)
        || exhausted.backend.frames.len() != before
        || !matches!(exhausted.state, State::Associated { .. })
    {
        return Err("dialog exhaustion reused an old token or broke fresh non-BA association");
    }
    run(exhausted.send_ethernet(&frame(0))).map_err(|_| "exhausted-dialog non-BA data")?;
    Ok(())
}
fn mt76_tx_ba_native_close_precedes_keys_and_midstream_sequence_is_not_guessed() -> TestResult {
    close().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_native_close_precedes_keys_and_midstream_sequence_is_not_guessed
);

fn late_control() -> Result<(), &'static str> {
    for deauth in [false, true] {
        let mut session = joined(6, false, false)?;
        // The STA receipt drains queued native RX. Several ordinary packets
        // precede a later close; one decoded Ethernet result is not RX idle.
        for n in 0..6u16 {
            let mut f = vec![0; 24];
            f[..2].copy_from_slice(&[8, 2]);
            f[4..10].copy_from_slice(&OWN);
            f[10..16].copy_from_slice(&AP);
            f[16..22].copy_from_slice(&AP);
            f[22..24].copy_from_slice(&(n << 4).to_le_bytes());
            f.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3]);
            session.backend.tx_ba_late_rx.push_back(descriptor(&f));
        }
        let close = if deauth {
            let mut f = vec![0; 26];
            f[0] = 0xc0;
            f[4..10].copy_from_slice(&OWN);
            f[10..16].copy_from_slice(&AP);
            f[16..22].copy_from_slice(&AP);
            f[24..26].copy_from_slice(&3u16.to_le_bytes());
            descriptor(&f)
        } else {
            delba()
        };
        session.backend.tx_ba_late_rx.push_back(close);
        let result = run(session.negotiate_transmit_ba());
        if deauth {
            if result != Err(Error::DeviceGone)
                || !matches!(session.state, State::Failed { .. })
                || !session.tx_ba.published()
            {
                return Err("queued AP close did not preserve uncertain native originator claims");
            }
        } else if result != Ok(false)
            || session.tx_ba.active()
            || session.tx_ba.published()
            || session.tx_ba.remote()
        {
            return Err("data ahead of DELBA was mistaken for current native idle");
        }
        if !session.backend.data_aggregation.is_empty() {
            return Err("queued peer close admitted an aggregate before idle fence");
        }
    }
    Ok(())
}
fn mt76_tx_ba_actual_rx_idle_drains_data_ahead_of_peer_close_before_activation() -> TestResult {
    late_control().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_ba_actual_rx_idle_drains_data_ahead_of_peer_close_before_activation
);
