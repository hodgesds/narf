//! Genuine HT/WMM station admission and queue/control/key lifetime composition.
use super::*;
use crate::mt7921::association::Security;
const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
fn frame(n: u8) -> Vec<u8> {
    let mut bytes = vec![n; 60];
    bytes[..6].copy_from_slice(&AP);
    bytes[6..12].copy_from_slice(&OWN);
    bytes[12..14].copy_from_slice(&[8, 0]);
    bytes
}
fn joined(ht: bool, secured: bool) -> Result<Session<Model>, &'static str> {
    let (mut session, mut bss) = super::ht20_tests::prepared(6, secured);
    if !ht {
        session.backend.ht_reply = None;
        let mut retained = Vec::new();
        let mut rest = bss.information_elements.as_slice();
        while !rest.is_empty() {
            let length = 2 + usize::from(rest[1]);
            if !matches!(rest[0], 45 | 61) {
                retained.extend_from_slice(&rest[..length]);
            }
            rest = &rest[length..];
        }
        bss.information_elements = retained;
    }
    let security = if secured {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    };
    run(session.associate_station(&bss, b"narf", security, test_permission_for(6), &[]))
        .map_err(|_| "genuine queued station")?;
    session.backend.tx_stall = true;
    Ok(session)
}
fn fill(session: &mut Session<Model>) -> Result<(), &'static str> {
    for n in 0..8 {
        session
            .start_ethernet(&frame(n))
            .map_err(|_| "eight owned native submissions")?;
    }
    if session.data_pending.len() != 8 {
        return Err("pipeline lost a submitted packet owner");
    }
    Ok(())
}
fn admission() -> Result<(), &'static str> {
    for secured in [false, true] {
        let mut session = joined(true, secured)?;
        let before = session.backend.frames.len();
        fill(&mut session)?;
        if session.start_ethernet(&frame(9)) != Err(Error::Busy)
            || session.backend.frames.len() != before + 8
            || session.poll_data_tx() != Ok(false)
        {
            return Err("HT pipeline overflow or stalled slot reuse");
        }
        session.backend.tx_stall = false;
        session.backend.completion_budget = Some(3);
        if session.poll_data_tx() != Ok(true) || session.data_pending.len() != 5 {
            return Err("partial terminal progress did not expose only bounded capacity");
        }
        for n in 0..3 {
            session
                .start_ethernet(&frame(20 + n))
                .map_err(|_| "refill terminal capacity")?;
        }
        if session.data_pending.len() != 8 || session.start_ethernet(&frame(29)) != Err(Error::Busy)
        {
            return Err("refill exceeded native bounded queue");
        }
        session.backend.completion_budget = None;
        if !session
            .poll_data_tx()
            .map_err(|_| "drain terminal pipeline")?
            || !session.data_pending.is_empty()
        {
            return Err("terminal pipeline retained software pending entries");
        }
        if session
            .backend
            .data_protection
            .iter()
            .any(|p| *p != secured)
            || session.backend.data_qos.iter().any(|q| !*q)
        {
            return Err("pipelined frame crossed negotiated QoS/security profile");
        }
        let mut legacy = joined(false, secured)?;
        legacy
            .start_ethernet(&frame(0))
            .map_err(|_| "legacy single-frame fallback")?;
        if legacy.start_ethernet(&frame(1)) != Err(Error::Busy) || legacy.data_pending.len() != 1 {
            return Err("legacy profile lost serialized fallback");
        }
    }
    Ok(())
}
fn mt76_tx_pipeline_genuine_ht_wmm_open_wpa2_capacity_and_legacy_fallback() -> TestResult {
    admission().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_pipeline",
    mt76_tx_pipeline_genuine_ht_wmm_open_wpa2_capacity_and_legacy_fallback
);

fn failures() -> Result<(), &'static str> {
    for timeout in [false, true] {
        let mut session = joined(true, true)?;
        fill(&mut session)?;
        let error = if timeout {
            session
                .backend
                .ticks
                .set(session.backend.ticks.get() + 4_000_000_000);
            Error::Timeout
        } else {
            session.backend.tx_stall = false;
            session.backend.completion_status = 3;
            Error::Rejected(3)
        };
        if session.poll_data_tx() != Err(error)
            || !matches!(session.state, State::Failed { .. })
            || session.data_pending.len() != if timeout { 8 } else { 7 }
            || session.security.is_some()
            || session.station_permission.is_some()
            || !session.backend.owner.published
            || session.start_ethernet(&frame(9)) != Err(Error::Busy)
        {
            return Err("pipeline failure released uncertain tail or retained producer/key grant");
        }
    }
    Ok(())
}
fn mt76_tx_pipeline_rejected_head_and_oldest_timeout_preserve_uncertain_tail() -> TestResult {
    failures().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_pipeline",
    mt76_tx_pipeline_rejected_head_and_oldest_timeout_preserve_uncertain_tail
);

fn authority() -> Result<(), &'static str> {
    let mut session = joined(true, true)?;
    let before = session.backend.frames.len();
    // Model::check_tx_permission samples the native publication log length.
    // Revoke after exactly three additional data descriptors are admitted.
    session.backend.deny_tx_after = Some(before + 3);
    for n in 0..3 {
        session
            .start_ethernet(&frame(n))
            .map_err(|_| "per-frame current-grant fixture")?;
    }
    if session.start_ethernet(&frame(4)) != Err(Error::Authority)
        || session.backend.frames.len() != before + 3
        || session.data_pending.len() != 3
        || !matches!(session.state, State::Failed { .. })
    {
        return Err("later queued frame bypassed current source/policy admission");
    }
    session.backend.deny_tx_after = None;
    if session.start_ethernet(&frame(5)) != Err(Error::Busy) || !session.backend.owner.published {
        return Err("restored authority reused terminal queue lifetime");
    }
    Ok(())
}
fn mt76_tx_pipeline_each_native_publication_requires_current_authority() -> TestResult {
    authority().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_pipeline",
    mt76_tx_pipeline_each_native_publication_requires_current_authority
);

fn control_priority() -> Result<(), &'static str> {
    let mut session = joined(true, true)?;
    fill(&mut session)?;
    // A native bound EAPOL challenge must stop replenishment, then wait for
    // every old-key packet's terminal receipt before the first M2/key write.
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
        return Err("queued EAPOL did not wait for old-key packets");
    }
    let before = session.backend.frames.len();
    run(session.service_keys()).map_err(|_| "deferred rekey service")?;
    if session.backend.frames.len() != before {
        return Err("EAPOL reply preceded old-key TX retirement");
    }
    session.backend.tx_stall = false;
    session.backend.completion_budget = Some(1);
    if session.poll_data_tx() != Ok(false)
        || session.data_pending.len() != 7
        || session.start_ethernet(&frame(19)) != Err(Error::Busy)
    {
        return Err("pending rekey did not fence packet replenishment below capacity");
    }
    session.backend.completion_budget = None;
    session
        .poll_data_tx()
        .map_err(|_| "old-key terminal drain")?;
    if !session.data_pending.is_empty() || !session.keys_pending() {
        return Err("terminal drain did not release key control priority");
    }
    session.backend.access_point = None;
    session.backend.psk = [0x55; 32];
    session.backend.own_mac = OWN;
    session.backend.ap_mac = AP;
    session.backend.anonce = [0x55; 32];
    run(session.service_keys()).map_err(|_| "genuine rekey M2 after data receipts")?;
    if !session.backend.frames[before..]
        .iter()
        .any(|(_, f)| extract_eapol(f).is_some())
    {
        return Err("rekey stayed unreachable after all old-key terminal receipts");
    }
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return Err("genuine rekey M3 receipt absent");
    }
    run(session.service_keys()).map_err(|_| "new native PTK receipts")?;
    if session.security.is_none() || !matches!(session.state, State::Associated { .. }) {
        return Err("terminal packet/control composition failed to restore associated owner");
    }
    Ok(())
}
fn mt76_tx_pipeline_old_key_packets_drain_before_rekey_and_block_replenishment() -> TestResult {
    control_priority().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_pipeline",
    mt76_tx_pipeline_old_key_packets_drain_before_rekey_and_block_replenishment
);

fn cancellation() -> Result<(), &'static str> {
    let mut session = joined(true, true)?;
    fill(&mut session)?;
    let before = session.backend.frames.len();
    {
        let mut future = pin!(session.disassociate_station());
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("teardown skipped outstanding native packet receipt");
        }
    }
    if !matches!(session.state, State::Running(Stage::StaRecord))
        || session.security.is_some()
        || session.station_permission.is_some()
        || session.data_pending.len() != 8
        || session.backend.frames.len() != before
        || !session.backend.owner.published
    {
        return Err("cancelled queue drain published key/WCID removal or released tail");
    }
    session.backend.tx_stall = false;
    session
        .poll_data_tx()
        .map_err(|_| "late terminal packet cleanup")?;
    if !matches!(session.state, State::Running(_))
        || session.start_ethernet(&frame(8)) != Err(Error::Busy)
    {
        return Err("late packet receipts restored cancelled closing owner");
    }
    run(session.recover(OWN)).map_err(|_| "verified queue reset")?;
    if !session.data_pending.is_empty() || !matches!(session.state, State::RadioReady(_)) {
        return Err("verified reset retained old queue epoch");
    }
    Ok(())
}
fn mt76_tx_pipeline_teardown_cancel_keeps_all_packets_until_terminal_or_verified_reset(
) -> TestResult {
    cancellation().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_pipeline",
    mt76_tx_pipeline_teardown_cancel_keeps_all_packets_until_terminal_or_verified_reset
);
