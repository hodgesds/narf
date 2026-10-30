//! Genuine MLME/RSNA, native receipt ownership and a real user-packet sample.
use super::*;
use crate::mt7921::association::Security;
use alloc::boxed::Box;
fn joined(secure: bool) -> Result<Session<Model>, &'static str> {
    let (mut session, bss) = super::ht20_tests::prepared(6, secure);
    run(Box::pin(session.associate_station(
        &bss,
        b"narf",
        if secure {
            Security::Wpa2Psk { psk: [0x55; 32] }
        } else {
            Security::Open
        },
        test_permission(),
        &[],
    )))
    .map_err(|_| "restart genuine station")?;
    session.backend.tx_ba_offer = Some((64, 0));
    // Model variant3 offers the peer's A-MSDU-in-A-MPDU capability.
    // The default offer legitimately clears it and must suppress A-MSDU.
    session.backend.tx_ba_fault = 3;
    Ok(session)
}
fn frame(tid: u8) -> Vec<u8> {
    let mut frame = vec![0x63; 60];
    frame[..6].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[6..12].copy_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame[12..14].copy_from_slice(&[0x88, 0x47]);
    frame[14..18].copy_from_slice(&(u32::from(tid) << 9).to_be_bytes());
    frame
}
fn txs(pid: u8, tid: u8, sn: u16) -> Vec<u8> {
    [
        1u32 << 27 | 40,
        0,
        u32::from(tid) << 26 | 1 << 15,
        u32::from(sn) << 20,
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
fn restart() -> Result<(), &'static str> {
    for secure in [false, true] {
        for tid in 0..8 {
            let mut session = joined(secure)?;
            let epoch = session.receive_epoch;
            let other = (tid + 1) % 8;
            let had_ba = tid % 2 == 0;
            if had_ba && run(session.negotiate_transmit_ba_tid(tid)) != Ok(true)
                || run(session.negotiate_transmit_ba_tid(other)) != Ok(true)
            {
                return Err("restart initial independent BA fixture");
            }
            run(session.send_ethernet(&frame(tid))).map_err(|_| "real midstream data")?;
            if run(session.negotiate_transmit_ba_tid(tid)) != Err(Error::Busy) {
                return Err("fresh API bypassed used native sequence");
            }
            session.backend.tx_stall = true;
            session
                .start_ethernet(&frame(tid))
                .map_err(|_| "older pending native packet")?;
            let before = session.backend.frames.len();
            if run(session.request_transmit_ba_restart_tid(tid)) != Err(Error::Busy)
                || session.backend.frames.len() != before
            {
                return Err("restart sampled before older MAC/FW tokens retired");
            }
            session.backend.tx_stall = false;
            session.poll_data_tx().map_err(|_| "old packet terminal")?;
            let before = session.backend.frames.len();
            run(Box::pin(session.request_transmit_ba_restart_tid(tid)))
                .map_err(|_| "request retained midstream restart")?;
            let retiring = if had_ba { 3 } else { 0 };
            if session.backend.frames.len() != before + retiring
                || session.tx_ba.active_tid(tid)
                || !session.tx_ba.active_tid(other)
                || session.backend.tx_ba_native_tids & (1 << tid) != 0
                || session.receive_current(epoch) != Ok(true)
            {
                return Err("restart did not retire only the old target agreement");
            }
            let before = session.backend.frames.len();
            run(Box::pin(session.service_keys())).map_err(|_| "waiting for a true user packet")?;
            if session.backend.frames.len() != before || session.tx_restart.is_none() {
                return Err("restart invented RF traffic or guessed an SN without a packet");
            }
            run(session.send_ethernet(&frame(other)))
                .map_err(|_| "other TID remains independent")?;
            if session.backend.data_amsdu.last() != Some(&true) {
                return Err("restart suppressed another TID's TX A-MSDU");
            }
            run(session.send_ethernet(&frame(tid)))
                .map_err(|_| "true user MSDU sequence sample")?;
            let header = session
                .backend
                .data_headers
                .last()
                .ok_or("sample descriptor")?;
            if header[20..24] != [3, 4, 0, 0]
                || session.backend.data_aggregation.last() != Some(&false)
                || session.backend.data_amsdu.last() != Some(&false)
            {
                return Err("sample did not isolate HOST TXS/non-BA/non-AMSDU to the real packet");
            }
            let before = session.backend.frames.len();
            run(Box::pin(session.service_keys()))
                .map_err(|_| "terminal packet still awaiting TXS")?;
            if session.start_ethernet(&frame(tid)) != Err(Error::Busy)
                || session.backend.frames.len() != before
                || session.tx_ba.active_tid(tid)
            {
                return Err("TX_FREE/DMA alone resumed target data or BA");
            }
            let observed = if tid % 2 == 0 { 4095 } else { 0x5fd };
            let next = (observed + 1) & 4095;
            session.backend.tx_status.push_back(txs(3, tid, observed));
            run(Box::pin(session.service_keys())).map_err(|_| "native SN-based ADDBA restart")?;
            if !session.tx_ba.active_tid(tid)
                || !session.tx_ba.active_tid(other)
                || session.tx_restart.is_some()
                || session.receive_epoch != epoch
                || session.receive_current(epoch) != Ok(true)
            {
                return Err("restart lost peer/port/epoch or independent agreement");
            }
            let frames = &session.backend.frames[before..];
            if frames.len() != 3
                || frames[0].1[24..26] != [3, 0]
                || frames[0].1[26] != if had_ba { 2 } else { 1 }
                || frames[0].1[31..33] != (next << 4).to_le_bytes()
                || frames[1].1[76..78] != [0, 0]
            {
                return Err("ADDBA did not bind sampled SN+1/dialog or guessed native WTBL SN");
            }
            run(session.send_ethernet(&frame(tid)))
                .map_err(|_| "post-restart genuine aggregate")?;
            if session.backend.data_aggregation.last() != Some(&true)
                || session.backend.data_amsdu.last() != Some(&true)
            {
                return Err(
                    "completed midstream restart did not restore native aggregate eligibility",
                );
            }
        }
    }
    Ok(())
}
fn mt76_midstream_restart_uses_real_native_sequence_all_tids_without_invented_packets() -> TestResult
{
    restart().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_midstream_restart_uses_real_native_sequence_all_tids_without_invented_packets
);

fn errors() -> Result<(), &'static str> {
    for timeout in [false, true] {
        let mut session = joined(true)?;
        let epoch = session.receive_epoch;
        run(session.send_ethernet(&frame(3))).map_err(|_| "error pre-restart traffic")?;
        run(Box::pin(session.request_transmit_ba_restart_tid(3)))
            .map_err(|_| "error sample request")?;
        run(session.send_ethernet(&frame(3))).map_err(|_| "error actual sample packet")?;
        if timeout {
            session
                .backend
                .ticks
                .set(session.backend.ticks.get() + 3_000_000_000);
        } else {
            session.backend.tx_status.push_back(txs(3, 2, 123));
        }
        let error = if timeout {
            Error::Timeout
        } else {
            Error::MalformedEvent
        };
        if run(Box::pin(session.service_keys())) != Err(error)
            || !matches!(session.state, State::Failed { .. })
            || session.receive_current(epoch) != Ok(false)
            || session.backend.receive_open
        {
            return Err("missing/wrong TXS reused a native sequence or station port");
        }
        session
            .backend
            .arm_transmit_sequence(3)
            .map_err(|_| "quarantined old PID leaves another free PID")?;
        if session.backend.sequence.pid(3) != Ok(Some(4)) {
            return Err("ambiguous/cancelled native PID reused without full reset");
        }
    }
    let mut session = joined(false)?;
    run(session.negotiate_transmit_ba_tid(0)).map_err(|_| "cancel old BA")?;
    session.backend.tx_stall_after = Some(session.backend.frames.len() + 1);
    let mut future = Box::pin(session.request_transmit_ba_restart_tid(0));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..10 {
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("cancelled old-BA retirement did not hold native command");
        }
    }
    drop(future);
    if session.state != State::Running(Stage::StaRecord)
        || !session.backend.owner.published
        || session.receive_ethernet() != Err(Error::Busy)
    {
        return Err("cancelled restart exposed Associated or lost DMA ownership");
    }
    Ok(())
}
fn mt76_midstream_restart_missing_wrong_status_and_cancelled_commands_keep_owner_closed(
) -> TestResult {
    errors().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_midstream_restart_missing_wrong_status_and_cancelled_commands_keep_owner_closed
);

fn final_fragment() -> Result<(), &'static str> {
    let mut session = joined(true)?;
    run(session.send_ethernet(&frame(5))).map_err(|_| "fragment restart midstream")?;
    run(Box::pin(session.request_transmit_ba_restart_tid(5)))
        .map_err(|_| "fragment restart request")?;
    session.frag_threshold = 256;
    let mut packet = frame(5);
    packet.resize(714, 0x71);
    let before = session.backend.frames.len();
    run(Box::pin(session.send_ethernet(&packet)))
        .map_err(|_| "async whole fragmented user MSDU")?;
    let fragments = &session.backend.frames[before..];
    if fragments.len() != 4
        || !session.tx_fragments.is_empty()
        || !session.data_pending.is_empty()
        || !session
            .tx_restart
            .is_some_and(|request| request.waiting_receipt())
    {
        return Err("async fragmented MSDU returned before final real native token");
    }
    let headers = &session.backend.data_headers[session.backend.data_headers.len() - 4..];
    if headers[..3].iter().any(|header| header[20..24] != [0; 4])
        || headers[3][20..24] != [3, 4, 0, 0]
        || fragments[3].1[1] & 4 != 0
        || fragments[3].1[22] != 3
    {
        return Err("sample did not bind only the final true user fragment");
    }
    session.backend.tx_status.push_back(txs(3, 5, 0x73));
    run(Box::pin(session.service_keys())).map_err(|_| "fragment actual SN ADDBA")?;
    if !session.tx_ba.active_tid(5) {
        return Err("final-fragment native sequence did not activate BA");
    }
    Ok(())
}
fn mt76_restart_samples_final_real_fragment_and_async_send_drains_whole_msdu() -> TestResult {
    final_fragment().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_restart_samples_final_real_fragment_and_async_send_drains_whole_msdu
);
