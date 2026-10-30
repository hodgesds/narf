//! Distinct TID protocol/native ownership; expected wire fields are literal
//! Linux mt76_connac_mcu_{wtbl,sta}_ba_tlv and mac80211 ADDBA fields.
use super::*;

fn tid_frame(tid: u8) -> Vec<u8> {
    let mut bytes = frame(0);
    bytes[12..14].copy_from_slice(&0x8847u16.to_be_bytes());
    bytes[14..18].copy_from_slice(&(u32::from(tid) << 9).to_be_bytes());
    bytes
}

fn all_tids() -> Result<(), &'static str> {
    for secure in [false, true] {
        let mut session = joined(6, false, secure)?;
        for tid in 0..8 {
            let before = session.backend.frames.len();
            if run(session.negotiate_transmit_ba_tid(tid)) != Ok(true) {
                return Err("per-TID ADDBA/native completion");
            }
            let frames = &session.backend.frames[before..];
            let mut request = [3, 0, 1, 3, 16, 0, 0, 0, 0];
            request[3] |= tid << 2;
            let mut wtbl = [
                0, 1, 1, 0, 1, 0, 0, 0, 13, 0, 40, 0, 1, 2, 1, 0, 0, 0, 0, 0, 8, 0, 28, 0, 0, 1, 0,
                0, 0, 0, 1, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            wtbl[24] = tid;
            let mut sta = [0, 1, 1, 0, 1, 0, 0, 0, 6, 0, 12, 0, 0, 1, 0, 1, 0, 0, 64, 0];
            sta[12] = tid;
            sta[15] = 1 << tid;
            if frames.len() != 3
                || frames[0].1.get(24..) != Some(request.as_slice())
                || frames[1].1.get(48..) != Some(wtbl.as_slice())
                || frames[2].1.get(48..) != Some(sta.as_slice())
                || !(0..=tid).all(|t| session.tx_ba.active_tid(t))
            {
                return Err("TID request/WTBL/STA fields or independent active records");
            }
        }
        for tid in 0..8 {
            run(session.send_ethernet(&tid_frame(tid))).map_err(|_| "per-TID aggregate data")?;
        }
        if session.backend.data_tids != [0, 1, 2, 3, 4, 5, 6, 7]
            || session.backend.data_aggregation != [true; 8]
            || session.backend.data_ba_disabled != [false; 8]
        {
            return Err("per-TID agreement did not select its native aggregate eligibility");
        }
        run(session.disassociate_station()).map_err(|_| "all-TID native teardown")?;
        if session.tx_ba.published()
            || session.tx_ba.remote()
            || session.backend.tx_ba_native_tids != 0
        {
            return Err("disconnect left an independent native originator record");
        }
    }
    Ok(())
}
fn mt76_all_tx_tids_have_independent_addba_native_records_and_data() -> TestResult {
    all_tids().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_all_tx_tids_have_independent_addba_native_records_and_data
);

fn isolation() -> Result<(), &'static str> {
    let mut session = joined(6, false, false)?;
    establish(&mut session)?;
    session.backend.tx_ba_offer = Some((3, 0));
    if run(session.negotiate_transmit_ba_tid(4)) != Ok(true) {
        return Err("TID4 fixture");
    }
    session.backend.tx_ba_fault = 2; // response names TID2, not requested TID3.
    if run(session.negotiate_transmit_ba_tid(3)) != Ok(false)
        || !session.tx_ba.active_tid(0)
        || !session.tx_ba.active_tid(4)
        || session.tx_ba.active_tid(2)
        || session.tx_ba.active_tid(3)
    {
        return Err("cross-TID response or fallback changed another agreement");
    }
    session.backend.tx_ba_fault = 0;
    // A peer DELBA for TID4 must not stop TID0. Both disable receipts precede
    // fallback, and no foreign TID may borrow the old session's native bit.
    let mut packet = delba();
    let at = packet.len() - 4;
    packet[at + 1] = 0x40;
    session.backend.packets.push_back(packet);
    session.receive_ethernet().map_err(|_| "TID4 DELBA")?;
    run(session.service_keys()).map_err(|_| "TID4 native retirement")?;
    if !session.tx_ba.active_tid(0)
        || session.tx_ba.active_tid(4)
        || session.backend.tx_ba_native_tids != 1
    {
        return Err("TID4 DELBA retired an unrelated originator");
    }
    run(session.send_ethernet(&tid_frame(4))).map_err(|_| "retired TID4 fallback")?;
    if session.backend.data_aggregation.last() != Some(&false) {
        return Err("retired TID still aggregated");
    }
    let before = session.backend.frames.len();
    if run(session.negotiate_transmit_ba_tid(4)) != Err(Error::Busy)
        || run(session.negotiate_transmit_ba_tid(8)) != Err(Error::Bounds)
        || session.backend.frames.len() != before
    {
        return Err("used/out-of-range TID reset or published native sequence");
    }
    Ok(())
}
fn mt76_tx_tid_responses_delba_and_used_sequence_are_isolated() -> TestResult {
    isolation().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_tx_tid_responses_delba_and_used_sequence_are_isolated
);
