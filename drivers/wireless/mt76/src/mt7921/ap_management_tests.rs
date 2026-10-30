//! Native management result follows actual requested TXS plus packet receipt.
use super::*;
fn report(pid: u8, wcid: u16, acked: bool) -> Vec<u8> {
    [
        1u32 << 27 | 40,
        0,
        if acked { 0 } else { 1 << 16 },
        0,
        u32::from(wcid) << 16,
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
fn frame(own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
    let mut f = vec![0; 30];
    f[0] = 0xb0;
    f[4..10].copy_from_slice(&peer);
    f[10..16].copy_from_slice(&own);
    f[16..22].copy_from_slice(&own);
    f[26] = 2;
    f
}
fn management() -> Result<(), &'static str> {
    let (mut session, fixture, peer) = secure_peer()?;
    for (pid, associated, acked) in [(3, true, true), (4, false, false)] {
        let destination = if associated {
            peer
        } else {
            [2, 0, 0, 0, 0x77, 1]
        };
        let wcid = if associated { 1 } else { 19 };
        session
            .backend
            .tx_status
            .push_back(report(pid, wcid, acked));
        let authority = bound(&fixture)?;
        let epoch = session.receive_epoch;
        if run(Box::pin(session.ap_send_management(
            authority,
            &frame(fixture.radio.mac(), destination),
        ))) != Ok(acked)
        {
            return Err("native AP management did not use its actual TXS ACK result");
        }
        let txd = session
            .backend
            .data_headers
            .last()
            .ok_or("native AP management TXD")?;
        if txd[20..24] != [pid, 4, 0, 0]
            || txd[4] != wcid as u8
            || !matches!(session.state, State::AccessPoint { .. })
            || session.receive_epoch != epoch
            || !session.data_pending.is_empty()
        {
            return Err("management ACK changed BSS/copy owner or skipped native PID/WCID");
        }
    }
    let authority = bound(&fixture)?;
    if run(Box::pin(session.ap_send_management(
        authority,
        &frame(fixture.radio.mac(), [0xff; 6]),
    ))) != Ok(false)
    {
        return Err("no-ACK multicast management invented peer ACK");
    }
    if session.backend.data_headers.last().unwrap()[20..24] != [0; 4] {
        return Err("multicast management requested an impossible peer ACK");
    }
    let authority = bound(&fixture)?;
    let pending_frame = frame(fixture.radio.mac(), peer);
    let mut operation = Box::pin(session.ap_send_management(authority, &pending_frame));
    let mut cx = Context::from_waker(Waker::noop());
    if operation.as_mut().poll(&mut cx).is_ready() {
        return Err("TX_FREE/DMA-only management produced a positive ACK");
    }
    drop(operation);
    if session.state != State::Running(Stage::ApPeer)
        || session.ap_owner.as_ref().unwrap().pending.is_none()
        || bound(&fixture).is_ok()
    {
        return Err("dropped management ACK wait released its native control owner");
    }
    run(Box::pin(session.shutdown())).map_err(|_| "abandoned management native reset")?;
    if session.ap_owner.is_some() || bound(&fixture).is_err() {
        return Err("management reset did not retire native request ownership");
    }
    Ok(())
}
fn mt76_ap_native_management_ack_is_txs_not_packet_release_and_cancellation_retains_owner(
) -> TestResult {
    management().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_native_management_ack_is_txs_not_packet_release_and_cancellation_retains_owner
);
