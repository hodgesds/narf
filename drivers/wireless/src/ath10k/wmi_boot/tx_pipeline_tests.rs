//! N-deep native HTT TX: per-MSDU-ID DMA ownership, multi-ID terminal
//! indications, explicit key-reply fencing and teardown retention.
use super::*;

const DEPTH: usize = 32;

/// One HTT_T2H TX completion indication naming several MSDU IDs
/// (Linux htt.h struct htt_data_tx_completion, num_msdus + le16 IDs).
fn complete_batch(m: &mut RadioModel, ids: &[u16], status: u8) {
    let mut b = vec![7, status, ids.len() as u8, 0];
    for id in ids {
        b.extend_from_slice(&id.to_le_bytes());
    }
    if ids.len() % 2 == 1 {
        b.extend_from_slice(&[0xff, 0xff]);
    }
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &b)));
}
fn dma_pending(r: &radio::Radio<RadioModel>) -> usize {
    r.htt
        .wmi
        .htc
        .transport
        .inner
        .storage
        .as_ref()
        .unwrap()
        .tx
        .pending()
}
fn authorized_hold() -> radio::Radio<RadioModel> {
    let mut r = joined(4, Dialect::Tlv, true, true);
    assert!(matches!(start(&mut r, true), Poll::Ready(Ok(_))));
    r.htt.wmi.htc.transport.data.as_mut().unwrap().hold_data = true;
    r
}
fn send(
    r: &mut radio::Radio<RadioModel>,
    uplink: &[u8],
    n: usize,
) -> Result<Vec<u16>, &'static str> {
    let mut ids = Vec::new();
    for _ in 0..n {
        match drive(r.transmit_ethernet(&station_tests::policy(), uplink)) {
            Poll::Ready(Ok(id)) => ids.push(id),
            _ => return Err("native HTT refused an admissible in-flight data frame"),
        }
    }
    Ok(ids)
}

fn smoke_ath10k_tx_pipeline_multi_id_out_of_order_completion() -> TestResult {
    let mut r = authorized_hold();
    let (uplink, _) = packets();
    let ids = match send(&mut r, &uplink, 4) {
        Ok(ids) => ids,
        Err(e) => return TestResult::Fail(e),
    };
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != 4
        || r.tx_in_flight() != 4
        || dma_pending(&r) != 4
        || r.htt.wmi.htc.transport.data.as_ref().unwrap().held.len() != 4
    {
        return TestResult::Fail("four data frames did not each own a distinct HTT ID and payload");
    }
    // Out-of-order, multi-MSDU terminal indications, one ACKed, one NO_ACK.
    let m = &mut r.htt.wmi.htc.transport;
    m.data.as_mut().unwrap().held.clear();
    complete_batch(m, &[ids[2], ids[0]], 0);
    complete_batch(m, &[ids[3], ids[1], ids[1]], 2);
    // The duplicate above must be rejected without freeing either ID.
    if drive(r.poll_ethernet(&station_tests::policy())).is_ready_and_ok()
        || dma_pending(&r) != 2
        || r.tx_in_flight() != 2
    {
        return TestResult::Fail("duplicate ID in one indication partially retired DMA");
    }
    TestResult::Pass
}
trait ReadyOk {
    fn is_ready_and_ok(&self) -> bool;
}
impl<T, E> ReadyOk for Poll<Result<T, E>> {
    fn is_ready_and_ok(&self) -> bool {
        matches!(self, Poll::Ready(Ok(_)))
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_tx_pipeline_multi_id_out_of_order_completion
);

fn smoke_ath10k_tx_pipeline_batch_completion_accounts_per_tid() -> TestResult {
    let mut r = authorized_hold();
    let (uplink, _) = packets();
    let ids = match send(&mut r, &uplink, 4) {
        Ok(ids) => ids,
        Err(e) => return TestResult::Fail(e),
    };
    let m = &mut r.htt.wmi.htc.transport;
    m.data.as_mut().unwrap().held.clear();
    complete_batch(m, &[ids[2], ids[0]], 0);
    complete_batch(m, &[ids[3], ids[1]], 2);
    if !drive(r.poll_ethernet(&station_tests::policy())).is_ready_and_ok()
        || r.tx_in_flight() != 0
        || dma_pending(&r) != 0
        || r.station_link().is_none()
    {
        return TestResult::Fail("multi-ID indications did not retire every exact HTT ID");
    }
    let c = r.tx_counters(16);
    if c.acked != 2 || c.no_ack != 2 || c.discarded != 0 {
        return TestResult::Fail("NO_ACK data receipts were not accounted per TID");
    }
    // A NO_ACK data receipt is not a link failure: the next frame is admitted.
    r.htt.wmi.htc.transport.data.as_mut().unwrap().hold_data = false;
    if send(&mut r, &uplink, 1).is_err()
        || !drive(r.poll_ethernet(&station_tests::policy())).is_ready_and_ok()
        || r.tx_counters(16).acked != 3
    {
        return TestResult::Fail("data path closed after an accounted NO_ACK receipt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_tx_pipeline_batch_completion_accounts_per_tid
);

fn smoke_ath10k_tx_pipeline_depth_bound_refuses_without_publishing() -> TestResult {
    let mut r = authorized_hold();
    let (uplink, _) = packets();
    if send(&mut r, &uplink, DEPTH).is_err() || r.tx_in_flight() != DEPTH {
        return TestResult::Fail("pipeline did not admit its full in-flight depth");
    }
    let sent = r.htt.wmi.htc.transport.data.as_ref().unwrap().uplink.len();
    if drive(r.transmit_ethernet(&station_tests::policy(), &uplink))
        != Poll::Ready(Err(radio::Error::Htt(
            crate::ath10k::htt_runtime::Error::Busy,
        )))
        || r.htt.wmi.htc.transport.data.as_ref().unwrap().uplink.len() != sent
        || dma_pending(&r) != DEPTH
    {
        return TestResult::Fail("over-depth data frame was published or consumed DMA");
    }
    let ids: Vec<u16> = core::mem::take(&mut r.htt.wmi.htc.transport.data.as_mut().unwrap().held)
        .into_iter()
        .collect();
    complete_batch(&mut r.htt.wmi.htc.transport, &ids[..1], 0);
    if !drive(r.poll_ethernet(&station_tests::policy())).is_ready_and_ok()
        || r.tx_in_flight() != DEPTH - 1
        || send(&mut r, &uplink, 1).is_err()
    {
        return TestResult::Fail("one terminal receipt did not free exactly one slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_tx_pipeline_depth_bound_refuses_without_publishing
);

fn smoke_ath10k_tx_pipeline_key_reply_drains_data_and_fences_admission() -> TestResult {
    let mut r = authorized_hold();
    let (uplink, _) = packets();
    let ids = match send(&mut r, &uplink, 3) {
        Ok(ids) => ids,
        Err(e) => return TestResult::Fail(e),
    };
    let m = &mut r.htt.wmi.htc.transport;
    let f = m.data.as_mut().unwrap();
    f.held.clear();
    let group = f.group_rekey();
    f.queue.push_back(group);
    let _ = drive(r.poll_ethernet(&station_tests::policy()));
    if r.htt.wmi.htc.transport.data.as_ref().unwrap().group_replies != 0 || r.tx_in_flight() != 3 {
        return TestResult::Fail("group 2/2 reply overtook in-flight data IDs");
    }
    complete_batch(&mut r.htt.wmi.htc.transport, &ids, 0);
    let _ = drive(r.poll_ethernet(&station_tests::policy()));
    let f = r.htt.wmi.htc.transport.data.as_ref().unwrap();
    if f.group_replies != 1 || f.held.len() != 1 || r.tx_in_flight() != 1 {
        return TestResult::Fail("drained data did not release the fenced key reply");
    }
    let sent = f.uplink.len();
    if drive(r.transmit_ethernet(&station_tests::policy(), &uplink)).is_ready_and_ok()
        || r.htt.wmi.htc.transport.data.as_ref().unwrap().uplink.len() != sent
    {
        return TestResult::Fail("data was admitted while a key reply awaited its receipt");
    }
    let m = &mut r.htt.wmi.htc.transport;
    let f = m.data.as_mut().unwrap();
    f.hold_data = false;
    let reply = f.held.pop_front().unwrap();
    complete(m, reply, 0);
    let _ = drive(r.poll_ethernet(&station_tests::policy()));
    if r.tx_in_flight() != 0 || r.station_link().is_none() || send(&mut r, &uplink, 1).is_err() {
        return TestResult::Fail("key reply receipt did not reopen data admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_tx_pipeline_key_reply_drains_data_and_fences_admission
);

fn smoke_ath10k_tx_pipeline_teardown_retains_every_in_flight_payload() -> TestResult {
    let mut r = authorized_hold();
    let (uplink, _) = packets();
    if send(&mut r, &uplink, 5).is_err() {
        return TestResult::Fail("setup could not publish five frames");
    }
    // DOWN/DELETE begin by closing the data owner before any await.
    let _ = drive(r.disconnect_station());
    if r.station_link().is_some() || dma_pending(&r) != 5 || r.tx_in_flight() != 5 {
        return TestResult::Fail("teardown released or pretended to complete in-flight HTT IDs");
    }
    if drive(r.transmit_ethernet(&station_tests::policy(), &uplink)).is_ready_and_ok()
        || drive(r.poll_ethernet(&station_tests::policy())).is_ready_and_ok()
    {
        return TestResult::Fail("closed owner resumed packet service with IDs outstanding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_tx_pipeline_teardown_retains_every_in_flight_payload
);
