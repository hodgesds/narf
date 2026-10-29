//! Firmware-owned TX Block Ack (Linux v7.2 mac.c::ath10k_ampdu_action denies
//! every mac80211 TX action; TX_AMPDU_SETUP_IN_HW). The host obligations are
//! an HT/QoS peer, QoS descriptor TIDs and several MPDUs of one TID in flight;
//! firmware's own ADDBA/DELBA exchange never reaches host ownership.
use super::*;

const AGGREGATE: usize = 8;

fn complete_ids(m: &mut RadioModel, ids: &[u16], status: u8) {
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
/// IEEE 802.11 9.6.4 Block Ack action frame from the AP (category 3).
fn block_ack_action(action: u8) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0x10, 0, 3, action, 1]);
    match action {
        // ADDBA Response: status 0, BA parameters (A-MSDU off, immediate,
        // TID 0, 64-frame buffer), timeout 0.
        1 => f.extend_from_slice(&[0, 0, 0x02, 0x10, 0, 0]),
        // DELBA: initiator TID 0, reason 37 (END_BA).
        _ => f.extend_from_slice(&[0x08, 0, 37, 0]),
    }
    f
}
fn aggregate_in_flight(h: &Harness) -> Result<Vec<u16>, &'static str> {
    enable(h);
    h.join()?;
    let (uplink, _) = packets();
    h.model(|m| m.data.as_mut().unwrap().hold_data = true);
    let qos = h.model(|m| m.data.as_ref().unwrap().qos_frames);
    for _ in 0..AGGREGATE {
        narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "TID-0 enqueue")?;
        h.pump();
    }
    let ids: Vec<u16> = h.model(|m| m.data.as_ref().unwrap().held.iter().copied().collect());
    if ids.len() != AGGREGATE
        || h.model(|m| m.inner.storage.as_ref().unwrap().tx.pending()) != AGGREGATE
        || h.device.radio.try_lock().unwrap().tx_in_flight() != AGGREGATE
        || h.model(|m| m.data.as_ref().unwrap().qos_frames) != qos + AGGREGATE
    {
        return Err("HT peer did not hold several QoS MPDUs of one TID in flight");
    }
    Ok(ids)
}

fn smoke_ath10k_tx_ba_firmware_aggregates_several_tid_mpdus() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new(version, dialect, true);
        let ids = match aggregate_in_flight(&h) {
            Ok(ids) => ids,
            Err(e) => return TestResult::Fail(e),
        };
        // Firmware's ADDBA Response/DELBA are its own; the host neither
        // answers nor publishes a WMI ADDBA command (aggr_mode AUTO).
        let sent = h.model(|m| m.sent.len());
        h.model(|m| {
            management_frame(m, block_ack_action(1));
            management_frame(m, block_ack_action(2));
        });
        h.pump();
        if !h.device.link_up() || h.model(|m| m.sent.len()) != sent {
            return TestResult::Fail("firmware TX BA exchange reached host ownership");
        }
        // One BA-window completion names every MPDU of the aggregate.
        h.model(|m| {
            m.data.as_mut().unwrap().held.clear();
            m.data.as_mut().unwrap().hold_data = false;
            complete_ids(m, &ids, 0);
        });
        h.pump();
        let r = h.device.radio.try_lock().unwrap();
        if r.tx_in_flight() != 0
            || r.tx_counters(0).acked != AGGREGATE as u64
            || r.htt
                .wmi
                .htc
                .transport
                .inner
                .storage
                .as_ref()
                .unwrap()
                .tx
                .pending()
                != 0
        {
            return TestResult::Fail("aggregate completion did not retire each MPDU ID");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_tx_ba_firmware_aggregates_several_tid_mpdus
);

fn smoke_ath10k_aggregate_retry_exhaustion_is_accounted_not_fatal() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    let ids = match aggregate_in_flight(&h) {
        Ok(ids) => ids,
        Err(e) => return TestResult::Fail(e),
    };
    // Firmware retransmits unacknowledged subframes itself; NO_ACK and
    // DISCARD are terminal after its retry budget (htt_rx.c status map).
    h.model(|m| {
        m.data.as_mut().unwrap().held.clear();
        complete_ids(m, &ids[..3], 0);
        complete_ids(m, &ids[3..6], 2);
        complete_ids(m, &ids[6..], 1);
    });
    h.pump();
    {
        let r = h.device.radio.try_lock().unwrap();
        let c = r.tx_counters(0);
        if c.acked != 3 || c.no_ack != 3 || c.discarded != 2 || r.tx_in_flight() != 0 {
            return TestResult::Fail("aggregate subframe outcomes were not accounted per TID");
        }
    }
    if !h.device.link_up() {
        return TestResult::Fail("retry-exhausted subframes failed the station link");
    }
    // A malformed status (> POSTPONE) is rejected before any ID is freed.
    let (uplink, _) = packets();
    narf_net::iface::send_on(&h.name, &uplink).ok();
    h.pump();
    let id = h.model(|m| m.data.as_mut().unwrap().held.pop_front());
    let Some(id) = id else {
        return TestResult::Fail("link did not admit a frame after retry exhaustion");
    };
    h.model(|m| complete_ids(m, &[id], 4));
    h.pump();
    if h.model(|m| m.inner.storage.as_ref().unwrap().tx.pending()) != 1 {
        return TestResult::Fail("malformed completion status released DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_aggregate_retry_exhaustion_is_accounted_not_fatal
);

fn smoke_ath10k_tx_ba_teardown_retains_aggregate_payloads() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    if let Err(e) = aggregate_in_flight(&h) {
        return TestResult::Fail(e);
    }
    h.model(|m| teardown_tests::arm_data_disconnect(m, false));
    let _ = drive(h.device.disassociate());
    if !h.closed()
        || h.model(|m| m.inner.storage.as_ref().unwrap().tx.pending()) != AGGREGATE
        || h.device.radio.try_lock().unwrap().tx_in_flight() != AGGREGATE
    {
        return TestResult::Fail("teardown released in-flight aggregate MPDU DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht",
    smoke_ath10k_tx_ba_teardown_retains_aggregate_payloads
);
