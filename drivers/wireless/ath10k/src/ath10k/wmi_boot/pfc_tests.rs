//! Actual RAW/CCMP/HTT/CE station flow with independently authored PFC events.
use super::*;
type Radio = radio::Radio<RadioModel>;

fn input(r: &mut Radio, bytes: &[u8]) {
    let m = &mut r.htt.wmi.htc.transport;
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, bytes)));
}
fn pull(r: &mut Radio) {
    // 10.4 MODE_SWITCH: enabled, zero per-peer records, PUSH_PULL,
    // global push threshold0. It is real input, not a host mode setter.
    input(r, &[0x30, 0, 1, 0, 1, 0, 0, 0]);
}
fn fetch(sequence: u16, peer: u16, tid: u8, msdus: u16, bytes: u32) -> Vec<u8> {
    let mut b = vec![0x16, 0];
    b.extend_from_slice(&sequence.to_le_bytes());
    b.extend_from_slice(&(0x77550000 | u32::from(sequence)).to_le_bytes());
    b.extend_from_slice(&[0, 0, 1, 0]); // no confirms, one complete record.
    b.extend_from_slice(&(peer | (u16::from(tid) << 12)).to_le_bytes());
    b.extend_from_slice(&msdus.to_le_bytes());
    b.extend_from_slice(&bytes.to_le_bytes());
    b
}
fn progress(r: &mut Radio) -> Result<(), &'static str> {
    r.poll_ethernet_now(&station_tests::policy())
        .map(|_| ())
        .map_err(|_| "bounded actual native PFC packet progress failed")
}
fn ready() -> Result<Radio, &'static str> {
    let mut r = joined_features(6, Dialect::TenFour, true, true, 1 << 13);
    if !matches!(start(&mut r, true), Poll::Ready(Ok(_))) || r.station_link().is_none() {
        return Err("real RAW/PFC auth/association/RSNA did not authorize");
    }
    if r.htt
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
        return Err("initial native M2/M4 payloads lacked terminal receipts");
    }
    pull(&mut r);
    progress(&mut r)?;
    let qstate = r
        .htt
        .wmi
        .htc
        .transport
        .inner
        .storage
        .as_ref()
        .unwrap()
        .qstate
        .as_ref()
        .unwrap();
    if qstate.len() != 8192 || qstate.bytes[4772..].iter().any(|b| *b != 0xa5) {
        return Err(
            "rounded physical qstate extent/tail changed during native RSNA and mode publication",
        );
    }
    r.htt.wmi.htc.transport.data.as_mut().unwrap().hold_data = true;
    Ok(r)
}
fn pending(r: &Radio) -> usize {
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
fn sent(r: &Radio) -> usize {
    r.htt.wmi.htc.transport.ce.as_ref().unwrap().sent
}
fn payload(r: &Radio, id: u16) -> Vec<u8> {
    r.htt
        .wmi
        .htc
        .transport
        .inner
        .storage
        .as_ref()
        .unwrap()
        .tx
        .snapshot(id)
        .unwrap()
        .1
}
fn response(r: &Radio) -> Option<&[u8]> {
    r.htt
        .wmi
        .htc
        .transport
        .data
        .as_ref()
        .unwrap()
        .pfc_responses
        .last()
        .map(Vec::as_slice)
}
fn release(r: &mut Radio, id: u16) -> Result<(), &'static str> {
    let m = &mut r.htt.wmi.htc.transport;
    if m.data.as_mut().unwrap().held.pop_front() != Some(id) {
        return Err("native AP did not retain the exact submitted HTT ID");
    }
    complete(m, id, 0); // actual event7, not a direct pool/pipeline mutation.
    progress(r)
}

fn smoke_ath10k_pfc_secure_fetch_budget_qstate_and_exact_air_terminal() -> TestResult {
    (|| {
        let mut r = ready()?;
        let (uplink, downlink) = packets();
        let before = sent(&r);
        let id = r.begin_ethernet(&station_tests::policy(), &uplink).map_err(|_| "queue native original")?;
        let original = payload(&r, id);
        // Non-QoS CCMP RAW is24+CCMP8+LLC6+Ethernet-minus-MAC12+MIC8.
        let wire_length = uplink.len() + 34;
        let table = r.htt.wmi.htc.transport.inner.storage.as_ref().unwrap().qstate.as_ref().unwrap();
        if pending(&r) != 1 || r.tx_in_flight() != 1 || table.read(17) == 0
            || sent(&r) != before || !r.htt.wmi.htc.transport.data.as_ref().unwrap().uplink.is_empty()
            || original.len() != wire_length
            || table.bytes[4772..].iter().any(|b| *b != 0xa5) {
            return Err("host queue invented a native TX, lost its qstate or changed retained payload");
        }
        // Foreign vdev's actual firmware ID18 cannot select station17.
        input(&mut r, &fetch(1, 18, 0, 1, u32::MAX));
        progress(&mut r)?;
        if response(&r).is_none_or(|b| b[14..20] != [0; 6]) || pending(&r) != 1
            || payload(&r, id) != original {
            return Err("foreign peer acquired DATA or response completion credit");
        }
        input(&mut r, &fetch(2, 17, 0, 1, 0));
        progress(&mut r)?;
        if response(&r).is_none_or(|b| b[14..20] != [0; 6]) || pending(&r) != 1 {
            return Err("zero-byte fetch threshold emitted a native frame");
        }
        let responses_before = r.htt.wmi.htc.transport.data.as_ref().unwrap().pfc_responses.len();
        let commands_before = sent(&r);
        {
            let ce = r.htt.wmi.htc.transport.ce.as_mut().unwrap();
            if !ce.source_ready(4).map_err(|_| "actual previous CE4 receipt")? {
                return Err("previous response still owns actual CE4 source");
            }
            ce.hold_source(true);
        }
        // Linux's positive remaining threshold permits one whole final
        // frame despite coarse byte hints; report its actual complete size.
        input(&mut r, &fetch(3, 17, 0, 1, wire_length as u32 - 1));
        progress(&mut r)?;
        if sent(&r) != commands_before + 1 || pending(&r) != 1 || payload(&r, id) != original
            || r.htt.wmi.htc.transport.data.as_ref().unwrap().pfc_responses.len() != responses_before
            || r.htt.wmi.htc.transport.ce.as_mut().unwrap().source_ready(4)
                .map_err(|_| "actual held CE4 source readback")? {
            return Err("partial native CE handoff overwrote response phase or released the air original");
        }
        r.htt.wmi.htc.transport.ce.as_mut().unwrap().hold_source(false);
        progress(&mut r)?;
        if sent(&r) != commands_before + 2 {
            return Err("actual CE4 receipt did not permit exactly one complete pending response");
        }
        let expected = response(&r).ok_or("missing actual native fetch response")?.to_vec();
        if expected[12..16] != [17, 0, 1, 0]
            || expected[16..20] != (wire_length as u32).to_le_bytes()
            || pending(&r) != 1 || r.tx_counters(16).acked != 0
            || r.htt.wmi.htc.transport.data.as_ref().unwrap().uplink.as_slice() != core::slice::from_ref(&uplink)
            || r.htt.wmi.htc.transport.inner.storage.as_ref().unwrap().qstate.as_ref().unwrap().read(17) != 0 {
            return Err("native fetch response, independent CCMP payload or held air ownership wrong");
        }
        let qstate = r.htt.wmi.htc.transport.inner.storage.as_ref().unwrap().qstate.as_ref().unwrap();
        if qstate.bytes[4772..].iter().any(|b| *b != 0xa5) {
            return Err("native queue publication overwrote the rounded DMA allocation tail");
        }
        // A separate actual native event may legally reuse identical opaque
        // echoes. Without a host entry it reports0, never resubmits the old
        // in-flight ID or infers its completion from the response.
        input(&mut r, &fetch(3, 17, 0, 1, wire_length as u32 - 1));
        progress(&mut r)?;
        if response(&r).is_none_or(|b| b[14..20] != [0; 6]) || pending(&r) != 1
            || payload(&r, id) != original
            || r.htt.wmi.htc.transport.data.as_ref().unwrap().uplink.len() != 1 {
            return Err("same-header native event republished or completed the old air ID");
        }
        let second = r.begin_ethernet(&station_tests::policy(), &uplink).map_err(|_| "second queued original")?;
        let second_bytes = payload(&r, second);
        input(&mut r, &fetch(3, 17, 0, 1, wire_length as u32 - 1));
        progress(&mut r)?;
        if response(&r) != Some(expected.as_slice()) || pending(&r) != 2
            || second == id || second_bytes == original
            || payload(&r, second) != second_bytes || payload(&r, id) != original
            || r.htt.wmi.htc.transport.data.as_ref().unwrap().uplink.len() != 2 {
            return Err("new native event with reused echo did not own a distinct fresh-PN ID");
        }
        input(&mut r, &[0x17, 0, 1, 0, 0, 0, 0, 0]);
        progress(&mut r)?;
        if pending(&r) != 2 || r.tx_in_flight() != 2 || payload(&r, id) != original {
            return Err("FETCH_CONFIRM retired native payload or station ticket");
        }
        release(&mut r, id)?;
        if pending(&r) != 1 || r.tx_in_flight() != 1 || r.tx_counters(16).acked != 1 {
            return Err("exact native event7 did not retire its one air owner");
        }
        release(&mut r, second)?;
        let third = r.begin_ethernet(&station_tests::policy(), &uplink).map_err(|_| "third queued original")?;
        // Lower/wrapped opaque sequence is still a new native request.
        input(&mut r, &fetch(0, 17, 0, 1, wire_length as u32));
        progress(&mut r)?;
        if response(&r).is_none_or(|b| b[4..6] != [0, 0] || b[14..16] != [1, 0])
            || pending(&r) != 1 || r.tx_counters(16).acked != 2 {
            return Err("opaque sequence ordering replaced current native request ownership");
        }
        release(&mut r, third)?;
        if pending(&r) != 0 || r.tx_in_flight() != 0 || r.tx_counters(16).acked != 3 {
            return Err("distinct actual air terminals did not retire exactly three original IDs");
        }
        let m = &mut r.htt.wmi.htc.transport;
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&downlink);
        f.queue.push_back(frame);
        if !matches!(drive(r.poll_ethernet(&station_tests::policy())), Poll::Ready(Ok(frames)) if frames == [downlink]) {
            return Err("actual protected downlink failed after native PFC continuation");
        }
        Ok(())
    })().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/pfc",
    smoke_ath10k_pfc_secure_fetch_budget_qstate_and_exact_air_terminal
);

fn smoke_ath10k_pfc_queued_data_keeps_group_rekey_and_old_key_terminals_ordered() -> TestResult {
    (|| {
        let mut r = ready()?;
        let (uplink, _) = packets();
        let id = r
            .begin_ethernet(&station_tests::policy(), &uplink)
            .map_err(|_| "queued original before group rekey")?;
        let original = payload(&r, id);
        {
            let f = r.htt.wmi.htc.transport.data.as_mut().unwrap();
            let actual = f.group_rekey(); // real old-TK CCMP + MIC + AES-KW GTK.
            f.queue.push_back(actual);
        }
        progress(&mut r)?;
        if r.station_link().is_none()
            || pending(&r) != 1
            || r.htt.wmi.htc.transport.data.as_ref().unwrap().group_replies != 0
            || payload(&r, id) != original
        {
            return Err(
                "incoming group1 replaced old key/port before retained host DATA could drain",
            );
        }
        input(&mut r, &fetch(1, 17, 0, 1, u32::MAX));
        progress(&mut r)?;
        if r.station_link().is_some()
            || pending(&r) != 1
            || r.tx_in_flight() != 1
            || r.htt.wmi.htc.transport.data.as_ref().unwrap().group_replies != 0
        {
            return Err("new group reply bypassed old DATA native terminal");
        }
        release(&mut r, id)?;
        let reply = r.tx_in_flight_ids();
        if reply.len() != 1
            || pending(&r) != 1
            || r.station_link().is_some()
            || r.htt.wmi.htc.transport.data.as_ref().unwrap().group_replies != 0
        {
            return Err("group2 did not remain an exact queued Reply owner without fetch credit");
        }
        input(&mut r, &fetch(2, 17, 0, 1, u32::MAX));
        progress(&mut r)?;
        if pending(&r) != 1
            || r.station_link().is_some()
            || r.htt.wmi.htc.transport.data.as_ref().unwrap().group_replies != 1
        {
            return Err("group2 native publication invented its terminal or failed real AES/MIC");
        }
        release(&mut r, reply[0])?;
        if pending(&r) != 0 || r.tx_in_flight() != 0 || r.station_link().is_none() {
            return Err("actual group2 air receipt did not promote the retained new key/port");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/pfc",
    smoke_ath10k_pfc_queued_data_keeps_group_rekey_and_old_key_terminals_ordered
);

fn smoke_ath10k_pfc_missed_fetch_unmap_and_oversized_suffix_retain_native_originals() -> TestResult
{
    (|| {
        for negative in 0..3 {
            let mut r = ready()?;
            let (uplink, _) = packets();
            let id = r.begin_ethernet(&station_tests::policy(), &uplink).map_err(|_| "retained negative original")?;
            let original = payload(&r, id);
            let before = sent(&r);
            match negative {
                0 => {
                    // Age only the existing native operation deadline; real
                    // production data_check/Timeout logic remains unchanged.
                    r.expire_pending_tx_for_test();
                }
                1 => input(&mut r, &[4, 0, 17, 0]),
                _ => {
                    let mut b = vec![0x16, 0, 1, 0, 0x55, 0x44, 0x33, 0x22, 0, 0, 30, 0];
                    for peer in 0u16..30 { b.extend_from_slice(&peer.to_le_bytes()); b.extend_from_slice(&[1, 0, 0xff, 0xff, 0xff, 0xff]); }
                    input(&mut r, &b);
                }
            }
            if r.poll_ethernet_now(&station_tests::policy()).is_ok()
                || pending(&r) != 1 || r.tx_in_flight() != 1 || payload(&r, id) != original
                || sent(&r) != before || r.tx_counters(16).acked != 0
                || !r.htt.wmi.htc.transport.data.as_ref().unwrap().uplink.is_empty()
                || r.begin_ethernet(&station_tests::policy(), &uplink).is_ok() {
                return Err("missing fetch/peer loss/30-record request emitted, completed or rebound a host original");
            }
            if payload(&r, id) != original || pending(&r) != 1 {
                return Err("denied retry consumed/replaced native payload, PN or descriptor");
            }
        }
        Ok(())
    })().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/pfc",
    smoke_ath10k_pfc_missed_fetch_unmap_and_oversized_suffix_retain_native_originals
);

#[cfg(feature = "kernel-test")]
fn smoke_ath10k_pfc_current_original_source_is_required_after_fetch_before_publication(
) -> TestResult {
    (|| {
        let mut r = ready()?;
        let (source, caps) = crate::ath10k::firmware_source::fixture()?;
        r.htt.wmi.htc.transport.sources = Some(source);
        let (uplink, _) = packets();
        let id = r
            .begin_ethernet(&station_tests::policy(), &uplink)
            .map_err(|_| "source-bound queued original")?;
        let original = payload(&r, id);
        let before = sent(&r);
        input(&mut r, &fetch(1, 17, 0, 1, u32::MAX));
        caps[0].revoke();
        if r.poll_ethernet_now(&station_tests::policy()).is_ok()
            || sent(&r) != before
            || payload(&r, id) != original
            || pending(&r) != 1
            || r.begin_ethernet(&station_tests::policy(), &uplink).is_ok()
            || r.tx_counters(16).acked != 0
        {
            return Err(
                "fresh fetch/registry capability lookup revived a revoked queued DATA source",
            );
        }
        // Even after the failed waiter goes away, actual physical ownership
        // remains in the original native pool, not in a response/cookie.
        if pending(&r) != 1 || r.tx_in_flight() != 1 {
            return Err("cancelled source failure released uncertain native queue ownership");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/wireless/ath10k/pfc",
    smoke_ath10k_pfc_current_original_source_is_required_after_fetch_before_publication
);
