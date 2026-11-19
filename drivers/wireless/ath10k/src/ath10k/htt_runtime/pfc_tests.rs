//! Independent packed records and qstate offsets from Linux7.2 htt.h.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const AP: [u8; 6] = [2, 8, 9, 10, 11, 12];
fn mapped() -> Owner {
    let mut owner = Owner::new(2500);
    owner
        .observe(&[3, 0, 17, 0, 2, 8, 9, 10, 11, 12, 0, 0])
        .unwrap();
    owner
}
fn ids() -> [u64; 32] {
    let mut ids = [0; 32];
    ids[0] = 1 << 17;
    ids
}
fn fetch(sequence: u16, count: usize) -> Vec<u8> {
    let mut b = vec![0x16, 0];
    b.extend_from_slice(&sequence.to_le_bytes());
    b.extend_from_slice(&0x55aa7711u32.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&(count as u16).to_le_bytes());
    for peer in 0..count {
        b.extend_from_slice(&(peer as u16).to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    b
}
fn smoke_ath10k_pfc_native_queue_bitmap_push_budget_and_air_owner() -> TestResult {
    (|| {
        let mut owner = mapped();
        // Enabled PUSH_PULL, global threshold0; actual peer17/TID3 limit1.
        owner
            .observe(&[0x30, 0, 5, 0, 1, 0, 0, 0, 17, 0x30, 7, 0, 17, 0x30, 1, 0])
            .map_err(|_| "packed native MODE indication")?;
        if owner.queues[0].push != 1 {
            return Err("repeated MODE record did not preserve last-record-wins native semantics");
        }
        // Earlier valid9 cannot replace1 before later malformed TID8 is
        // rejected from the complete native message.
        if owner.observe(&[0x30, 0, 5, 0, 1, 0, 0, 0, 17, 0x30, 9, 0, 17, 0x80, 1, 0]).is_ok()
            || owner.queues[0].push != 1 {
            return Err("malformed later MODE record partially changed earlier push authority");
        }
        let key = owner
            .key(0, AP, 3)
            .map_err(|_| "exact native MAP binding")?;
        owner
            .enqueue(key, 41, 8192, vec![0x41])
            .map_err(|_| "first host original")?;
        owner
            .enqueue(key, 42, 128, vec![0x42])
            .map_err(|_| "second host original")?;
        let state = owner.state().map_err(|_| "actual qstate snapshot")?;
        // count[3][17] = (8320>>7)>>3 |EXP1 =8|0x40. map has17 bits/word.
        let map_at = 4224 + (3 * 17) * 4;
        if state.len() != 4772
            || state[3 * 528 + 17] != 0x48
            || state[map_at..map_at + 4] != (1u32 << 17).to_le_bytes()
            || state[4768..] != 1u32.to_le_bytes()
            || owner.validate_receipts(&[41]).is_ok()
        {
            return Err("qstate count/map/sequence or unpublished ID air authority");
        }
        let work = owner
            .next(AP, &ids(), 0)
            .map_err(|_| "push work")?
            .ok_or("missing queue push")?;
        if !matches!(
            &work,
            Work::Frame {
                id: 41,
                fetched: None,
                ..
            }
        ) {
            return Err("per-TID push selected a different original");
        }
        owner
            .published(work)
            .map_err(|_| "native publication owner")?;
        if owner.pending() != 1
            || owner
                .next(AP, &ids(), 1)
                .map_err(|_| "push budget read")?
                .is_some()
            || owner.validate_receipts(&[41]).is_err()
            || owner.validate_receipts(&[42]).is_ok()
        {
            return Err("push threshold or queued/native ownership confused");
        }
        owner
            .observe(&[0x17, 0, 1, 0, 0, 0, 0, 0])
            .map_err(|_| "actual FETCH_CONFIRM0")?;
        if owner.flights.len() != 1 || owner.pending() != 1 {
            return Err("FETCH_CONFIRM granted an air completion");
        }
        owner.complete(&[41]);
        if !matches!(
            owner.next(AP, &ids(), 0),
            Ok(Some(Work::Frame { id: 42, .. }))
        ) {
            return Err("actual air terminal did not reopen the genuine per-TID push budget");
        }
        let mut foreign = ids();
        foreign[0] = 1 << 18;
        if owner.next(AP, &foreign, 0).is_ok()
            || owner.key(1, AP, 3).is_ok()
            || owner.key(0, AP, 8).is_ok()
        {
            return Err("foreign parent/map/TID became a host queue alias");
        }
        owner.enqueue(key, 43, 256, vec![0x43]).map_err(|_| "second repeated-record original")?;
        let mut repeated = fetch(0, 2);
        for at in [12, 20] {
            repeated[at..at + 2].copy_from_slice(&[17, 0x30]);
            // Positive bytes admits one whole frame per independent record.
            repeated[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        }
        owner.observe(&repeated).map_err(|_| "actual repeated FETCH record budgets")?;
        let first = owner.next(AP, &ids(), 0).map_err(|_| "first repeated-record work")?.ok_or("missing first record")?;
        let stale = owner.next(AP, &ids(), 0).map_err(|_| "repeat same owned frame poll")?.ok_or("missing owned frame phase")?;
        if !matches!(&first, Work::Frame { id: 42, .. }) { return Err("first repeated record selected wrong native original"); }
        owner.published(first).map_err(|_| "actual first record handoff")?;
        if owner.published(stale).is_ok() || owner.flights.len() != 1 {
            return Err("repeated owned poll duplicated native ID or its byte accounting");
        }
        let second = owner.next(AP, &ids(), 1).map_err(|_| "second repeated-record work")?.ok_or("missing second record")?;
        if !matches!(&second, Work::Frame { id: 43, .. }) { return Err("second repeated record reused old native ID"); }
        owner.published(second).map_err(|_| "actual second record handoff")?;
        let response = owner.next(AP, &ids(), 2).map_err(|_| "complete repeated-record response")?.ok_or("missing response")?;
        let b = response.bytes();
        if b[6..8] != [2, 0] || b[14..16] != [1, 0] || b[22..24] != [1, 0]
            || b[16..20] != 128u32.to_le_bytes() || b[24..28] != 256u32.to_le_bytes()
            || owner.pending() != 0 || owner.flights.len() != 2 {
            return Err("repeated record budgets lost whole-frame actual counts or exact native ID ownership");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/pfc",
    smoke_ath10k_pfc_native_queue_bitmap_push_budget_and_air_owner
);

fn smoke_ath10k_pfc_full_request_validation_and_29_record_native_boundary() -> TestResult {
    (|| {
        let mut owner = mapped();
        owner.observe(&[0x30, 0, 1, 0, 1, 0, 0, 0]).map_err(|_| "pull mode")?;
        let key = owner.key(0, AP, 0).map_err(|_| "queue owner")?;
        owner.enqueue(key, 9, 300, vec![1]).map_err(|_| "retained original")?;
        let too_large = fetch(1, 30);
        if owner.observe(&too_large).is_ok() || owner.fetch_serial != 0
            || owner.pending() != 1 || !owner.flights.is_empty() {
            return Err("30-record fetch changed ownership before its impossible response was rejected");
        }
        let mut bad_suffix = fetch(1, 29);
        // Final record TID8 is not part of the actual eight-TID qstate.
        bad_suffix[12 + 28 * 8 + 1] |= 0x80;
        if owner.observe(&bad_suffix).is_ok() || owner.fetch_serial != 0
            || owner.pending() != 1 || !owner.fetches.is_empty() {
            return Err("malformed final record partially admitted the valid request prefix");
        }
        let mut duplicate = fetch(1, 2);
        let first = [duplicate[12], duplicate[13]];
        duplicate[20..22].copy_from_slice(&first);
        duplicate.pop(); // Actual incomplete record; repeated keys are legal.
        if owner.observe(&duplicate).is_ok() || owner.fetch_serial != 0 {
            return Err("truncated repeated-record message acquired a prefix budget");
        }
        // All29 records are real zero-byte requests. Their complete packed
        // response fits252 including HTC and does not publish the queued ID.
        let mut valid = fetch(1, 29);
        for at in (12..valid.len()).step_by(8) { valid[at + 4..at + 8].fill(0); }
        owner.observe(&valid).map_err(|_| "valid29-record native fetch")?;
        let work = owner.next(AP, &ids(), 0).map_err(|_| "complete zero response")?
            .ok_or("missing actual full response")?;
        if !matches!(&work, Work::Response { body, .. } if body.len() + 8 == 252 && body[6..8] == 29u16.to_le_bytes())
            || owner.pending() != 1 || !owner.flights.is_empty() {
            return Err("29-record response truncated records or invented native TX");
        }
        let original = work.bytes().to_vec();
        let stale = owner.next(AP, &ids(), 0).map_err(|_| "same owned phase poll")?.ok_or("missing owned phase")?;
        owner.published(work).map_err(|_| "native response publication")?;
        // Linux treats a new native event as new even with identical opaque
        // headers. Only its private phase, not the echoed scalar, is unique.
        owner.observe(&valid).map_err(|_| "new actual event with identical headers")?;
        let fresh = owner.next(AP, &ids(), 0).map_err(|_| "fresh owned response")?.ok_or("missing fresh response")?;
        if !matches!(&fresh, Work::Response { operation: 2, .. }) || fresh.bytes() != original
            || owner.pending() != 1 || !owner.flights.is_empty() {
            return Err("opaque header equality replaced native-event phase ownership");
        }
        if owner.published(stale).is_ok() || owner.fetches.len() != 1 {
            return Err("old owned phase republished or consumed the new native event");
        }
        owner.published(fresh).map_err(|_| "second actual response owner")?;
        for sequence in [0, u16::MAX, 0] {
            let request = fetch(sequence, 0);
            owner.observe(&request).map_err(|_| "lower/wrapped opaque echo refused")?;
            let work = owner.next(AP, &ids(), 0).map_err(|_| "new opaque-event phase")?.ok_or("missing opaque-event response")?;
            if work.bytes()[4..6] != sequence.to_le_bytes() || owner.pending() != 1 {
                return Err("opaque sequence acquired queue/air authority");
            }
            owner.published(work).map_err(|_| "actual opaque-event response")?;
        }
        if owner.observe(&[0x17, 0, 1, 0, 9, 0, 0, 0]).is_ok()
            || owner.validate_receipts(&[9]).is_ok() {
            return Err("response-ID was treated as a native MSDU completion");
        }
        owner.serial = u32::MAX;
        if owner.state().is_ok() { return Err("qstate commit serial wrapped"); }
        owner.fetch_serial = u64::MAX;
        if owner.observe(&fetch(1, 0)).is_ok() || !owner.fetches.is_empty() {
            return Err("private native-event phase serial wrapped");
        }
        Ok(())
    })().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/pfc",
    smoke_ath10k_pfc_full_request_validation_and_29_record_native_boundary
);
