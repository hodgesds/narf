//! Native retained AR9285 sender BA: actual action/DMA/tail receipts. Model
//! records are synthetic test-only inputs, never physical RF measurements.
use super::*;
use crate::ath9k::{
    ht,
    packet::tests::Model,
    station::tests::{self as station, AP, PMK, SSID},
};
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::Ordering;
use narf_kernel_test::{kernel_test_in, TestResult};
use zeroize::Zeroizing;
pub(in crate::ath9k) fn qualify(model: &Arc<Model>, window: u8) -> Cap<FirmwareBlob, Read> {
    let base = model.ht.borrow().clone().unwrap();
    let r = request(&base);
    let mut b = vec![0; 96];
    b[..8].copy_from_slice(&[b'N', b'8', b'5', b'T', 1, 0, 96, 0]);
    b[8..12].copy_from_slice(&96u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..58].copy_from_slice(&[1, 20, 1, 2]);
    b[58..60].copy_from_slice(&12i16.to_le_bytes());
    b[60] = window;
    b[61] = 3;
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
    let cap = Cap::bootstrap();
    let g = Source::Verified {
        bytes: b,
        signer: Some([0x85; 32]),
        cap,
    }
    .load(base)
    .unwrap();
    *model.tx_ba.borrow_mut() = Some(g);
    cap
}
fn associate(f: &mut station::Fixture, protected: bool) {
    station::complete(
        f.radio
            .associate(AP, SSID, protected.then(|| Zeroizing::new(PMK)), &[]),
    )
    .unwrap();
}
fn settle(f: &mut station::Fixture) {
    for _ in 0..16 {
        f.radio.poll().unwrap();
    }
}
fn fixture(protected: bool, mcs: u8) -> station::Fixture {
    let mut f = station::fixture_ht(protected, 1 << mcs).unwrap();
    qualify(&f.model, 64);
    associate(&mut f, protected);
    settle(&mut f);
    assert!(f.radio.can_aggregate());
    f
}
fn ethernet(f: &station::Fixture, n: u8, length: usize) -> Vec<u8> {
    let mut p = vec![n; length];
    p[..6].copy_from_slice(&AP);
    p[6..12].copy_from_slice(&f.plan.station);
    p[12..14].copy_from_slice(&[8, 0]);
    p
}
fn data_trace(f: &station::Fixture) -> Vec<Vec<u8>> {
    f.model
        .transmitted
        .borrow()
        .iter()
        .filter(|f| f.first() == Some(&0x88))
        .cloned()
        .collect()
}
fn smoke_ar9285_tx_ba_distinct_signed_contract_and_missing_source_keeps_single_mpdu() -> TestResult
{
    let _policy = ht::tests::Policy::install();
    let mut f = station::fixture_ht(true, 255).unwrap();
    let base = f.model.ht.borrow().clone().unwrap();
    let r = request(&base);
    if r.identity == base.ba_identity().0
        || r.identity == crate::ath9k::rx_ba::request(&base).identity
        || !r.filename.starts_with("ath9k/ar9285-txba-v1-")
    {
        return TestResult::Fail("sender qualification aliased another profile");
    }
    let mut b = vec![0; 96];
    b[..8].copy_from_slice(&[b'N', b'8', b'5', b'T', 1, 0, 96, 0]);
    b[8..12].copy_from_slice(&96u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..58].copy_from_slice(&[1, 20, 1, 2]);
    b[58..60].copy_from_slice(&12i16.to_le_bytes());
    b[60] = 64;
    b[61] = 3;
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
    for at in [0, 4, 6, 8, 12, 14, 16, 48, 54, 55, 56, 57, 60, 61, 64, 95] {
        let mut bad = b.clone();
        bad[at] ^= 1;
        if at == 60 {
            bad[at] = 3;
        }
        if Grant::decode(&bad, Some([1; 32]), Cap::bootstrap(), base.clone()).is_ok() {
            return TestResult::Fail("foreign sender contract accepted");
        }
    }
    if Grant::decode(&b, None, Cap::bootstrap(), base).is_ok() {
        return TestResult::Fail("unsigned sender record");
    }
    associate(&mut f, true);
    settle(&mut f);
    let packet = ethernet(&f, 1, 1514);
    f.radio.send(&packet).unwrap();
    settle(&mut f);
    if !f.peer.lock().tx_ba_requests.is_empty()
        || f.model.last_pair.get().is_some()
        || f.model.registers.borrow().get(&0x803c) != Some(&0x17)
    {
        return TestResult::Fail("missing sender source enabled BA or changed RX filters");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_distinct_signed_contract_and_missing_source_keeps_single_mpdu
);
fn smoke_ar9285_tx_ba_real_request_ack_current_ssn_and_isolated_data_remain_unaggregated(
) -> TestResult {
    let _policy = ht::tests::Policy::install();
    for protected in [false, true] {
        let mut f = station::fixture_ht(protected, 255).unwrap();
        qualify(&f.model, 64);
        f.peer.lock().hold_tx_request = true;
        associate(&mut f, protected);
        let request = f.peer.lock().tx_ba_requests.last().unwrap().clone();
        if request[26] == 0
            || request[27..31] != [2, 16, 0, 0]
            || f.radio.ready()
            || f.radio.can_aggregate()
        {
            return TestResult::Fail("air proposal activated before native request ACK");
        }
        for _ in 0..4 {
            f.radio.poll().unwrap();
        }
        if f.radio.can_aggregate() {
            return TestResult::Fail("queued response bypassed held native ACK");
        }
        f.model.complete(true).unwrap();
        f.model.registers.borrow_mut().insert(0x840, 1);
        f.model.registers.borrow_mut().insert(0xa00, 1);
        f.radio.poll().unwrap();
        if f.radio.ready() {
            return TestResult::Fail("request TxDone bypassed live native queue");
        }
        f.model.registers.borrow_mut().insert(0x840, 0);
        f.model.registers.borrow_mut().insert(0xa00, 0);
        settle(&mut f);
        let packet = ethernet(&f, 2, 128);
        f.radio.send(&packet).unwrap();
        settle(&mut f);
        let trace = data_trace(&f);
        let first = &trace[0];
        if first[22..24] != request[31..33]
            || f.model.last_pair.get().is_some()
            || f.peer.lock().uplink.last() != Some(&packet)
        {
            return TestResult::Fail("ADDBA SSN was invented or isolated MPDU aggregated");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_real_request_ack_current_ssn_and_isolated_data_remain_unaggregated
);
fn smoke_ar9285_tx_ba_all_mcs_two_native_maps_duration_pad_fcs_and_tail_only_release() -> TestResult
{
    let _policy = ht::tests::Policy::install();
    for protected in [false, true] {
        for mcs in 0..8 {
            let mut f = fixture(protected, mcs);
            f.peer.lock().hold_data = true;
            let a = ethernet(&f, 3, 14);
            let b = ethernet(&f, 4, 1514);
            f.radio.send_pair(&a, &b).unwrap();
            let (head, tail) = f.model.last_pair.get().unwrap();
            let originals = data_trace(&f);
            let first = &originals[0];
            let last = &originals[1];
            let ndbps = [26u32, 52, 78, 104, 156, 208, 234, 260][usize::from(mcs)];
            let air0 = first.len() + 4;
            let air1 = last.len() + 4;
            let delimiters = 256usize.saturating_sub(air0).div_ceil(4);
            let air = (air0 + 4).next_multiple_of(4) + delimiters * 4 + air1 + 4;
            let duration = 36 + 4 * (air as u32 * 8 + 22).div_ceil(ndbps);
            if f.model.word(head) != Ok(tail)
                || f.model.word(tail) != Ok(0)
                || f.model.word(head + 12).unwrap() & 0x6000_0000 != 0x6000_0000
                || f.model.word(tail + 12).unwrap() & 0x6000_0000 != 0x4000_0000
                || f.model.word(head + 32) != Ok(air as u32 | ((delimiters as u32) << 18))
                || f.model.word(head + 24) != Ok(duration)
                || f.model.word(head + 20) != Ok(u32::from(0x80 | mcs))
                || [16, 20, 24, 28, 36]
                    .into_iter()
                    .any(|o| f.model.word(tail + o) != Ok(0))
                || f.peer.lock().uplink != vec![a.clone(), b.clone()]
            {
                return TestResult::Fail(
                    "literal two-map native aggregate/duration or independently opened originals",
                );
            }
            let dma = f.model.dma_transmitted.borrow();
            let copies = &dma[dma.len() - 2..];
            for (i, original) in [first, last].into_iter().enumerate() {
                let d = if i == 0 { head } else { tail };
                if copies[i][..26] != original[..26]
                    || copies[i][26..28] != [0, 0]
                    || copies[i][28..] != original[26..]
                    || f.model.word(d + 8).unwrap() & 0xfff != (original.len() + 4) as u32
                    || f.model.word(d + 12).unwrap() & 0xfff != (original.len() + 2) as u32
                {
                    return TestResult::Fail("per-MPDU FCS/DMA padding altered original CCMP");
                }
            }
            drop(dma);
            if protected {
                let (pn0, _) =
                    narf_wireless::ccmp::decode_ccmp_header(first[26..34].try_into().unwrap())
                        .unwrap();
                let (pn1, _) =
                    narf_wireless::ccmp::decode_ccmp_header(last[26..34].try_into().unwrap())
                        .unwrap();
                if pn1 != pn0 + 1 {
                    return TestResult::Fail("two original packet PNs were fabricated/shared");
                }
            }
            f.model.put(head + 92, 1).unwrap();
            f.radio.poll().unwrap();
            if f.radio.ready() || f.model.tx.get() != Some(head) {
                return TestResult::Fail("FIRST TxDone released a still-owned tail");
            }
            f.model.complete(true).unwrap();
            settle(&mut f);
            if !f.radio.ready() {
                return TestResult::Fail("actual tail BA/idle did not release batch");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_all_mcs_two_native_maps_duration_pad_fcs_and_tail_only_release
);
fn smoke_ar9285_tx_ba_partial_bitmap_and_wrong_tid_retry_originals_without_new_pn() -> TestResult {
    let _policy = ht::tests::Policy::install();
    for protected in [false, true] {
        for wrong_tid in [false, true] {
            let mut f = fixture(protected, 7);
            if wrong_tid {
                f.model.ba_tid.set(15);
            } else {
                f.model.pair_received.set(2);
            }
            let a = ethernet(&f, 5, 256);
            let b = ethernet(&f, 6, 512);
            f.radio.send_pair(&a, &b).unwrap();
            settle(&mut f);
            let trace = data_trace(&f);
            let retries = if wrong_tid { 2 } else { 1 };
            if trace.len() != 2 + retries || f.peer.lock().uplink != vec![a, b] || !f.radio.ready()
            {
                return TestResult::Fail("native partial/wrong-TID receipt delivered a false prefix or failed bounded retry");
            }
            for i in 0..retries {
                let mut expected = trace[i].clone();
                expected[1] |= 8;
                if trace[2 + i] != expected {
                    return TestResult::Fail("software retry changed original PN/SC/ciphertext");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_partial_bitmap_and_wrong_tid_retry_originals_without_new_pn
);
fn smoke_ar9285_tx_ba_exhausted_retry_uses_real_bar_tx_ba_fields_before_hole_advance() -> TestResult
{
    let _policy = ht::tests::Policy::install();
    for failure in 0..4 {
        let mut f = fixture(true, 7);
        f.model.pair_received.set(2);
        f.model.data_ack.set(false);
        f.model.retry_receive.set(false);
        f.peer.lock().hold_bar = true;
        let a = ethernet(&f, 7, 256);
        let b = ethernet(&f, 8, 512);
        f.radio.send_pair(&a, &b).unwrap();
        for _ in 0..16 {
            f.radio.poll().unwrap();
            if !f.peer.lock().bars.is_empty() {
                break;
            }
        }
        let bar = f.peer.lock().bars.last().unwrap().clone();
        let d = f.model.tx.get().unwrap();
        if f.radio.ready()
            || bar.len() != 20
            || f.model.word(d + 8).unwrap() & 0xfff != 24
            || f.model.word(d + 12).unwrap() & 0xfff != 20
            || data_trace(&f).len() != 5
            || f.peer.lock().uplink != vec![b]
        {
            return TestResult::Fail(
                "BAR/retry lost actual original ownership or fabricated missing DATA",
            );
        }
        match failure {
            1 => f.model.ba_flag.set(false),
            2 => f.model.ba_tid.set(1),
            3 => f.model.ba_ssn.set(Some(4090)),
            _ => {}
        }
        f.model.complete(true).unwrap();
        if failure == 0 {
            settle(&mut f);
            if !f.radio.ready() {
                return TestResult::Fail(
                    "actual BAR TX BAflag/TID/SSN receipt did not advance hole",
                );
            }
        } else if f.radio.poll().is_ok() || f.radio.peer().is_some() || f.model.master.get() {
            return TestResult::Fail("missing/wrong native BAR BA proof reopened sender window");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_exhausted_retry_uses_real_bar_tx_ba_fields_before_hole_advance
);
fn smoke_ar9285_tx_ba_held_pair_rekey_drops_old_retries_and_uses_current_bar_epoch() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = fixture(true, 7);
    f.model.pair_received.set(2);
    f.peer.lock().hold_data = true;
    f.peer.lock().hold_group = true;
    let a = ethernet(&f, 9, 256);
    let b = ethernet(&f, 10, 512);
    f.radio.send_pair(&a, &b).unwrap();
    let (head, tail) = f.model.last_pair.get().unwrap();
    let before = data_trace(&f).len();
    let group = f.peer.lock().group_rekey();
    f.model.inject(&group, 0).unwrap();
    assert!(f.radio.poll().unwrap().is_empty());
    if f.radio.receive_open()
        || f.radio.peer().is_none()
        || f.model.tx.get() != Some(head)
        || f.model.word(tail + 92).unwrap() & 1 != 0
    {
        return TestResult::Fail(
            "rekey failed to close port while preserving native pair DMA/carrier",
        );
    }
    f.model.complete(true).unwrap();
    f.radio.poll().unwrap();
    f.radio.poll().unwrap();
    if f.peer.lock().group_replies != 1 || f.radio.receive_open() {
        return TestResult::Fail("old pair receipt skipped held actual Group2");
    }
    f.peer.lock().hold_data = false;
    f.model.complete(true).unwrap();
    settle(&mut f);
    if !f.radio.ready() || f.peer.lock().bars.len() != 1 || data_trace(&f).len() != before {
        return TestResult::Fail(
            "late old pair created successor-epoch retries or skipped genuine BAR",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_held_pair_rekey_drops_old_retries_and_uses_current_bar_epoch
);
fn smoke_ar9285_tx_ba_source_descriptor_cancel_and_native_mute_failures_are_terminal() -> TestResult
{
    let _policy = ht::tests::Policy::install();
    for case in 0..7 {
        let mut f = fixture(true, 7);
        f.peer.lock().hold_data = true;
        let mappings = f
            .model
            .regions
            .borrow()
            .iter()
            .map(|r| (r.bus, r.cpu, r.len))
            .collect::<Vec<_>>();
        let a = ethernet(&f, 11, 256);
        let b = ethernet(&f, 12, 512);
        f.radio.send_pair(&a, &b).unwrap();
        let (head, tail) = f.model.last_pair.get().unwrap();
        match case {
            0 => {
                f.model.tx_ba.borrow().as_ref().unwrap().cap.revoke();
            }
            1 => {
                f.model
                    .put(head, f.model.word(head).unwrap() ^ 128)
                    .unwrap();
            }
            2 => {
                let address = f.model.word(tail + 4).unwrap();
                f.model.put(address + 28, 1).unwrap();
            }
            3 => f.model.ba_flag.set(false),
            4 => {
                f.model.put(tail + 20, 0x87).unwrap();
            }
            5 => {
                f.model.allowed.set(false);
            }
            _ => {
                f.radio.stop().unwrap();
            }
        }
        if !matches!(case, 0 | 5) {
            f.model.complete(true).unwrap();
        }
        if f.radio.poll().is_ok()
            || f.radio.peer().is_some()
            || f.model.master.get()
            || f.model
                .regions
                .borrow()
                .iter()
                .map(|r| (r.bus, r.cpu, r.len))
                .collect::<Vec<_>>()
                != mappings
        {
            return TestResult::Fail(
                "ambiguous/modified/revoked/cancelled pair reused native ownership",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_source_descriptor_cancel_and_native_mute_failures_are_terminal
);
fn smoke_ar9285_tx_ba_actual_decline_small_window_and_tu_teardown_have_native_receipts(
) -> TestResult {
    let _policy = ht::tests::Policy::install();
    for case in 0..3 {
        let mut f = station::fixture_ht(false, 255).unwrap();
        qualify(&f.model, 64);
        match case {
            0 => f.peer.lock().tx_ba_status = 37,
            1 => f.peer.lock().tx_ba_window = 2,
            _ => f.peer.lock().tx_ba_timeout = 1,
        }
        associate(&mut f, false);
        settle(&mut f);
        if case == 2 {
            f.env.now.fetch_add(2, Ordering::AcqRel);
            settle(&mut f);
        }
        let a = ethernet(&f, 13, 256);
        f.radio.send(&a).unwrap();
        settle(&mut f);
        if !f.radio.ready()
            || f.radio.can_aggregate()
            || f.model.last_pair.get().is_some()
            || (case != 0 && f.peer.lock().sender_delbas.len() != 1)
        {
            return TestResult::Fail(
                "declined/small/TU sender agreement lacked actual DELBA/single continuation",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_actual_decline_small_window_and_tu_teardown_have_native_receipts
);
fn smoke_ar9285_tx_ba_native_wrap_and_complete_current_response_are_required() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = station::fixture_ht(false, 255).unwrap();
    station::open_qos_start(&mut f, 4095);
    qualify(&f.model, 64);
    f.peer.lock().tx_ba_respond = false;
    associate(&mut f, false);
    for _ in 0..4 {
        f.radio.poll().unwrap();
    }
    let request = f.peer.lock().tx_ba_requests[0].clone();
    if request[31..33] != [0xf0, 0xff] {
        return TestResult::Fail("real Open producer SSN was reset before ADDBA");
    }
    let mut valid = vec![0xd0, 0, 0, 0];
    valid.extend_from_slice(&f.plan.station);
    valid.extend_from_slice(&AP);
    valid.extend_from_slice(&AP);
    valid.extend_from_slice(&[0, 0, 3, 1, request[26], 0, 0, 2, 16, 0, 0]);
    for case in 0..9 {
        let mut bad = valid.clone();
        match case {
            0 => bad[4] ^= 2,
            1 => bad[10] ^= 2,
            2 => bad[16] ^= 2,
            3 => bad[26] ^= 1,
            4 => bad[29] |= 4,
            5 => bad[29] |= 1,
            6 => bad[29] &= !2,
            7 => {
                bad.pop();
            }
            _ => {
                bad[30] = 32;
            }
        }
        f.model.inject(&bad, 0).unwrap();
        f.radio.poll().unwrap();
        if f.radio.can_aggregate() {
            return TestResult::Fail(
                "foreign/partial/wrong-dialog/TID/window response activated sender",
            );
        }
    }
    // Configure the fixture AP's actual explicit-SSN recipient by replaying
    // the genuine already-captured request, then deliver only its real response.
    f.peer.lock().tx_ba_respond = true;
    let response = f.peer.lock().react(&request).unwrap().0.remove(0);
    f.model.inject(&response, 0).unwrap();
    settle(&mut f);
    let a = ethernet(&f, 14, 256);
    let b = ethernet(&f, 15, 512);
    f.radio.send_pair(&a, &b).unwrap();
    settle(&mut f);
    let trace = data_trace(&f);
    if trace[0][22..24] != [0xf0, 0xff]
        || trace[1][22..24] != [0, 0]
        || f.peer.lock().uplink != vec![a, b]
        || !f.radio.ready()
    {
        return TestResult::Fail("native two-original wrap/bitmap/explicit receiver head");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/tx-ba",
    smoke_ar9285_tx_ba_native_wrap_and_complete_current_response_are_required
);
