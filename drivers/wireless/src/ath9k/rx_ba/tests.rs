//! Actual retained non-EDMA descriptors, original crypto and air BA actions.
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
const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
const AGGR: u32 = 1 << 17;
const FIRST: u32 = 1 << 29;
const MORE: u32 = 1 << 16;
pub(in crate::ath9k) fn qualify(model: &Arc<Model>, window: u8) -> Cap<FirmwareBlob, Read> {
    let base = model.ht.borrow().clone().unwrap();
    let r = request(&base);
    let mut b = vec![0; 96];
    b[..8].copy_from_slice(&[b'N', b'8', b'5', b'B', 1, 0, 96, 0]);
    b[8..12].copy_from_slice(&96u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..58].copy_from_slice(&[1, 20, 1, 1]);
    b[58..60].copy_from_slice(&12i16.to_le_bytes());
    b[60] = window;
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
    let cap = Cap::bootstrap();
    let g = Source::Verified {
        bytes: b,
        signer: Some([0x85; 32]),
        cap,
    }
    .load(base)
    .unwrap();
    *model.ba.borrow_mut() = Some(g);
    cap
}
fn fixture(protected: bool, window: u8) -> station::Fixture {
    let mut f = station::fixture_ht(protected, 255).unwrap();
    qualify(&f.model, window);
    station::complete(
        f.radio
            .associate(AP, SSID, protected.then(|| Zeroizing::new(PMK)), &[]),
    )
    .unwrap();
    f
}
pub(in crate::ath9k) fn addba(
    tid: u8,
    ssn: u16,
    window: u16,
    timeout: u16,
    amsdu: bool,
) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0, 0, 3, 0, 7 + tid]);
    f.extend_from_slice(
        &((window << 6) | (u16::from(tid) << 2) | 2 | u16::from(amsdu)).to_le_bytes(),
    );
    f.extend_from_slice(&timeout.to_le_bytes());
    f.extend_from_slice(&(ssn << 4).to_le_bytes());
    f
}
fn begin(f: &mut station::Fixture, tid: u8, ssn: u16, window: u16, timeout: u16, amsdu: bool) {
    f.model
        .inject(&addba(tid, ssn, window, timeout, amsdu), 0)
        .unwrap();
    f.radio.poll().unwrap();
    f.radio.poll().unwrap();
}
fn bar(tid: u8, ssn: u16) -> Vec<u8> {
    let mut f = vec![0x84, 0, 0, 0];
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&(4u16 | (u16::from(tid) << 12)).to_le_bytes());
    f.extend_from_slice(&(ssn << 4).to_le_bytes());
    f
}
fn peer_delba(tid: u8) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0, 0, 3, 2]);
    f.extend_from_slice(&(0x800u16 | (u16::from(tid) << 12)).to_le_bytes());
    f.extend_from_slice(&37u16.to_le_bytes());
    f
}
fn packet(f: &station::Fixture, n: u8) -> Vec<u8> {
    narf_wifi_fixtures::udp_ipv4(
        OWN,
        AP,
        f.plan.server_ip,
        f.plan.lease_ip,
        4501,
        4502,
        &[n; 8],
    )
}
fn raw(
    f: &station::Fixture,
    seq: u16,
    tid: u8,
    pn: u64,
    ack: u8,
    aggregate: Option<&[u8]>,
) -> (Vec<u8>, Vec<u8>) {
    let ethernet = packet(f, pn as u8);
    let protected = f.peer.lock().ap.protected();
    let mut h = vec![0x88, if protected { 0x42 } else { 2 }, 0, 0];
    h.extend_from_slice(&OWN);
    h.extend_from_slice(&AP);
    h.extend_from_slice(&AP);
    h.extend_from_slice(&(seq << 4).to_le_bytes());
    h.extend_from_slice(&[tid | ack | if aggregate.is_some() { 0x80 } else { 0 }, 0]);
    let mut body = if let Some(a) = aggregate {
        a.to_vec()
    } else {
        let mut b = vec![0xaa, 0xaa, 3, 0, 0, 0];
        b.extend_from_slice(&ethernet[12..]);
        b
    };
    if protected {
        let key: [u8; 16] = f
            .peer
            .lock()
            .ptk
            .as_ref()
            .unwrap()
            .tk
            .as_slice()
            .try_into()
            .unwrap();
        body = narf_wireless::ccmp::protect(&station::Ccm, &h, &key, pn, 0, tid, false, &mut body)
            .unwrap();
    }
    h.extend_from_slice(&body);
    (h, ethernet)
}
fn inject(f: &station::Fixture, wire: &[u8], flags: u32) {
    f.model.inject(wire, 0).unwrap();
    let d = f.model.last_rx.get().unwrap();
    f.model.put(d + 48, 3 | flags).unwrap();
}
fn tick(f: &station::Fixture, ms: u64) {
    f.env.now.fetch_add(ms, Ordering::AcqRel);
    f.model.now.set(f.model.now.get() + ms * 1000);
}
fn smoke_ar9285_rx_ba_exact_signed_board_contract_and_native_filter_readback() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = station::fixture_ht(true, 255).unwrap();
    let base = f.model.ht.borrow().clone().unwrap();
    let r = request(&base);
    if r.identity == base.ba_identity().0 || !r.filename.starts_with("ath9k/ar9285-rxba-v1-") {
        return TestResult::Fail("RX BA qualification aliased HT source");
    }
    let cap = qualify(&f.model, 4);
    station::complete(f.radio.associate(AP, SSID, Some(Zeroizing::new(PMK)), &[])).unwrap();
    if f.model.registers.borrow().get(&0x803c) != Some(&0x17) {
        return TestResult::Fail("optional asset itself changed live RX filter");
    }
    begin(&mut f, 3, 100, 64, 0, true);
    if f.model.registers.borrow().get(&0x803c) != Some(&0x417)
        || f.peer.lock().ba_accepts.last().unwrap()[29..31]
            != ((4u16 << 6) | (3 << 2) | 3).to_le_bytes()
    {
        return TestResult::Fail("native BAR filter/readback or measured window narrowing");
    }
    cap.revoke();
    if f.radio.poll().is_ok() || f.radio.peer().is_some() {
        return TestResult::Fail("revoked RX BA source left data/automatic-response owner open");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_exact_signed_board_contract_and_native_filter_readback
);
fn smoke_ar9285_rx_ba_native_air_ssn_wrap_duplicate_add_and_original_pn_order() -> TestResult {
    let _policy = ht::tests::Policy::install();
    for protected in [false, true] {
        let mut f = fixture(protected, 64);
        begin(&mut f, 3, 4095, 64, 0, true);
        let (later, later_eth) = raw(&f, 0, 3, 2, 0x60, None);
        let (first, first_eth) = raw(&f, 4095, 3, 1, 0x60, None);
        inject(&f, &later, AGGR | FIRST | MORE);
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("air SSN was replaced by first native sequence");
        }
        inject(&f, &first, AGGR);
        if f.radio.poll().unwrap() != vec![first_eth, later_eth] {
            return TestResult::Fail(
                "native wrap MPDUs were decrypted/PN committed before ordering",
            );
        }
        begin(&mut f, 3, 4095, 64, 0, true);
        let (next, eth) = raw(&f, 1, 3, 3, 0x60, None);
        inject(&f, &next, AGGR | FIRST);
        if f.radio.poll().unwrap() != vec![eth] {
            return TestResult::Fail("duplicate native acknowledged ADDBA reset live SSN");
        }
        inject(&f, &later, AGGR | FIRST);
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("duplicate old sequence/replay escaped native BA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_native_air_ssn_wrap_duplicate_add_and_original_pn_order
);
fn smoke_ar9285_rx_ba_native_bar_future_window_holes_and_sixteen_tid_owners() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = fixture(true, 4);
    for tid in 0..16 {
        begin(&mut f, tid, 10, 4, 0, false);
        let (wire, expected) = raw(&f, 14, tid, 5, 0x60, None);
        inject(&f, &wire, AGGR | FIRST);
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("future window did not retain a bounded hole");
        }
        let mut foreign = bar(tid, 14);
        foreign[10] ^= 2;
        f.model.inject(&foreign, 0).unwrap();
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("foreign BAR advanced native reorder");
        }
        f.model.inject(&bar(tid, 14), 0).unwrap();
        if f.radio.poll().unwrap() != vec![expected] {
            return TestResult::Fail(
                "actual compressed BAR/current native TID did not release ordered original",
            );
        }
        let (old, _) = raw(&f, 11, tid, 6, 0x60, None);
        inject(&f, &old, AGGR | FIRST);
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("late old sequence advanced a current PN");
        }
        let (next, expected) = raw(&f, 15, tid, 6, 0x60, None);
        inject(&f, &next, AGGR | FIRST);
        if f.radio.poll().unwrap() != vec![expected] {
            return TestResult::Fail(
                "TID PN/window shared another session or old drop committed PN",
            );
        }
    }
    let (hole, expected) = raw(&f, 17, 0, 7, 0x60, None);
    inject(&f, &hole, AGGR | FIRST);
    assert!(f.radio.poll().unwrap().is_empty());
    tick(&f, 99);
    if !f.radio.poll().unwrap().is_empty() {
        return TestResult::Fail("hole timeout released early");
    }
    tick(&f, 1);
    if f.radio.poll().unwrap() != vec![expected] {
        return TestResult::Fail("native Idle did not expire bounded reorder hole");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_native_bar_future_window_holes_and_sixteen_tid_owners
);
fn smoke_ar9285_rx_ba_native_ack_idle_admission_delba_and_cancel_retire_originals() -> TestResult {
    let _policy = ht::tests::Policy::install();
    for cancel in [false, true] {
        let mut f = fixture(true, 64);
        f.peer.lock().hold_ba = true;
        f.model.inject(&addba(5, 1, 64, 0, true), 0).unwrap();
        f.radio.poll().unwrap();
        let desc = f.model.tx.get().unwrap();
        if f.model.word(desc + 8).unwrap() & 0xfff != 37
            || f.model.word(desc + 12).unwrap() & 0xfff != 33
            || f.model.word(desc + 20) != Ok(0x1b)
        {
            return TestResult::Fail("accepted BA did not consume actual legacy native descriptor");
        }
        let (wire, expected) = raw(&f, 1, 5, 1, 0x60, None);
        inject(&f, &wire, AGGR | FIRST);
        assert!(f.radio.poll().unwrap().is_empty());
        let retained = f
            .model
            .regions
            .borrow()
            .iter()
            .map(|r| (r.bus, r.cpu, r.len))
            .collect::<Vec<_>>();
        if cancel {
            f.radio.stop().unwrap();
            f.model.complete(true).unwrap();
            if f.radio.poll().is_ok() || f.radio.peer().is_some() {
                return TestResult::Fail("cancelled held BA response authorized late receipt");
            }
        } else {
            f.model.complete(true).unwrap();
            if f.radio.poll().unwrap() != vec![expected.clone()] {
                return TestResult::Fail(
                    "positive native ACK+idle lost bounded staged first burst",
                );
            }
            inject(&f, &wire, AGGR | FIRST);
            if !f.radio.poll().unwrap().is_empty() {
                return TestResult::Fail(
                    "staged native original delivered twice or replayed after ACK",
                );
            }
            let (buffered, _) = raw(&f, 3, 5, 2, 0x60, None);
            inject(&f, &buffered, AGGR | FIRST);
            assert!(f.radio.poll().unwrap().is_empty());
            f.model.inject(&peer_delba(5), 0).unwrap();
            if !f.radio.poll().unwrap().is_empty() {
                return TestResult::Fail("peer DELBA implicitly delivered buffered original");
            }
            tick(&f, 100);
            if !f.radio.poll().unwrap().is_empty() {
                return TestResult::Fail("retired DELBA owner released old timeout data");
            }
        }
        if retained
            != f.model
                .regions
                .borrow()
                .iter()
                .map(|r| (r.bus, r.cpu, r.len))
                .collect::<Vec<_>>()
        {
            return TestResult::Fail("BA ACK/cancel/DELBA replaced retained native DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_native_ack_idle_admission_delba_and_cancel_retire_originals
);
fn smoke_ar9285_rx_ba_native_invalid_phy_ppdu_tid_and_key_reply_never_seed_context() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = fixture(true, 64);
    begin(&mut f, 15, 1, 64, 0, true);
    let (wire, expected) = raw(&f, 1, 15, 1, 0x60, None);
    inject(&f, &wire, AGGR | FIRST | MORE);
    let d = f.model.last_rx.get().unwrap();
    f.model.put(d + 28, 1).unwrap();
    assert!(f.radio.poll().unwrap().is_empty());
    inject(&f, &wire, AGGR);
    assert!(f.radio.poll().unwrap().is_empty());
    f.peer.lock().hold_group = true;
    let group = f.peer.lock().group_rekey();
    f.model.inject(&group, 0).unwrap();
    f.radio.poll().unwrap();
    inject(&f, &wire, AGGR | FIRST | MORE);
    assert!(f.radio.poll().unwrap().is_empty());
    f.model.complete(true).unwrap();
    f.radio.poll().unwrap();
    inject(&f, &wire, AGGR);
    assert!(f.radio.poll().unwrap().is_empty());
    inject(&f, &wire, AGGR | FIRST);
    if f.radio.poll().unwrap() != vec![expected] {
        return TestResult::Fail("closed-port/invalid PHY FIRST seeded native PPDU or advanced PN");
    }
    let (other, _) = raw(&f, 2, 14, 2, 0x60, None);
    inject(&f, &other, AGGR | FIRST | MORE);
    assert!(f.radio.poll().unwrap().is_empty());
    let (next, expected) = raw(&f, 2, 15, 2, 0x60, None);
    inject(&f, &next, AGGR);
    assert!(f.radio.poll().unwrap().is_empty());
    inject(&f, &next, AGGR | FIRST);
    if f.radio.poll().unwrap() != vec![expected] {
        return TestResult::Fail("foreign TID PPDU context authorized orphan LAST");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_native_invalid_phy_ppdu_tid_and_key_reply_never_seed_context
);
fn smoke_ar9285_rx_ba_original_full3839_amsdu_normal_and_block_ack_are_ordered_atomically(
) -> TestResult {
    let _policy = ht::tests::Policy::install();
    for protected in [false, true] {
        for ack in [0, 0x60] {
            let mut f = fixture(protected, 64);
            begin(&mut f, 15, 1, 64, 0, true);
            let (body, expected) = ht::tests::aggregate_body(OWN);
            let (later, _) = raw(&f, 2, 15, 2, ack, Some(&body));
            let (first, _) = raw(&f, 1, 15, 1, ack, Some(&body));
            inject(&f, &later, AGGR | FIRST | MORE);
            assert!(f.radio.poll().unwrap().is_empty());
            inject(&f, &first, AGGR);
            let mut pair = expected.clone();
            pair.extend(expected);
            if f.radio.poll().unwrap() != pair {
                return TestResult::Fail(
                    "original3839 A-MSDU in native AMPDU lost source/header/order/atomic PN",
                );
            }
            let (mut body, expected) = ht::tests::aggregate_body(OWN);
            body[3060..3062].copy_from_slice(&0xffffu16.to_be_bytes());
            let (bad, _) = raw(&f, 3, 15, 3, ack, Some(&body));
            inject(&f, &bad, AGGR | FIRST);
            assert!(f.radio.poll().unwrap().is_empty());
            let (valid_body, _) = ht::tests::aggregate_body(OWN);
            let (valid, _) = raw(&f, 4, 15, 3, ack, Some(&valid_body));
            inject(&f, &valid, AGGR | FIRST);
            if f.radio.poll().unwrap() != expected {
                return TestResult::Fail(
                    "later malformed subframe consumed PN before new ordered sequence",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_original_full3839_amsdu_normal_and_block_ack_are_ordered_atomically
);
fn smoke_ar9285_rx_ba_stbc1_whole3839_coding_context_before_original_ccmp() -> TestResult {
    let _policy = ht::tests::Policy::install();
    for protected in [false, true] {
        for ack in [0, 0x60] {
            let mut f = station::fixture_ht_stbc(protected, true, true).unwrap();
            qualify(&f.model, 64);
            station::complete(f.radio.associate(
                AP,
                SSID,
                protected.then(|| Zeroizing::new(PMK)),
                &[],
            ))
            .unwrap();
            begin(&mut f, 15, 1, 64, 0, true);
            let (body, expected) = ht::tests::aggregate_body(OWN);
            let (second, _) = raw(&f, 2, 15, 2, ack, Some(&body));
            let (first, _) = raw(&f, 1, 15, 1, ack, Some(&body));
            inject(&f, &second, AGGR | FIRST | MORE);
            f.model.put(f.model.last_rx.get().unwrap() + 28, 8).unwrap();
            assert!(f.radio.poll().unwrap().is_empty());
            inject(&f, &first, AGGR);
            f.model.put(f.model.last_rx.get().unwrap() + 28, 8).unwrap();
            let mut pair = expected.clone();
            pair.extend(expected.clone());
            if f.radio.poll().unwrap() != pair {
                return TestResult::Fail("STBC1 whole3839 original aggregate/order/header/PN");
            }
            let (third, _) = raw(&f, 3, 15, 3, ack, Some(&body));
            inject(&f, &third, AGGR | FIRST | MORE);
            f.model.put(f.model.last_rx.get().unwrap() + 28, 8).unwrap();
            if f.radio.poll().unwrap() != expected {
                return TestResult::Fail("source-backed STBC1 FIRST was not delivered");
            }
            let (fourth, _) = raw(&f, 4, 15, 4, ack, Some(&body));
            inject(&f, &fourth, AGGR); // Native coding changes inside the PPDU.
            if !f.radio.poll().unwrap().is_empty() {
                return TestResult::Fail("mixed STBC coding context reached PN");
            }
            inject(&f, &fourth, AGGR); // The rejected member also retired context.
            f.model.put(f.model.last_rx.get().unwrap() + 28, 8).unwrap();
            if !f.radio.poll().unwrap().is_empty() {
                return TestResult::Fail("orphan LAST reused old STBC context");
            }
            inject(&f, &fourth, AGGR | FIRST);
            f.model.put(f.model.last_rx.get().unwrap() + 28, 8).unwrap();
            if f.radio.poll().unwrap() != expected {
                return TestResult::Fail("mixed/orphan coding committed CCMP PN or BA sequence");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_stbc1_whole3839_coding_context_before_original_ccmp
);
fn smoke_ar9285_rx_ba_native_tu_activity_bar_refresh_and_delba_receipt_are_real() -> TestResult {
    let _policy = ht::tests::Policy::install();
    for timeout in [1, 10, u16::MAX] {
        let mut f = fixture(true, 64);
        begin(&mut f, 4, 1, 64, timeout, false);
        f.peer.lock().hold_delba = true;
        let request = f.peer.lock().ba_accepts.last().unwrap().clone();
        if request[31..33] != timeout.to_le_bytes() {
            return TestResult::Fail("native accepted ADDBA did not retain TU field");
        }
        if timeout == u16::MAX {
            let (wire, expected) = raw(&f, 1, 4, 1, 0x60, None);
            inject(&f, &wire, AGGR | FIRST);
            assert_eq!(f.radio.poll().unwrap(), vec![expected]);
            tick(&f, 100);
            f.radio.poll().unwrap();
            if !f.peer.lock().delbas.is_empty() {
                return TestResult::Fail("maximum TU overflowed to short inactivity");
            }
            continue;
        }
        tick(&f, u64::from(timeout));
        f.radio.poll().unwrap();
        if !f.peer.lock().delbas.is_empty() {
            return TestResult::Fail("TU treated as milliseconds or expired early");
        }
        f.model.inject(&bar(4, 1), 0).unwrap();
        f.radio.poll().unwrap();
        tick(&f, u64::from(timeout));
        f.radio.poll().unwrap();
        if !f.peer.lock().delbas.is_empty() {
            return TestResult::Fail("actual BAR failed to refresh inactivity");
        }
        tick(&f, 1);
        f.radio.poll().unwrap();
        let desc = f.model.tx.get().unwrap();
        let delba = f.peer.lock().delbas.last().unwrap().clone();
        if delba[24..30] != [3, 2, 0, 0x40, 39, 0]
            || f.model.word(desc + 8).unwrap() & 0xfff != 34
            || f.model.word(desc + 12).unwrap() & 0xfff != 30
            || f.model.word(desc + 20) != Ok(0x1b)
        {
            return TestResult::Fail("TU expiry lacked actual recipient DELBA legacy DMA");
        }
        f.model.inject(&addba(4, 10, 64, 0, false), 0).unwrap();
        f.radio.poll().unwrap();
        if f.peer.lock().ba_accepts.len() != 1 {
            return TestResult::Fail("held DELBA ticket allowed new BA before native ACK+idle");
        }
        f.model.complete(true).unwrap();
        f.radio.poll().unwrap();
        f.radio.poll().unwrap();
        if f.peer.lock().ba_accepts.len() != 2 {
            return TestResult::Fail(
                "terminal native DELBA ACK+idle did not retire old agreement ticket",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_native_tu_activity_bar_refresh_and_delba_receipt_are_real
);
fn smoke_ar9285_rx_ba_native_failed_response_delba_source_and_mutated_receipts_close() -> TestResult
{
    let _policy = ht::tests::Policy::install();
    for mode in 0..5 {
        let mut f = fixture(true, 64);
        let cap = f.model.ba.borrow().as_ref().unwrap().cap;
        f.peer.lock().hold_ba = true;
        f.model.inject(&addba(7, 1, 64, 0, false), 0).unwrap();
        f.radio.poll().unwrap();
        let d = f.model.tx.get().unwrap();
        let (stage, _) = raw(&f, 1, 7, 1, 0x60, None);
        inject(&f, &stage, AGGR | FIRST);
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail(
                "unacknowledged BA proposal authenticated/published staged data",
            );
        }
        let retained = f
            .model
            .regions
            .borrow()
            .iter()
            .map(|r| (r.bus, r.cpu, r.len))
            .collect::<Vec<_>>();
        match mode {
            0 => f.model.complete(false).unwrap(),
            1 => {
                let addr = f.model.word(d + 4).unwrap();
                let old = f.model.word(addr + 28).unwrap();
                f.model.put(addr + 28, old ^ 0x100).unwrap();
                f.model.complete(true).unwrap();
            }
            2 => cap.revoke(),
            3 => f.model.allowed.set(false),
            _ => {
                f.model.registers.borrow_mut().insert(0x803c, 0x17);
            }
        }
        if f.radio.poll().is_ok() || f.radio.peer().is_some() {
            return TestResult::Fail(
                "failed/modified/foreign-source BA response authorized native ordering",
            );
        }
        f.model.allowed.set(true);
        if f.radio.poll().is_ok()
            || retained
                != f.model
                    .regions
                    .borrow()
                    .iter()
                    .map(|r| (r.bus, r.cpu, r.len))
                    .collect::<Vec<_>>()
        {
            return TestResult::Fail("restored BA policy reopened or released retained owner");
        }
    }
    for fault in 0..3 {
        let mut f = fixture(true, 64);
        begin(&mut f, 7, 1, 64, 1, false);
        f.peer.lock().hold_delba = true;
        tick(&f, 2);
        f.radio.poll().unwrap();
        assert!(!f.peer.lock().delbas.is_empty());
        if fault == 0 {
            f.model.complete(false).unwrap();
        } else if fault == 1 {
            f.model.ba.borrow().as_ref().unwrap().cap.revoke();
        } else {
            f.model.allowed.set(false);
        }
        if f.radio.poll().is_ok() || f.radio.peer().is_some() {
            return TestResult::Fail("native inactivity DELBA failed current source/ACK fence");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_native_failed_response_delba_source_and_mutated_receipts_close
);
fn smoke_ar9285_rx_ba_native_foreign_malformed_addba_and_unnegotiated_amsdu_stay_closed(
) -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = fixture(true, 64);
    let valid = addba(3, 1, 64, 0, false);
    for (at, mask) in [(4, 2), (10, 2), (16, 2), (22, 1), (27, 2), (31, 1)] {
        let mut bad = valid.clone();
        bad[at] ^= mask;
        let n = f.model.transmitted.borrow().len();
        f.model.inject(&bad, 0).unwrap();
        f.radio.poll().unwrap();
        if f.model.transmitted.borrow().len() != n {
            return TestResult::Fail("foreign/malformed ADDBA created native agreement response");
        }
    }
    let mut oversize = valid.clone();
    oversize[27..29].copy_from_slice(&((65u16 << 6) | (3 << 2) | 2).to_le_bytes());
    f.model.inject(&oversize, 0).unwrap();
    f.radio.poll().unwrap();
    f.radio.poll().unwrap();
    if f.peer.lock().declines.len() != 1 || !f.peer.lock().ba_accepts.is_empty() {
        return TestResult::Fail("HT buffer>64 did not receive real decline");
    }
    begin(&mut f, 3, 1, 64, 0, false);
    let (body, _) = ht::tests::aggregate_body(OWN);
    let (bad, _) = raw(&f, 1, 3, 1, 0x60, Some(&body));
    inject(&f, &bad, AGGR | FIRST);
    if !f.radio.poll().unwrap().is_empty() {
        return TestResult::Fail("A-MSDU inside AMPDU bypassed actual ADDBA negotiation");
    }
    let (valid, expected) = raw(&f, 1, 3, 1, 0x60, None);
    inject(&f, &valid, AGGR | FIRST);
    if f.radio.poll().unwrap() != vec![expected] {
        return TestResult::Fail("unnegotiated subframe drop advanced sequence/PN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_native_foreign_malformed_addba_and_unnegotiated_amsdu_stay_closed
);
fn smoke_ar9285_rx_ba_pending_first_burst_delba_and_key_epoch_drop_opaque_stage() -> TestResult {
    let _policy = ht::tests::Policy::install();
    for key_change in [false, true] {
        let mut f = fixture(true, 64);
        f.peer.lock().hold_ba = true;
        f.model.inject(&addba(15, 1, 64, 0, true), 0).unwrap();
        f.radio.poll().unwrap();
        let (wire, expected) = raw(&f, 1, 15, 1, 0x60, None);
        inject(&f, &wire, AGGR | FIRST);
        assert!(f.radio.poll().unwrap().is_empty());
        if key_change {
            f.peer.lock().hold_group = true;
            let group = f.peer.lock().group_rekey();
            f.model.inject(&group, 0).unwrap();
            assert!(f.radio.poll().unwrap().is_empty());
            f.model.complete(true).unwrap();
            if !f.radio.poll().unwrap().is_empty() || f.peer.lock().group_replies != 1 {
                return TestResult::Fail("key marker authenticated/published stale proposal stage");
            }
            f.model.complete(true).unwrap();
            assert!(f.radio.poll().unwrap().is_empty());
            let (fresh, _) = raw(&f, 2, 15, 1, 0x60, None);
            inject(&f, &fresh, AGGR | FIRST);
            if f.radio.poll().unwrap() != vec![expected] {
                return TestResult::Fail(
                    "retired stage consumed sequence/PN across current group key epoch",
                );
            }
        } else {
            f.model.inject(&peer_delba(15), 0).unwrap();
            assert!(f.radio.poll().unwrap().is_empty());
            f.model.complete(true).unwrap();
            if !f.radio.poll().unwrap().is_empty() {
                return TestResult::Fail(
                    "peer DELBA let late positive receipt activate staged originals",
                );
            }
            f.peer.lock().hold_ba = false;
            begin(&mut f, 15, 1, 64, 0, true);
            inject(&f, &wire, AGGR | FIRST);
            if f.radio.poll().unwrap() != vec![expected] {
                return TestResult::Fail(
                    "cancelled proposal consumed PN or prevented fresh actual agreement",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_pending_first_burst_delba_and_key_epoch_drop_opaque_stage
);
fn smoke_ar9285_rx_ba_current_recipient_session_preserves_native_group_key_path() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = fixture(true, 64);
    begin(&mut f, 15, 1, 64, 0, true);
    let (body, expected) = ht::tests::aggregate_body([255; 6]);
    let first = ht::tests::aggregate(&f, &body, true, 15, 1, true);
    inject(&f, &first, 0);
    if f.radio.poll().unwrap() != expected {
        return TestResult::Fail("unicast BA session captured independent normal-ACK GTK traffic");
    }
    let valid = ht::tests::aggregate(&f, &body, true, 15, 2, true);
    let mut invalid = valid.clone();
    invalid[24] |= 0x60;
    inject(&f, &invalid, 0);
    if !f.radio.poll().unwrap().is_empty() {
        return TestResult::Fail("group BlockAck policy acquired native BA admission");
    }
    inject(&f, &valid, 0);
    if f.radio.poll().unwrap() != expected {
        return TestResult::Fail("rejected group BlockAck metadata consumed GTK PN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_current_recipient_session_preserves_native_group_key_path
);
