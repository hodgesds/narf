// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic signed inputs; assertions observe real packet/descriptor/DMA,
//! station security and the reactive native peer, never host-only receipts.
use super::*;
use crate::ath9k::{
    ht,
    packet::tests::Model,
    station::tests::{self as station, AP, PMK, SSID},
};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use zeroize::Zeroizing;
pub(in crate::ath9k) fn record(base: &ht::Grant, members: u8, air: u16, window: u8) -> Vec<u8> {
    let r = request(base);
    let mut b = vec![0; 128];
    b[..8].copy_from_slice(&[b'N', b'8', b'5', b'T', 4, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..58].copy_from_slice(&base.geometry().body());
    b[58..60].copy_from_slice(&12i16.to_le_bytes());
    b[60] = window;
    b[61] = 3;
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
    b[64] = members;
    b[65] = base.version();
    b[66..68].copy_from_slice(&air.to_le_bytes());
    b[68..100].copy_from_slice(&base.ba_identity().1);
    b
}
pub(in crate::ath9k) fn qualify(
    model: &Arc<Model>,
    members: u8,
    air: u16,
    window: u8,
) -> Cap<FirmwareBlob, Read> {
    let base = model.ht.borrow().clone().unwrap();
    let cap = Cap::bootstrap();
    let grant = Source::Verified {
        bytes: record(&base, members, air, window),
        signer: Some([0x85; 32]),
        cap,
    }
    .load(base)
    .unwrap();
    *model.tx_ba.borrow_mut() = Some(grant);
    model.pair_received.set(255);
    cap
}
fn settle(f: &mut station::Fixture) {
    for _ in 0..64 {
        f.radio.poll().unwrap();
    }
}
fn associated(protected: bool, mcs: u8, members: u8, air: u16, window: u8) -> station::Fixture {
    let mut f = station::fixture_ht(protected, 1 << mcs).unwrap();
    qualify(&f.model, members, air, window);
    station::complete(
        f.radio
            .associate(AP, SSID, protected.then(|| Zeroizing::new(PMK)), &[]),
    )
    .unwrap();
    settle(&mut f);
    assert!(f.radio.can_aggregate());
    f
}
fn ethernet(f: &station::Fixture, value: u8, length: usize) -> Vec<u8> {
    let mut p = vec![value; length];
    p[..6].copy_from_slice(&AP);
    p[6..12].copy_from_slice(&f.plan.station);
    p[12..14].copy_from_slice(&[8, 0]);
    p
}
fn data(f: &station::Fixture) -> Vec<Vec<u8>> {
    f.model
        .transmitted
        .borrow()
        .iter()
        .filter(|f| f.first() == Some(&0x88))
        .cloned()
        .collect()
}
fn smoke_ar9285_large_tx_distinct_v4_signed_body_and_legacy_two_member_bound() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = station::fixture_ht(true, 255).unwrap();
    let base = f.model.ht.borrow().clone().unwrap();
    let bytes = record(&base, 8, 65535, 64);
    if request(&base).identity == super::super::request(&base).identity
        || !request(&base)
            .filename
            .starts_with("ath9k/ar9285-txba-v4-ch1-ext0-")
    {
        return TestResult::Fail("v4 aliases accepted two-member identity");
    }
    for at in [
        0, 4, 6, 8, 12, 16, 48, 54, 55, 56, 57, 61, 65, 68, 99, 100, 127,
    ] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        if Grant::decode(&bad, Some([1; 32]), Cap::bootstrap(), base.clone()).is_ok() {
            return TestResult::Fail(
                "foreign v4 identity/geometry/whole-base/reserved field accepted",
            );
        }
    }
    for (at, value) in [(60, 3), (60, 65), (64, 2), (64, 9)] {
        let mut bad = bytes.clone();
        bad[at] = value;
        if Grant::decode(&bad, Some([1; 32]), Cap::bootstrap(), base.clone()).is_ok() {
            return TestResult::Fail("v4 window or member bounds accepted");
        }
    }
    let mut zero = bytes.clone();
    zero[66..68].fill(0);
    if Grant::decode(&zero, Some([1; 32]), Cap::bootstrap(), base.clone()).is_ok()
        || Grant::decode(&bytes, None, Cap::bootstrap(), base).is_ok()
    {
        return TestResult::Fail("zero-air or unsigned v4 accepted");
    }
    super::super::tests::qualify(&f.model, 64);
    station::complete(f.radio.associate(AP, SSID, Some(Zeroizing::new(PMK)), &[])).unwrap();
    settle(&mut f);
    let frames: Vec<Vec<u8>> = (0..8).map(|n| ethernet(&f, n, 64)).collect();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let before = f.model.transmitted.borrow().len();
    if f.radio.aggregate_count(&refs) != Ok(2)
        || f.radio.send_aggregate(&refs).is_ok()
        || f.model.transmitted.borrow().len() != before
        || f.model.regions.borrow().len() != 12
    {
        return TestResult::Fail("legacy source grew maps or authorized >two originals");
    }
    f.radio.send_pair(&frames[0], &frames[1]).unwrap();
    settle(&mut f);
    if f.model.last_chain.borrow().len() != 2 {
        return TestResult::Fail("legacy two-map chain changed");
    }
    f.radio.stop().unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/large-tx",
    smoke_ar9285_large_tx_distinct_v4_signed_body_and_legacy_two_member_bound
);
fn smoke_ar9285_large_tx_three_to_eight_native_links_all_mcs_pns_padding_and_tail_fence(
) -> TestResult {
    let _policy = ht::tests::Policy::install();
    for protected in [false, true] {
        for mcs in 0..8 {
            for count in 3..=8 {
                let mut f = associated(protected, mcs, 8, 65535, 64);
                f.peer.lock().hold_data = true;
                let frames: Vec<Vec<u8>> =
                    (0..count).map(|n| ethernet(&f, n as u8, 64 + n)).collect();
                f.radio
                    .send_aggregate(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>())
                    .unwrap();
                let chain = f.model.last_chain.borrow().clone();
                let originals = data(&f);
                if chain.len() != count
                    || originals.len() != count
                    || f.peer.lock().uplink != frames
                    || f.model.regions.borrow().len() != 19
                {
                    return TestResult::Fail("native eight-map ring/peer originals missing");
                }
                let mut air = 0usize;
                for index in 0..count {
                    let original = &originals[index];
                    let d = chain[index];
                    let length = original.len() + 4;
                    let delimiters = if index + 1 == count {
                        0
                    } else {
                        256usize.saturating_sub(length).div_ceil(4)
                    };
                    air += 4 + length;
                    if index + 1 != count {
                        air = air.next_multiple_of(4) + delimiters * 4;
                    }
                    let flags = if index + 1 == count {
                        0x4000_0000
                    } else {
                        0x6000_0000
                    };
                    if f.model.word(d) != Ok(chain.get(index + 1).copied().unwrap_or(0))
                        || f.model.word(d + 12).unwrap() & 0x6000_0000 != flags
                        || f.model.word(d + 32).unwrap() >> 18 != delimiters as u32
                        || index != 0
                            && [16, 20, 24, 28, 36]
                                .into_iter()
                                .any(|offset| f.model.word(d + offset) != Ok(0))
                    {
                        return TestResult::Fail(
                            "source first/middle/last descriptor or delimiter mismatch",
                        );
                    }
                    let dma = f
                        .model
                        .bytes(f.model.word(d + 4).unwrap(), original.len() + 2)
                        .unwrap();
                    if dma[..26] != original[..26]
                        || dma[26..28] != [0, 0]
                        || dma[28..] != original[26..]
                        || f.model.word(d + 8).unwrap() & 0xfff != length as u32
                    {
                        return TestResult::Fail("native FCS/DMA pad changed original ciphertext");
                    }
                    if index > 0 {
                        let previous = &originals[index - 1];
                        let seq = |f: &[u8]| u16::from_le_bytes([f[22], f[23]]) >> 4;
                        if seq(original) != (seq(previous) + 1) & 4095 {
                            return TestResult::Fail("per-original sequence did not advance");
                        }
                        if protected {
                            let pn = |f: &[u8]| {
                                narf_wireless::ccmp::decode_ccmp_header(
                                    f[26..34].try_into().unwrap(),
                                )
                                .unwrap()
                                .0
                            };
                            if pn(original) != pn(previous) + 1 {
                                return TestResult::Fail("per-original CCMP PN reused");
                            }
                        }
                    }
                }
                let bits = [26u32, 52, 78, 104, 156, 208, 234, 260][usize::from(mcs)];
                if f.model.word(chain[0] + 32).unwrap() & 65535 != air as u32
                    || f.model.word(chain[0] + 24)
                        != Ok(36 + 4 * (air as u32 * 8 + 22).div_ceil(bits))
                {
                    return TestResult::Fail("whole PPDU air length/duration mismatch");
                }
                // Earlier TxDone cannot release any map; tail cannot bypass QCU idle.
                for d in &chain[..count - 1] {
                    f.model.put(*d + 92, 1).unwrap();
                }
                f.radio.poll().unwrap();
                if f.radio.ready() || f.model.tx.get() != Some(chain[0]) {
                    return TestResult::Fail("non-tail completion released chain");
                }
                f.model.complete(true).unwrap();
                f.model.registers.borrow_mut().insert(0x840, 1);
                f.model.registers.borrow_mut().insert(0xa00, 1);
                f.radio.poll().unwrap();
                if f.radio.ready() {
                    return TestResult::Fail("tail completion bypassed queue-idle fence");
                }
                f.model.registers.borrow_mut().insert(0x840, 0);
                f.model.registers.borrow_mut().insert(0xa00, 0);
                settle(&mut f);
                if !f.radio.can_aggregate() {
                    return TestResult::Fail("valid bound tail did not reopen owner");
                }
                f.radio.stop().unwrap();
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/large-tx",
    smoke_ar9285_large_tx_three_to_eight_native_links_all_mcs_pns_padding_and_tail_fence
);
fn smoke_ar9285_large_tx_preflight_half_baw_peer_factor_air_time_and_no_sequence_consumption(
) -> TestResult {
    let _policy = ht::tests::Policy::install();
    for (mcs, members, air, window, length, expected) in [
        (7, 8, 65535, 64, 1514, 5),
        (7, 4, 65535, 64, 64, 4),
        (7, 8, 65535, 8, 64, 4),
        (7, 8, 4095, 64, 1514, 2),
        (0, 8, 65535, 64, 1514, 2),
    ] {
        let mut f = associated(true, mcs, members, air, window);
        let frames: Vec<Vec<u8>> = (0..8).map(|n| ethernet(&f, n, length)).collect();
        let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        if f.radio.aggregate_count(&refs) != Ok(expected) {
            return TestResult::Fail("preflight ignored halfBAW/factor/signed bound or4ms");
        }
        let ssn = f.peer.lock().tx_ba_requests.last().unwrap()[31..33].to_vec();
        let before = data(&f).len();
        if f.radio.send_aggregate(&refs).is_ok() || data(&f).len() != before {
            return TestResult::Fail("unfitting full prefix published");
        }
        f.radio.send(&frames[0]).unwrap();
        settle(&mut f);
        if data(&f).first().unwrap()[22..24] != ssn {
            return TestResult::Fail("rejected preflight consumed shared QoS sequence");
        }
        f.radio.stop().unwrap();
    }
    let mut f = station::fixture_ht(true, 128).unwrap();
    let mut offer = ht::tests::elements();
    offer[4] = (offer[4] & !3) | 3;
    f.peer.lock().ht = Some(offer);
    qualify(&f.model, 8, 65535, 64);
    station::complete(f.radio.associate(AP, SSID, Some(Zeroizing::new(PMK)), &[])).unwrap();
    settle(&mut f);
    let frames: Vec<Vec<u8>> = (0..8).map(|n| ethernet(&f, n, 1514)).collect();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    if f.radio.aggregate_count(&refs) != Ok(8) {
        return TestResult::Fail("larger peer inherits old air bound");
    }
    f.radio.send_aggregate(&refs).unwrap();
    settle(&mut f);
    let head = f.model.last_chain.borrow()[0];
    if f.model.word(head + 32).unwrap() & 65535 <= 8191 || f.peer.lock().uplink != frames {
        return TestResult::Fail("native chain absent above8191air");
    }
    f.radio.stop().unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/large-tx",
    smoke_ar9285_large_tx_preflight_half_baw_peer_factor_air_time_and_no_sequence_consumption
);
fn smoke_ar9285_large_tx_each_bitmap_hole_immutable_retry_bar_and_wrapped_sequence() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = station::fixture_ht(false, 128).unwrap();
    station::open_qos_start(&mut f, 4095);
    qualify(&f.model, 8, 65535, 64);
    station::complete(f.radio.associate(AP, SSID, None, &[])).unwrap();
    settle(&mut f);
    f.model.ba_ssn.set(Some(4091));
    f.model.ba_bitmap.set(Some(255 << 4));
    let frames: Vec<Vec<u8>> = (0..8).map(|n| ethernet(&f, n, 128)).collect();
    f.radio
        .send_aggregate(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>())
        .unwrap();
    settle(&mut f);
    if data(&f).len() != 8 || data(&f)[7][22..24] != (6u16 << 4).to_le_bytes() {
        return TestResult::Fail("BA bitmap did not bind wrapped4095 sequence");
    }
    f.radio.stop().unwrap();
    drop(f);
    for protected in [false, true] {
        let mut f = associated(protected, 7, 8, 65535, 64);
        f.model.pair_received.set(0x55);
        f.model.data_ack.set(false);
        f.model.retry_receive.set(false);
        let frames: Vec<Vec<u8>> = (0..8)
            .map(|n| ethernet(&f, n, 128 + usize::from(n)))
            .collect();
        f.radio
            .send_aggregate(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>())
            .unwrap();
        settle(&mut f);
        let sent = data(&f);
        if sent.len() != 20 || f.peer.lock().bars.len() != 1 || !f.radio.can_aggregate() {
            return TestResult::Fail("all four holes did not exhaust3 retries and real BAR");
        }
        for (index, retry) in sent[8..].iter().enumerate() {
            let mut expected = sent[(index / 3) * 2 + 1].clone();
            expected[1] |= 8;
            if *retry != expected {
                return TestResult::Fail("retry changed original SC/PN/ciphertext or wrong member");
            }
        }
        let request = f.peer.lock().bars[0].clone();
        let start = u16::from_le_bytes([sent[0][22], sent[0][23]]) >> 4;
        if u16::from_le_bytes([request[18], request[19]]) >> 4 != (start + 8) & 4095 {
            return TestResult::Fail("BAR skipped wrong end of full chain");
        }
        f.radio.stop().unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/large-tx",
    smoke_ar9285_large_tx_each_bitmap_hole_immutable_retry_bar_and_wrapped_sequence
);
fn smoke_ar9285_large_tx_middle_corruption_source_rekey_and_pinned_allocation_ownership(
) -> TestResult {
    let _policy = ht::tests::Policy::install();
    for fault in 0..5 {
        let mut f = associated(true, 7, 8, 65535, 64);
        f.peer.lock().hold_data = true;
        let frames: Vec<Vec<u8>> = (0..8).map(|n| ethernet(&f, n, 128)).collect();
        f.radio
            .send_aggregate(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>())
            .unwrap();
        let chain = f.model.last_chain.borrow().clone();
        match fault {
            0 => {
                f.model.tx_ba.borrow().as_ref().unwrap().cap.revoke();
            }
            1 => {
                f.model
                    .put(
                        chain[3] + 32,
                        f.model.word(chain[3] + 32).unwrap() ^ 0x40000,
                    )
                    .unwrap();
            }
            2 => {
                let address = f.model.word(chain[5] + 4).unwrap();
                f.model
                    .put(address + 28, f.model.word(address + 28).unwrap() ^ 1)
                    .unwrap();
            }
            3 => {
                f.model.ba_flag.set(false);
            }
            _ => {
                f.model.stuck_tx.set(true);
                f.model.stuck_rx.set(true);
            }
        }
        if fault == 4 {
            if f.radio.stop().is_ok() || !f.model.released.borrow().is_empty() {
                return TestResult::Fail("wedged chain freed retained/new rings");
            }
            continue;
        }
        f.model.complete(true).unwrap();
        if f.radio.poll().is_ok() || f.radio.peer().is_some() {
            return TestResult::Fail("corrupt middle/source/BA status reopened full chain");
        }
    }
    let mut f = associated(true, 7, 8, 65535, 64);
    f.model.pair_received.set(0x55);
    f.peer.lock().hold_data = true;
    f.peer.lock().hold_group = true;
    let frames: Vec<Vec<u8>> = (0..8).map(|n| ethernet(&f, n, 128)).collect();
    f.radio
        .send_aggregate(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>())
        .unwrap();
    let before = data(&f).len();
    let group = f.peer.lock().group_rekey();
    f.model.inject(&group, 0).unwrap();
    f.radio.poll().unwrap();
    if f.radio.receive_open() || f.model.tx.get().is_none() {
        return TestResult::Fail("rekey lost held DMA or left controlled port open");
    }
    f.model.complete(true).unwrap();
    f.radio.poll().unwrap();
    f.radio.poll().unwrap();
    if f.peer.lock().group_replies != 1 || f.radio.receive_open() {
        return TestResult::Fail("chain receipt skipped actual old-key Group2 receipt");
    }
    f.peer.lock().hold_data = false;
    f.model.complete(true).unwrap();
    settle(&mut f);
    if data(&f).len() != before || f.peer.lock().bars.len() != 1 {
        return TestResult::Fail("rekey kept old-key retry authority for larger chain");
    }
    f.radio.stop().unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/large-tx",
    smoke_ar9285_large_tx_middle_corruption_source_rekey_and_pinned_allocation_ownership
);
